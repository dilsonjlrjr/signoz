package oidccallbackauthn

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/SigNoz/signoz/pkg/authn"
	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/factory"
	"github.com/SigNoz/signoz/pkg/global"
	"github.com/SigNoz/signoz/pkg/http/client"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/valuer"
)

const redirectPath string = "/api/v1/complete/oidc"

const (
	// sealedStateParam is the query parameter, inside the state URL, that carries the sealed
	// per-login secrets (nonce and PKCE code_verifier).
	sealedStateParam string = "oidc_state"

	// sealedStateTTL bounds how long a login started by LoginURL can be completed.
	sealedStateTTL time.Duration = 10 * time.Minute

	// sealedStateKeyInfo is the HKDF info label used to derive the state key from the client secret.
	sealedStateKeyInfo string = "signoz-oidc-state-v1"
)

// sealedState holds the per-login secrets that must survive the round trip through the
// identity provider. It is encrypted and authenticated (AES-GCM) with a key derived from the
// auth domain's client secret, so it can neither be read nor forged by the browser or the IdP.
type sealedState struct {
	Nonce     string `json:"n"`
	Verifier  string `json:"v"`
	ExpiresAt int64  `json:"e"`
}

var scopes []string = []string{oidc.ScopeOpenID, "email", "profile"}

var _ authn.CallbackAuthN = (*AuthN)(nil)

type AuthN struct {
	store        authtypes.AuthNStore
	settings     factory.ScopedProviderSettings
	httpClient   *client.Client
	globalConfig global.Config
}

func New(ctx context.Context, store authtypes.AuthNStore, providerSettings factory.ProviderSettings, globalConfig global.Config) (*AuthN, error) {
	settings := factory.NewScopedProviderSettings(providerSettings, "github.com/SigNoz/signoz/pkg/authn/callbackauthn/oidccallbackauthn")

	httpClient, err := client.New(settings.Logger(), providerSettings.TracerProvider, providerSettings.MeterProvider)
	if err != nil {
		return nil, err
	}

	return &AuthN{
		store:        store,
		settings:     settings,
		httpClient:   httpClient,
		globalConfig: globalConfig,
	}, nil
}

func (a *AuthN) LoginURL(ctx context.Context, siteURL *url.URL, authDomain *authtypes.AuthDomain) (string, error) {
	ctx = oidc.ClientContext(ctx, a.httpClient.Client())

	oidcConfig, err := a.oidcConfig(authDomain)
	if err != nil {
		return "", err
	}

	oidcProvider, err := a.oidcProvider(ctx, oidcConfig)
	if err != nil {
		return "", err
	}

	oauth2Config := a.oauth2Config(siteURL, oidcConfig, oidcProvider, authDomain.AuthDomainConfig().RoleMapping)

	state := authtypes.NewState(siteURL, authDomain.StorableAuthDomain().ID)
	secrets := sealedState{
		Nonce:     rand.Text(),
		Verifier:  oauth2.GenerateVerifier(),
		ExpiresAt: time.Now().Add(sealedStateTTL).Unix(),
	}

	sealed, err := sealState(oidcConfig.ClientSecret, state, secrets)
	if err != nil {
		return "", errors.Newf(errors.TypeInternal, errors.CodeInternal, "oidc: failed to seal state").WithAdditional(err.Error())
	}

	stateQuery := state.URL.Query()
	stateQuery.Set(sealedStateParam, sealed)
	state.URL.RawQuery = stateQuery.Encode()

	return oauth2Config.AuthCodeURL(state.URL.String(), oauth2.S256ChallengeOption(secrets.Verifier), oidc.Nonce(secrets.Nonce)), nil
}

func (a *AuthN) HandleCallback(ctx context.Context, query url.Values) (*authtypes.CallbackIdentity, error) {
	ctx = oidc.ClientContext(ctx, a.httpClient.Client())

	if errorParam := query.Get("error"); errorParam != "" {
		a.settings.Logger().ErrorContext(ctx, "oidc: error while authenticating", slog.String("error", errorParam), slog.String("error_description", query.Get("error_description")))
		return nil, errors.Newf(errors.TypeInternal, errors.CodeInternal, "oidc: error while authenticating").WithAdditional(query.Get("error_description"))
	}

	state, err := authtypes.NewStateFromString(query.Get("state"))
	if err != nil {
		a.settings.Logger().ErrorContext(ctx, "oidc: invalid state", errors.Attr(err))
		return nil, errors.Newf(errors.TypeInvalidInput, authtypes.ErrCodeInvalidState, "oidc: invalid state").WithAdditional(err.Error())
	}

	authDomain, err := a.store.GetAuthDomainFromID(ctx, state.DomainID)
	if err != nil {
		return nil, err
	}

	oidcConfig, err := a.oidcConfig(authDomain)
	if err != nil {
		return nil, err
	}

	// The sealed state authenticates the whole state (domain and site URL), so a tampered
	// state is rejected here, before any redirect URL is derived from it.
	secrets, err := openState(oidcConfig.ClientSecret, state)
	if err != nil {
		a.settings.Logger().ErrorContext(ctx, "oidc: invalid sealed state", errors.Attr(err))
		return nil, errors.Newf(errors.TypeInvalidInput, authtypes.ErrCodeInvalidState, "oidc: invalid state")
	}

	if time.Now().Unix() > secrets.ExpiresAt {
		a.settings.Logger().ErrorContext(ctx, "oidc: expired state")
		return nil, errors.Newf(errors.TypeInvalidInput, authtypes.ErrCodeInvalidState, "oidc: login expired, please try again")
	}

	oidcProvider, err := a.oidcProvider(ctx, oidcConfig)
	if err != nil {
		return nil, err
	}

	oauth2Config := a.oauth2Config(state.URL, oidcConfig, oidcProvider, authDomain.AuthDomainConfig().RoleMapping)

	token, err := oauth2Config.Exchange(ctx, query.Get("code"), oauth2.VerifierOption(secrets.Verifier))
	if err != nil {
		if isTimeoutErr(err) {
			a.settings.Logger().ErrorContext(ctx, "oidc: timed out exchanging code for token", errors.Attr(err))
			return nil, errors.Newf(errors.TypeTimeout, errors.CodeTimeout, "oidc: timed out talking to identity provider").WithAdditional(err.Error())
		}

		var retrieveError *oauth2.RetrieveError
		if errors.As(err, &retrieveError) {
			a.settings.Logger().ErrorContext(ctx, "oidc: failed to get token", errors.Attr(err), slog.String("error_description", retrieveError.ErrorDescription), slog.String("body", string(retrieveError.Body)))
			return nil, errors.Newf(errors.TypeForbidden, errors.CodeForbidden, "oidc: failed to get token").WithAdditional(retrieveError.ErrorDescription)
		}

		a.settings.Logger().ErrorContext(ctx, "oidc: failed to get token", errors.Attr(err))
		return nil, errors.Newf(errors.TypeInternal, errors.CodeInternal, "oidc: failed to get token")
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New(errors.TypeInvalidInput, errors.CodeInvalidInput, "oidc: no id_token in token response")
	}

	verifier := oidcProvider.Verifier(&oidc.Config{ClientID: oidcConfig.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		if isTimeoutErr(err) {
			a.settings.Logger().ErrorContext(ctx, "oidc: timed out verifying token", errors.Attr(err))
			return nil, errors.Newf(errors.TypeTimeout, errors.CodeTimeout, "oidc: timed out talking to identity provider").WithAdditional(err.Error())
		}

		a.settings.Logger().ErrorContext(ctx, "oidc: failed to verify token", errors.Attr(err))
		return nil, errors.Newf(errors.TypeForbidden, errors.CodeForbidden, "oidc: failed to verify token")
	}

	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(secrets.Nonce)) != 1 {
		a.settings.Logger().ErrorContext(ctx, "oidc: id token nonce does not match")
		return nil, errors.Newf(errors.TypeForbidden, errors.CodeForbidden, "oidc: failed to verify token")
	}

	claims := make(map[string]any)
	if err := idToken.Claims(&claims); err != nil {
		a.settings.Logger().ErrorContext(ctx, "oidc: missing or invalid claims", errors.Attr(err))
		return nil, errors.Newf(errors.TypeForbidden, errors.CodeForbidden, "oidc: missing or invalid claims").WithAdditional(err.Error())
	}

	// OIDC Core 3.1.3.7: with multiple audiences azp must be present, and when present it must be this client.
	if azp, ok := claims["azp"]; ok || len(idToken.Audience) > 1 {
		if value, _ := azp.(string); value != oidcConfig.ClientID {
			a.settings.Logger().ErrorContext(ctx, "oidc: id token azp does not match client id")
			return nil, errors.Newf(errors.TypeForbidden, errors.CodeForbidden, "oidc: failed to verify token")
		}
	}

	if oidcConfig.GetUserInfo {
		userInfo, err := oidcProvider.UserInfo(ctx, oauth2Config.TokenSource(ctx, token))
		if err != nil {
			if isTimeoutErr(err) {
				a.settings.Logger().ErrorContext(ctx, "oidc: timed out fetching userinfo", errors.Attr(err))
				return nil, errors.Newf(errors.TypeTimeout, errors.CodeTimeout, "oidc: timed out talking to identity provider").WithAdditional(err.Error())
			}

			a.settings.Logger().ErrorContext(ctx, "oidc: failed to fetch userinfo", errors.Attr(err))
			return nil, errors.Newf(errors.TypeInternal, errors.CodeInternal, "oidc: failed to fetch userinfo").WithAdditional(err.Error())
		}

		// OIDC Core 5.3.4: the userinfo sub must match the id token sub, otherwise its claims must not be used.
		if userInfo.Subject != idToken.Subject {
			a.settings.Logger().ErrorContext(ctx, "oidc: userinfo subject does not match id token subject")
			return nil, errors.Newf(errors.TypeForbidden, errors.CodeForbidden, "oidc: userinfo subject does not match id token subject")
		}

		userInfoClaims := make(map[string]any)
		if err := userInfo.Claims(&userInfoClaims); err != nil {
			a.settings.Logger().ErrorContext(ctx, "oidc: invalid userinfo claims", errors.Attr(err))
			return nil, errors.Newf(errors.TypeForbidden, errors.CodeForbidden, "oidc: invalid userinfo claims").WithAdditional(err.Error())
		}

		for key, value := range userInfoClaims {
			claims[key] = value
		}
	}

	if !oidcConfig.InsecureSkipEmailVerified && !boolClaim(claims, "email_verified") {
		a.settings.Logger().ErrorContext(ctx, "oidc: email is not verified")
		return nil, errors.Newf(errors.TypeForbidden, errors.CodeForbidden, "oidc: email is not verified")
	}

	claimMapping := oidcConfig.ClaimMapping

	email, err := valuer.NewEmail(stringClaim(claims, claimMapping.Email))
	if err != nil {
		return nil, errors.Newf(errors.TypeInvalidInput, errors.CodeInvalidInput, "oidc: failed to parse email").WithAdditional(err.Error())
	}

	name := stringClaim(claims, claimMapping.Name)
	groups := stringSliceClaim(claims, claimMapping.Groups)
	role := stringClaim(claims, claimMapping.Role)

	// Audit trail: identifies who authenticated without logging tokens, secrets or the email (PII).
	a.settings.Logger().InfoContext(ctx, "oidc: user authenticated", slog.String("domain_id", authDomain.StorableAuthDomain().ID.String()), slog.String("org_id", authDomain.StorableAuthDomain().OrgID.String()), slog.String("subject", idToken.Subject), slog.String("issuer", idToken.Issuer))

	return authtypes.NewCallbackIdentity(name, email, authDomain.StorableAuthDomain().OrgID, state, groups, role), nil
}

func (a *AuthN) ProviderInfo(ctx context.Context, authDomain *authtypes.AuthDomain) *authtypes.AuthNProviderInfo {
	return &authtypes.AuthNProviderInfo{
		RelayStatePath: nil,
	}
}

func (a *AuthN) oidcConfig(authDomain *authtypes.AuthDomain) (*authtypes.OIDCConfig, error) {
	config := authDomain.AuthDomainConfig()
	if config.AuthNProvider != authtypes.AuthNProviderOIDC || config.OIDC == nil {
		return nil, errors.Newf(errors.TypeInternal, authtypes.ErrCodeAuthDomainMismatch, "oidc: domain %q is not configured for oidc", authDomain.StorableAuthDomain().Name)
	}

	return config.OIDC, nil
}

func (a *AuthN) oidcProvider(ctx context.Context, oidcConfig *authtypes.OIDCConfig) (*oidc.Provider, error) {
	discoveryURL := oidcConfig.Issuer
	if oidcConfig.IssuerAlias != "" {
		ctx = oidc.InsecureIssuerURLContext(ctx, oidcConfig.IssuerAlias)
		discoveryURL = oidcConfig.IssuerAlias
	}

	if !strings.HasPrefix(discoveryURL, "https://") {
		a.settings.Logger().WarnContext(ctx, "oidc: issuer is not served over https, traffic to the identity provider will not be encrypted", slog.String("issuer", discoveryURL))
	}

	provider, err := oidc.NewProvider(ctx, oidcConfig.Issuer)
	if err != nil {
		if isTimeoutErr(err) {
			a.settings.Logger().ErrorContext(ctx, "oidc: timed out discovering provider", errors.Attr(err), slog.String("issuer", oidcConfig.Issuer))
			return nil, errors.Newf(errors.TypeTimeout, errors.CodeTimeout, "oidc: timed out talking to identity provider").WithAdditional(err.Error())
		}

		a.settings.Logger().ErrorContext(ctx, "oidc: failed to discover provider", errors.Attr(err), slog.String("issuer", oidcConfig.Issuer))
		return nil, errors.Newf(errors.TypeInternal, errors.CodeInternal, "oidc: failed to discover provider").WithAdditional(err.Error())
	}

	return provider, nil
}

// isTimeoutErr reports whether err was caused by the request's context deadline being
// exceeded (e.g. the shared http client's request timeout or the callback handler's
// overall context budget), so callers can surface a friendlier "timeout" error.
func isTimeoutErr(err error) bool {
	return errors.Is(err, context.DeadlineExceeded)
}

func (a *AuthN) oauth2Config(siteURL *url.URL, oidcConfig *authtypes.OIDCConfig, provider *oidc.Provider, roleMapping *authtypes.RoleMapping) *oauth2.Config {
	requestedScopes := scopes
	if roleMapping != nil && (roleMapping.UseRoleAttribute || len(roleMapping.GroupMappings) > 0) {
		requestedScopes = append(append([]string{}, scopes...), "groups")
	}

	return &oauth2.Config{
		ClientID:     oidcConfig.ClientID,
		ClientSecret: oidcConfig.ClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       requestedScopes,
		RedirectURL: (&url.URL{
			Scheme: siteURL.Scheme,
			Host:   siteURL.Host,
			Path:   path.Join(a.globalConfig.ExternalPath(), redirectPath),
		}).String(),
	}
}

// sealState encrypts the per-login secrets and binds them to the domain and site URL carried by
// the state, so that neither the secrets nor the state they travel in can be altered unnoticed.
func sealState(clientSecret string, state authtypes.State, secrets sealedState) (string, error) {
	aead, err := stateAEAD(clientSecret)
	if err != nil {
		return "", err
	}

	plaintext, err := json.Marshal(secrets)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, plaintext, stateAdditionalData(state))), nil
}

// openState is the inverse of sealState. It fails if the sealed value is missing, was produced
// with another client secret, or if the domain or site URL in the state were changed.
func openState(clientSecret string, state authtypes.State) (*sealedState, error) {
	aead, err := stateAEAD(clientSecret)
	if err != nil {
		return nil, err
	}

	sealed, err := base64.RawURLEncoding.DecodeString(state.URL.Query().Get(sealedStateParam))
	if err != nil {
		return nil, err
	}

	if len(sealed) < aead.NonceSize() {
		return nil, errors.New(errors.TypeInvalidInput, authtypes.ErrCodeInvalidState, "sealed state is too short")
	}

	plaintext, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], stateAdditionalData(state))
	if err != nil {
		return nil, err
	}

	secrets := new(sealedState)
	if err := json.Unmarshal(plaintext, secrets); err != nil {
		return nil, err
	}

	return secrets, nil
}

func stateAEAD(clientSecret string) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, []byte(clientSecret), nil, sealedStateKeyInfo, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

func stateAdditionalData(state authtypes.State) []byte {
	return []byte(state.DomainID.String() + "|" + state.URL.Scheme + "://" + state.URL.Host + state.URL.Path)
}

func stringClaim(claims map[string]any, key string) string {
	if value, ok := claims[key].(string); ok {
		return value
	}

	return ""
}

func boolClaim(claims map[string]any, key string) bool {
	if value, ok := claims[key].(bool); ok {
		return value
	}

	return false
}

func stringSliceClaim(claims map[string]any, key string) []string {
	switch value := claims[key].(type) {
	case []string:
		return value
	case []any:
		result := make([]string, 0, len(value))
		for _, item := range value {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}

		return result
	case string:
		return []string{value}
	default:
		return nil
	}
}
