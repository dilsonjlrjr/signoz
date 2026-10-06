package oidccallbackauthn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/factory/factorytest"
	"github.com/SigNoz/signoz/pkg/global"
	"github.com/SigNoz/signoz/pkg/types"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/valuer"
)

// fakeStore is a minimal authtypes.AuthNStore that always resolves to a single, fixed auth domain.
type fakeStore struct {
	authDomain *authtypes.AuthDomain
}

func (f *fakeStore) GetActiveUserAndFactorPasswordByEmailAndOrgID(ctx context.Context, email string, orgID valuer.UUID) (*types.User, *types.FactorPassword, []*authtypes.UserRole, error) {
	return nil, nil, nil, errors.New(errors.TypeUnsupported, errors.CodeUnsupported, "not implemented")
}

func (f *fakeStore) GetAuthDomainFromID(ctx context.Context, domainID valuer.UUID) (*authtypes.AuthDomain, error) {
	if f.authDomain == nil || domainID != f.authDomain.StorableAuthDomain().ID {
		return nil, errors.New(errors.TypeNotFound, errors.CodeNotFound, "auth domain not found")
	}

	return f.authDomain, nil
}

func newTestAuthN(t *testing.T) *AuthN {
	t.Helper()

	authN, err := New(context.Background(), nil, factorytest.NewSettings(), global.Config{})
	require.NoError(t, err)
	require.NotNil(t, authN)

	return authN
}

func newTestOIDCAuthDomain(t *testing.T, oidcConfig *authtypes.OIDCConfig, roleMapping *authtypes.RoleMapping) *authtypes.AuthDomain {
	t.Helper()

	config := &authtypes.AuthDomainConfig{
		SSOEnabled:    true,
		AuthNProvider: authtypes.AuthNProviderOIDC,
		OIDC:          oidcConfig,
		RoleMapping:   roleMapping,
	}

	authDomain, err := authtypes.NewAuthDomainFromConfig("example.com", config, valuer.GenerateUUID())
	require.NoError(t, err)

	return authDomain
}

// newOIDCDiscoveryServer starts a local OIDC discovery server so that
// `oidc.NewProvider` can run in tests without reaching out to a real IdP.
func newOIDCDiscoveryServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 server.URL,
			"authorization_endpoint": server.URL + "/auth",
			"token_endpoint":         server.URL + "/token",
			"userinfo_endpoint":      server.URL + "/userinfo",
			"jwks_uri":               server.URL + "/jwks",
		})
	})

	return server
}

// fakeIdP is a local OIDC server that remembers the nonce and PKCE challenge of the last
// authorization request (see beginLogin), like a real IdP would.
type fakeIdP struct {
	*httptest.Server
	nonce         string
	codeChallenge string
}

// beginLogin runs LoginURL, records the nonce and PKCE challenge it sent to the IdP and returns
// the callback query the IdP would redirect back with.
func beginLogin(t *testing.T, authN *AuthN, authDomain *authtypes.AuthDomain, idp *fakeIdP) url.Values {
	t.Helper()

	rawURL, err := authN.LoginURL(context.Background(), &url.URL{Scheme: "https", Host: "signoz.example.com"}, authDomain)
	require.NoError(t, err)

	parsed, err := url.Parse(rawURL)
	require.NoError(t, err)

	idp.nonce = parsed.Query().Get("nonce")
	idp.codeChallenge = parsed.Query().Get("code_challenge")

	query := url.Values{}
	query.Set("code", "test-code")
	query.Set("state", parsed.Query().Get("state"))

	return query
}

// newOIDCServer starts a local OIDC server that serves discovery, JWKS, token
// exchange and (optionally) userinfo, so `HandleCallback` can run end-to-end
// against a fake but spec-compliant IdP. `idTokenClaims` is a JSON template
// where `%s` is replaced by the issuer URL. The token endpoint enforces PKCE and
// adds the nonce of the authorization request unless the template sets one.
func newOIDCServer(t *testing.T, idTokenClaims string, userInfoClaims map[string]any) *fakeIdP {
	t.Helper()

	idp := &fakeIdP{}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyServer := &oidctest.Server{
		PublicKeys: []oidctest.PublicKey{
			{PublicKey: priv.Public(), KeyID: "test-key", Algorithm: "RS256"},
		},
	}

	var issuer string

	mux := http.NewServeMux()
	mux.Handle("/keys", keyServer)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/auth",
			"token_endpoint":                        issuer + "/token",
			"userinfo_endpoint":                     issuer + "/userinfo",
			"jwks_uri":                              issuer + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if idp.codeChallenge != "" {
			sum := sha256.Sum256([]byte(r.FormValue("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(sum[:]) != idp.codeChallenge {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant", "error_description": "PKCE verification failed"})
				return
			}
		}

		claims := make(map[string]any)
		require.NoError(t, json.Unmarshal([]byte(strings.ReplaceAll(idTokenClaims, "%s", issuer)), &claims))
		if _, ok := claims["nonce"]; !ok && idp.nonce != "" {
			claims["nonce"] = idp.nonce
		}

		rawClaims, err := json.Marshal(claims)
		require.NoError(t, err)

		idToken := oidctest.SignIDToken(priv, "test-key", oidc.RS256, string(rawClaims))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
		})
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if userInfoClaims == nil {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(userInfoClaims)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	issuer = server.URL
	keyServer.SetIssuer(server.URL)
	idp.Server = server

	return idp
}

func TestNew(t *testing.T) {
	newTestAuthN(t)
}

func TestLoginURL(t *testing.T) {
	authN := newTestAuthN(t)

	server := newOIDCDiscoveryServer(t)
	authDomain := newTestOIDCAuthDomain(t, &authtypes.OIDCConfig{
		Issuer:       server.URL,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}, nil)

	siteURL := &url.URL{Scheme: "https", Host: "signoz.example.com"}

	rawURL, err := authN.LoginURL(context.Background(), siteURL, authDomain)
	require.NoError(t, err)

	parsed, err := url.Parse(rawURL)
	require.NoError(t, err)

	assert.Equal(t, server.URL+"/auth", parsed.Scheme+"://"+parsed.Host+parsed.Path)

	query := parsed.Query()
	assert.Equal(t, "test-client-id", query.Get("client_id"))
	assert.Equal(t, "code", query.Get("response_type"))
	assert.Equal(t, "https://signoz.example.com/api/v1/complete/oidc", query.Get("redirect_uri"))
	assert.ElementsMatch(t, []string{"openid", "email", "profile"}, strings.Split(query.Get("scope"), " "))

	assert.Equal(t, "S256", query.Get("code_challenge_method"))
	assert.NotEmpty(t, query.Get("code_challenge"))
	assert.NotEmpty(t, query.Get("nonce"))

	state, err := authtypes.NewStateFromString(query.Get("state"))
	require.NoError(t, err)
	assert.Equal(t, authDomain.StorableAuthDomain().ID, state.DomainID)
	assert.NotEmpty(t, state.URL.Query().Get(sealedStateParam))

	// the PKCE verifier and the nonce must never travel in clear text
	assert.NotContains(t, query.Get("state"), query.Get("nonce"))
}

func TestLoginURLWithRoleMappingRequestsGroupsScope(t *testing.T) {
	authN := newTestAuthN(t)

	server := newOIDCDiscoveryServer(t)
	authDomain := newTestOIDCAuthDomain(t, &authtypes.OIDCConfig{
		Issuer:       server.URL,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}, &authtypes.RoleMapping{
		UseRoleAttribute: true,
	})

	siteURL := &url.URL{Scheme: "https", Host: "signoz.example.com"}

	rawURL, err := authN.LoginURL(context.Background(), siteURL, authDomain)
	require.NoError(t, err)

	parsed, err := url.Parse(rawURL)
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"openid", "email", "profile", "groups"}, strings.Split(parsed.Query().Get("scope"), " "))
}

func TestLoginURLWithoutOIDCConfig(t *testing.T) {
	authN := newTestAuthN(t)

	config := &authtypes.AuthDomainConfig{
		SSOEnabled:    true,
		AuthNProvider: authtypes.AuthNProviderGoogleAuth,
		Google: &authtypes.GoogleConfig{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		},
	}

	authDomain, err := authtypes.NewAuthDomainFromConfig("example.com", config, valuer.GenerateUUID())
	require.NoError(t, err)

	_, err = authN.LoginURL(context.Background(), &url.URL{Scheme: "https", Host: "signoz.example.com"}, authDomain)
	require.Error(t, err)
	assert.True(t, errors.Ast(err, errors.TypeInternal))
}

func TestLoginURLWithDiscoveryTimeout(t *testing.T) {
	authN := newTestAuthN(t)

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(200 * time.Millisecond):
		case <-r.Context().Done():
		}
	})

	authDomain := newTestOIDCAuthDomain(t, &authtypes.OIDCConfig{
		Issuer:       server.URL,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := authN.LoginURL(ctx, &url.URL{Scheme: "https", Host: "signoz.example.com"}, authDomain)
	require.Error(t, err)
	assert.True(t, errors.Ast(err, errors.TypeTimeout))
	assert.True(t, errors.Asc(err, errors.CodeTimeout))
}

func TestLoginURLWithFailedDiscovery(t *testing.T) {
	authN := newTestAuthN(t)

	// server without a `.well-known/openid-configuration` handler -> 404 on discovery
	server := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(server.Close)

	authDomain := newTestOIDCAuthDomain(t, &authtypes.OIDCConfig{
		Issuer:       server.URL,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}, nil)

	_, err := authN.LoginURL(context.Background(), &url.URL{Scheme: "https", Host: "signoz.example.com"}, authDomain)
	require.Error(t, err)
	assert.True(t, errors.Ast(err, errors.TypeInternal))
}

func TestHandleCallbackWithErrorParam(t *testing.T) {
	authN := newTestAuthN(t)

	query := url.Values{}
	query.Set("error", "access_denied")
	query.Set("error_description", "user denied access")

	identity, err := authN.HandleCallback(context.Background(), query)
	require.Error(t, err)
	assert.Nil(t, identity)
	assert.True(t, errors.Ast(err, errors.TypeInternal))
}

func TestHandleCallbackWithInvalidState(t *testing.T) {
	authN := newTestAuthN(t)

	query := url.Values{}
	query.Set("code", "test-code")
	query.Set("state", "not-a-valid-state")

	identity, err := authN.HandleCallback(context.Background(), query)
	require.Error(t, err)
	assert.Nil(t, identity)
	assert.True(t, errors.Ast(err, errors.TypeInvalidInput))
	assert.True(t, errors.Asc(err, authtypes.ErrCodeInvalidState))
}

func TestHandleCallbackSuccess(t *testing.T) {
	idTokenClaims := `{
		"iss": "%s",
		"aud": "test-client-id",
		"sub": "user-123",
		"exp": ` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `,
		"email": "user@example.com",
		"email_verified": true,
		"name": "Test User",
		"groups": ["admin", "dev"],
		"role": "EDITOR"
	}`

	server := newOIDCServer(t, idTokenClaims, nil)

	authDomain := newTestOIDCAuthDomain(t, &authtypes.OIDCConfig{
		Issuer:       server.URL,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}, nil)

	authN, err := New(context.Background(), &fakeStore{authDomain: authDomain}, factorytest.NewSettings(), global.Config{})
	require.NoError(t, err)

	query := beginLogin(t, authN, authDomain, server)

	identity, err := authN.HandleCallback(context.Background(), query)
	require.NoError(t, err)
	require.NotNil(t, identity)

	assert.Equal(t, "Test User", identity.Name)
	assert.Equal(t, "user@example.com", identity.Email.StringValue())
	assert.Equal(t, authDomain.StorableAuthDomain().OrgID, identity.OrgID)
	assert.ElementsMatch(t, []string{"admin", "dev"}, identity.Groups)
	assert.Equal(t, "EDITOR", identity.Role)
	assert.Equal(t, authDomain.StorableAuthDomain().ID, identity.State.DomainID)
}

func TestHandleCallbackEmailNotVerified(t *testing.T) {
	idTokenClaims := `{
		"iss": "%s",
		"aud": "test-client-id",
		"sub": "user-123",
		"exp": ` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `,
		"email": "user@example.com",
		"email_verified": false,
		"name": "Test User"
	}`

	server := newOIDCServer(t, idTokenClaims, nil)

	authDomain := newTestOIDCAuthDomain(t, &authtypes.OIDCConfig{
		Issuer:       server.URL,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}, nil)

	authN, err := New(context.Background(), &fakeStore{authDomain: authDomain}, factorytest.NewSettings(), global.Config{})
	require.NoError(t, err)

	query := beginLogin(t, authN, authDomain, server)

	identity, err := authN.HandleCallback(context.Background(), query)
	require.Error(t, err)
	assert.Nil(t, identity)
	assert.True(t, errors.Ast(err, errors.TypeForbidden))
}

func TestHandleCallbackInsecureSkipEmailVerified(t *testing.T) {
	idTokenClaims := `{
		"iss": "%s",
		"aud": "test-client-id",
		"sub": "user-123",
		"exp": ` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `,
		"email": "user@example.com",
		"email_verified": false,
		"name": "Test User"
	}`

	server := newOIDCServer(t, idTokenClaims, nil)

	authDomain := newTestOIDCAuthDomain(t, &authtypes.OIDCConfig{
		Issuer:                    server.URL,
		ClientID:                  "test-client-id",
		ClientSecret:              "test-client-secret",
		InsecureSkipEmailVerified: true,
	}, nil)

	authN, err := New(context.Background(), &fakeStore{authDomain: authDomain}, factorytest.NewSettings(), global.Config{})
	require.NoError(t, err)

	query := beginLogin(t, authN, authDomain, server)

	identity, err := authN.HandleCallback(context.Background(), query)
	require.NoError(t, err)
	require.NotNil(t, identity)
	assert.Equal(t, "user@example.com", identity.Email.StringValue())
}

func TestHandleCallbackWithUserInfo(t *testing.T) {
	idTokenClaims := `{
		"iss": "%s",
		"aud": "test-client-id",
		"sub": "user-123",
		"exp": ` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `,
		"email": "user@example.com",
		"email_verified": true,
		"name": "Thin Token User"
	}`

	server := newOIDCServer(t, idTokenClaims, map[string]any{
		"sub":            "user-123",
		"email":          "user@example.com",
		"email_verified": true,
		"name":           "Full UserInfo User",
		"groups":         []string{"admin"},
	})

	authDomain := newTestOIDCAuthDomain(t, &authtypes.OIDCConfig{
		Issuer:       server.URL,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		GetUserInfo:  true,
	}, nil)

	authN, err := New(context.Background(), &fakeStore{authDomain: authDomain}, factorytest.NewSettings(), global.Config{})
	require.NoError(t, err)

	query := beginLogin(t, authN, authDomain, server)

	identity, err := authN.HandleCallback(context.Background(), query)
	require.NoError(t, err)
	require.NotNil(t, identity)

	assert.Equal(t, "Full UserInfo User", identity.Name)
	assert.ElementsMatch(t, []string{"admin"}, identity.Groups)
}

// newCallbackTest wires an AuthN to a fake IdP that issues an id token with the given claims.
func newCallbackTest(t *testing.T, idTokenClaims string, userInfoClaims map[string]any, getUserInfo bool) (*AuthN, *authtypes.AuthDomain, *fakeIdP) {
	t.Helper()

	server := newOIDCServer(t, idTokenClaims, userInfoClaims)

	authDomain := newTestOIDCAuthDomain(t, &authtypes.OIDCConfig{
		Issuer:       server.URL,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		GetUserInfo:  getUserInfo,
	}, nil)

	authN, err := New(context.Background(), &fakeStore{authDomain: authDomain}, factorytest.NewSettings(), global.Config{})
	require.NoError(t, err)

	return authN, authDomain, server
}

func validIDTokenClaims(extra string) string {
	return `{
		"iss": "%s",
		"aud": "test-client-id",
		"sub": "user-123",
		"exp": ` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `,
		"email": "user@example.com",
		"email_verified": true,
		"name": "Test User"` + extra + `
	}`
}

func TestHandleCallbackRejectsInvalidIDToken(t *testing.T) {
	expired := strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)

	testCases := []struct {
		name   string
		claims string
	}{
		{name: "WrongAudience", claims: `{"iss": "%s", "aud": "other-client", "sub": "user-123", "exp": 9999999999, "email": "user@example.com", "email_verified": true}`},
		{name: "WrongIssuer", claims: `{"iss": "https://evil.example.com", "aud": "test-client-id", "sub": "user-123", "exp": 9999999999, "email": "user@example.com", "email_verified": true}`},
		{name: "Expired", claims: `{"iss": "%s", "aud": "test-client-id", "sub": "user-123", "exp": ` + expired + `, "email": "user@example.com", "email_verified": true}`},
		{name: "NonceMismatch", claims: validIDTokenClaims(`, "nonce": "replayed-nonce"`)},
		{name: "AzpMismatch", claims: validIDTokenClaims(`, "azp": "other-client"`)},
		{name: "MultipleAudiencesWithoutAzp", claims: `{"iss": "%s", "aud": ["test-client-id", "other-client"], "sub": "user-123", "exp": 9999999999, "email": "user@example.com", "email_verified": true}`},
		{name: "EmailNotVerifiedMissing", claims: `{"iss": "%s", "aud": "test-client-id", "sub": "user-123", "exp": 9999999999, "email": "user@example.com"}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			authN, authDomain, server := newCallbackTest(t, tc.claims, nil, false)

			identity, err := authN.HandleCallback(context.Background(), beginLogin(t, authN, authDomain, server))
			require.Error(t, err)
			assert.Nil(t, identity)
			assert.True(t, errors.Ast(err, errors.TypeForbidden))
		})
	}
}

func TestHandleCallbackAcceptsMatchingAzp(t *testing.T) {
	authN, authDomain, server := newCallbackTest(t, `{"iss": "%s", "aud": ["test-client-id", "other-client"], "azp": "test-client-id", "sub": "user-123", "exp": 9999999999, "email": "user@example.com", "email_verified": true}`, nil, false)

	identity, err := authN.HandleCallback(context.Background(), beginLogin(t, authN, authDomain, server))
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", identity.Email.StringValue())
}

func TestHandleCallbackRejectsPKCEMismatch(t *testing.T) {
	authN, authDomain, server := newCallbackTest(t, validIDTokenClaims(""), nil, false)

	query := beginLogin(t, authN, authDomain, server)
	// simulate an authorization code obtained by another authorization request
	server.codeChallenge = "challenge-of-another-request"

	identity, err := authN.HandleCallback(context.Background(), query)
	require.Error(t, err)
	assert.Nil(t, identity)
	assert.True(t, errors.Ast(err, errors.TypeForbidden))
}

func TestHandleCallbackRejectsUserInfoSubjectMismatch(t *testing.T) {
	authN, authDomain, server := newCallbackTest(t, validIDTokenClaims(""), map[string]any{
		"sub":            "attacker-456",
		"email":          "attacker@example.com",
		"email_verified": true,
	}, true)

	identity, err := authN.HandleCallback(context.Background(), beginLogin(t, authN, authDomain, server))
	require.Error(t, err)
	assert.Nil(t, identity)
	assert.True(t, errors.Ast(err, errors.TypeForbidden))
}

func TestHandleCallbackRejectsTamperedState(t *testing.T) {
	testCases := []struct {
		name   string
		tamper func(state *url.URL)
	}{
		// an attacker-controlled host would receive the session tokens in the post-login redirect
		{name: "Host", tamper: func(state *url.URL) { state.Host = "evil.example.com" }},
		{name: "Path", tamper: func(state *url.URL) { state.Path = "/evil" }},
		{name: "MissingSealedState", tamper: func(state *url.URL) {
			query := state.Query()
			query.Del(sealedStateParam)
			state.RawQuery = query.Encode()
		}},
		{name: "CorruptedSealedState", tamper: func(state *url.URL) {
			query := state.Query()
			query.Set(sealedStateParam, "AAAA"+query.Get(sealedStateParam))
			state.RawQuery = query.Encode()
		}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			authN, authDomain, server := newCallbackTest(t, validIDTokenClaims(""), nil, false)

			query := beginLogin(t, authN, authDomain, server)
			state, err := url.Parse(query.Get("state"))
			require.NoError(t, err)
			tc.tamper(state)
			query.Set("state", state.String())

			identity, err := authN.HandleCallback(context.Background(), query)
			require.Error(t, err)
			assert.Nil(t, identity)
			assert.True(t, errors.Ast(err, errors.TypeInvalidInput))
			assert.True(t, errors.Asc(err, authtypes.ErrCodeInvalidState))
		})
	}
}

func TestHandleCallbackRejectsStateFromAnotherClientSecret(t *testing.T) {
	authN, authDomain, _ := newCallbackTest(t, validIDTokenClaims(""), nil, false)

	state := authtypes.NewState(&url.URL{Scheme: "https", Host: "signoz.example.com"}, authDomain.StorableAuthDomain().ID)
	sealed, err := sealState("guessed-secret", state, sealedState{Nonce: "n", Verifier: "v", ExpiresAt: time.Now().Add(time.Minute).Unix()})
	require.NoError(t, err)

	stateQuery := state.URL.Query()
	stateQuery.Set(sealedStateParam, sealed)
	state.URL.RawQuery = stateQuery.Encode()

	query := url.Values{}
	query.Set("code", "test-code")
	query.Set("state", state.URL.String())

	identity, err := authN.HandleCallback(context.Background(), query)
	require.Error(t, err)
	assert.Nil(t, identity)
	assert.True(t, errors.Asc(err, authtypes.ErrCodeInvalidState))
}

func TestHandleCallbackRejectsExpiredState(t *testing.T) {
	authN, authDomain, _ := newCallbackTest(t, validIDTokenClaims(""), nil, false)

	state := authtypes.NewState(&url.URL{Scheme: "https", Host: "signoz.example.com"}, authDomain.StorableAuthDomain().ID)
	sealed, err := sealState("test-client-secret", state, sealedState{Nonce: "n", Verifier: "v", ExpiresAt: time.Now().Add(-time.Second).Unix()})
	require.NoError(t, err)

	stateQuery := state.URL.Query()
	stateQuery.Set(sealedStateParam, sealed)
	state.URL.RawQuery = stateQuery.Encode()

	query := url.Values{}
	query.Set("code", "test-code")
	query.Set("state", state.URL.String())

	identity, err := authN.HandleCallback(context.Background(), query)
	require.Error(t, err)
	assert.Nil(t, identity)
	assert.True(t, errors.Asc(err, authtypes.ErrCodeInvalidState))
}

func TestProviderInfo(t *testing.T) {
	authN := newTestAuthN(t)

	info := authN.ProviderInfo(context.Background(), nil)

	require.NotNil(t, info)
	assert.Nil(t, info.RelayStatePath)
}
