/*
 *  Copyright 2026 Keyfactor
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 *  and limitations under the License.
 */

package kfbackend

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
)

// clearOAuthEnv ensures ambient KEYFACTOR_AUTH_* environment variables on the
// test machine can't mask a missing field in the config under test.
func clearOAuthEnv(t *testing.T) {
	t.Helper()
	t.Setenv(auth_providers.EnvKeyfactorClientID, "")
	t.Setenv(auth_providers.EnvKeyfactorClientSecret, "")
	t.Setenv(auth_providers.EnvKeyfactorAccessToken, "")
	t.Setenv(auth_providers.EnvKeyfactorAuthScopes, "")
	t.Setenv(auth_providers.EnvKeyfactorAuthAudience, "")
}

// newTestCommandServer stands in for Keyfactor Command's Status/Endpoints
// health check, which CommandAuthConfig.Authenticate calls once a token has
// been obtained. recvAuthHeader, if non-nil, captures the Authorization
// header of the request it receives.
func newTestCommandServer(t *testing.T, recvAuthHeader *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if recvAuthHeader != nil {
			*recvAuthHeader = r.Header.Get("Authorization")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]string{})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestNewClient_OAuthClientCredentials_PropagatesScopesAndAudience is a
// regression test for a bug in keyfactor-go-client-sdk/v24 v24.0.0: the SDK
// rebuilt its own internal OAuth client from scratch and did not copy the
// Scopes or Audience already configured on the plugin's auth_providers.Server,
// so client-credentials token requests silently lost `scope` and `audience`.
// Entra ID rejects a scope-less request with AADSTS90014. Fixed in SDK
// v24.0.1, which forwards these fields.
func TestNewClient_OAuthClientCredentials_PropagatesScopesAndAudience(t *testing.T) {
	clearOAuthEnv(t)

	var gotForm url.Values
	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse token request form: %v", err)
		}
		gotForm = r.Form

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	t.Cleanup(tokenServer.Close)

	commandServer := newTestCommandServer(t, nil)

	config := &keyfactorConfig{
		KeyfactorUrl:   commandServer.URL,
		CommandAPIPath: "KeyfactorAPI",
		ClientId:       "test-client-id",
		ClientSecret:   "test-client-secret",
		TokenUrl:       tokenServer.URL + "/oauth2/token",
		Scopes:         []string{"api://213f3fa5-d24f-44dd-b0cf-3c3826f1be38/.default"},
		Audience:       "api://213f3fa5-d24f-44dd-b0cf-3c3826f1be38",
		SkipTLSVerify:  true,
	}

	b, _ := getTestBackend(t)

	client, err := newClient(config, b)
	if err != nil {
		t.Fatalf("newClient returned an unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("newClient returned a nil client")
	}

	if gotForm == nil {
		t.Fatal("token endpoint was never called")
	}
	if got := gotForm.Get("scope"); got != config.Scopes[0] {
		t.Errorf("expected token request 'scope' to be %q, got %q (this is the AADSTS90014 regression if empty)", config.Scopes[0], got)
	}
	if got := gotForm.Get("audience"); got != config.Audience {
		t.Errorf("expected token request 'audience' to be %q, got %q", config.Audience, got)
	}
}

// TestNewClient_OAuthAccessToken_DoesNotRequireClientID is a regression test
// for the same SDK v24.0.0 bug: when the plugin is configured with only an
// external AccessToken (no client credentials), the SDK's rebuilt OAuth
// client had an empty AccessToken and fell back to the client-credentials
// path, failing validation with "client ID or environment variable
// KEYFACTOR_AUTH_CLIENT_ID is required" even though no client-credentials
// flow was requested. Fixed in SDK v24.0.1.
func TestNewClient_OAuthAccessToken_DoesNotRequireClientID(t *testing.T) {
	clearOAuthEnv(t)

	var gotAuthHeader string
	commandServer := newTestCommandServer(t, &gotAuthHeader)

	config := &keyfactorConfig{
		KeyfactorUrl:   commandServer.URL,
		CommandAPIPath: "KeyfactorAPI",
		AccessToken:    "test-external-access-token",
		SkipTLSVerify:  true,
	}

	b, _ := getTestBackend(t)

	client, err := newClient(config, b)
	if err != nil {
		t.Fatalf("newClient returned an unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("newClient returned a nil client")
	}

	if want := "Bearer test-external-access-token"; gotAuthHeader != want {
		t.Errorf("expected Command request Authorization header %q, got %q", want, gotAuthHeader)
	}
}
