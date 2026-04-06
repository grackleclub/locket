package locket

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRemoteRegistryEntries(t *testing.T) {
	want := []RegEntry{
		{Name: "svc1", KeyPub: "pub1"},
		{Name: "svc2", KeyPub: "pub2"},
	}

	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, http.MethodGet, r.Method)
			require.Equal(t, PathRegistry, r.URL.Path)
			require.Equal(t, "tok", r.Header.Get("X-Auth-Token"))
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(want))
		},
	))
	defer srv.Close()

	// Trailing slash on URL; JoinPath should normalize.
	reg := RemoteRegistry{URL: srv.URL + "/", Token: "tok"}
	got, err := reg.Entries()
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestRemoteRegistryUpsert(t *testing.T) {
	want := RegEntry{Name: "svc1", KeyPub: "pub1"}

	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, http.MethodPost, r.Method)
			require.Equal(t, PathRegistry, r.URL.Path)
			require.Equal(t,
				"application/json", r.Header.Get("Content-Type"),
			)

			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var got RegEntry
			require.NoError(t, json.Unmarshal(body, &got))
			require.Equal(t, want, got)

			// Return 201 to confirm 2xx acceptance.
			w.WriteHeader(http.StatusCreated)
		},
	))
	defer srv.Close()

	reg := RemoteRegistry{URL: srv.URL}
	require.NoError(t, reg.Upsert(want))
}

func TestRemoteRegistryDelete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, http.MethodDelete, r.Method)
			require.Equal(t, PathRegistry, r.URL.Path)

			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var got RegEntry
			require.NoError(t, json.Unmarshal(body, &got))
			require.Equal(t, "svc1", got.Name)

			// Return 204 to confirm 2xx acceptance.
			w.WriteHeader(http.StatusNoContent)
		},
	))
	defer srv.Close()

	reg := RemoteRegistry{URL: srv.URL}
	require.NoError(t, reg.Delete("svc1"))
}

func TestRemoteRegistryRegister(t *testing.T) {
	var seen RegEntry

	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, http.MethodPost, r.Method)
			require.NoError(t, json.NewDecoder(r.Body).Decode(&seen))
			w.WriteHeader(http.StatusOK)
		},
	))
	defer srv.Close()

	reg := RemoteRegistry{URL: srv.URL}
	pub, priv, err := reg.Register("svc1")
	require.NoError(t, err)
	require.NotEmpty(t, pub)
	require.NotEmpty(t, priv)
	require.Equal(t, "svc1", seen.Name)
	require.Equal(t, pub, seen.KeyPub)
}

func TestRemoteRegistryInvalidBaseURL(t *testing.T) {
	reg := RemoteRegistry{URL: "api:8888"}
	_, err := reg.Entries()
	require.Error(t, err)
	require.ErrorContains(t, err, "missing scheme or host")
}

func TestRemoteRegistryNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		},
	))
	defer srv.Close()

	reg := RemoteRegistry{URL: srv.URL}
	_, err := reg.Entries()
	require.Error(t, err)
	require.ErrorContains(t, err, "500")
}
