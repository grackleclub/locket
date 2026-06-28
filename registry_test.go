package locket

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

var testRegistryItems = []RegEntry{
	{
		Name:   "foo1",
		KeyPub: "asdfasdf",
	},
	{
		Name:   "bar2",
		KeyPub: "zyx",
	},
}

func TestFileRegistryReadWrite(t *testing.T) {
	reg := FileRegistry{Path: filepath.Join(t.TempDir(), "registry.yml")}

	for _, item := range testRegistryItems {
		err := reg.Upsert(item)
		require.NoError(t, err)
	}

	items, err := reg.Entries()
	require.NoError(t, err)
	require.NotNil(t, items)
	require.Equal(t, testRegistryItems, items)
	for _, item := range items {
		t.Logf("item: %v", item)
	}
}

// TestFileRegistryUpsertDedup verifies Upsert dedups on the exact name
// (verbatim, case-sensitive) per the cloud registry contract: re-registering
// the same name updates the entry in place, while a different name (e.g. one
// with a .env suffix) is a distinct entry — Upsert does not normalize.
func TestFileRegistryUpsertDedup(t *testing.T) {
	reg := FileRegistry{Path: filepath.Join(t.TempDir(), "registry.yml")}

	pub1, _, err := reg.Register("svc")
	require.NoError(t, err)

	// re-registering the exact name updates in place (no duplicate)
	pub2, _, err := reg.Register("svc")
	require.NoError(t, err)

	// a different, un-normalized name is a distinct entry
	_, _, err = reg.Register("svc.env")
	require.NoError(t, err)

	entries, err := reg.Entries()
	require.NoError(t, err)
	require.Len(t, entries, 2,
		"exact-name re-register dedups; a distinct name does not")

	byName := make(map[string]string, len(entries))
	for _, e := range entries {
		byName[e.Name] = e.KeyPub
	}
	require.Contains(t, byName, "svc")
	require.Contains(t, byName, "svc.env")
	require.Equal(t, pub2, byName["svc"], "last write wins for the exact name")
	require.NotEqual(t, pub1, pub2)
}

func TestFileRegistryRegister(t *testing.T) {
	reg := FileRegistry{Path: filepath.Join(t.TempDir(), "registry.yml")}

	services := []string{"service A", "service B", "service C"}

	for _, service := range services {
		pub, priv, err := reg.Register(service)
		require.NoError(t, err)
		require.NotEmpty(t, pub)
		require.NotEmpty(t, priv)
		t.Logf("Registered %q", service)

		entries, err := reg.Entries()
		require.NoError(t, err)
		for _, e := range entries {
			t.Logf("%s\n%s", e.Name, e.KeyPub)
		}
	}

	// upsert service A with new key
	pub, priv, err := reg.Register(services[0])
	require.NoError(t, err)
	require.NotEmpty(t, pub)
	require.NotEmpty(t, priv)
	t.Logf("Updated %q", services[0])

	entries, err := reg.Entries()
	require.NoError(t, err)
	for _, e := range entries {
		t.Logf("%s\n%s", e.Name, e.KeyPub)
	}
}

func TestFileRegistryDelete(t *testing.T) {
	reg := FileRegistry{Path: filepath.Join(t.TempDir(), "registry.yml")}

	require.NoError(t, reg.Upsert(RegEntry{Name: "a", KeyPub: "k1"}))
	require.NoError(t, reg.Upsert(RegEntry{Name: "b", KeyPub: "k2"}))

	entries, err := reg.Entries()
	require.NoError(t, err)
	require.Len(t, entries, 2)

	require.NoError(t, reg.Delete("a"))

	entries, err = reg.Entries()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "b", entries[0].Name)
}
