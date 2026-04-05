package locket

import (
	"os"
	"path"
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
	p := path.Join("example", "test-readwrite.yml")
	reg := FileRegistry{Path: p}
	defer os.Remove(p)

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

func TestFileRegistryRegister(t *testing.T) {
	testRegistry := path.Join("example", "test-registry.yml")
	reg := FileRegistry{Path: testRegistry}
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

	err = os.Remove(testRegistry)
	require.NoError(t, err)
}

func TestFileRegistryDelete(t *testing.T) {
	testRegistry := path.Join("example", "test-delete.yml")
	reg := FileRegistry{Path: testRegistry}
	defer os.Remove(testRegistry)

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
