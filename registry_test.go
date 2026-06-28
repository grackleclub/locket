package locket

import (
	"os"
	"path"
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

var testExampleReg = path.Join("example", "registry.yml")

func TestReadWrite(t *testing.T) {
	err := WriteRegistry(testExampleReg, testRegistryItems)
	require.NoError(t, err)

	items, err := ReadRegistryFile(testExampleReg)
	require.NoError(t, err)
	require.NotNil(t, items)
	require.Equal(t, testRegistryItems, items)
	for _, item := range items {
		t.Logf("item: %v", item)
	}
}

// TestRegisterNoDuplicate is the regression test for Register name
// normalization: re-registering a service (including with a .env suffix that
// WriteRegistry strips) must update the existing entry rather than append a
// duplicate.
func TestRegisterNoDuplicate(t *testing.T) {
	reg := filepath.Join(t.TempDir(), "registry.yml")

	_, _, err := Register("svc.env", reg)
	require.NoError(t, err)

	pub2, _, err := Register("svc.env", reg)
	require.NoError(t, err)

	// the plain name normalizes to the same entry too
	_, _, err = Register("svc", reg)
	require.NoError(t, err)

	entries, err := ReadRegistryFile(reg)
	require.NoError(t, err)
	require.Len(t, entries, 1, "re-registering the same service must not duplicate")
	require.Equal(t, "svc", entries[0].Name)
	// last write wins on the key
	require.NotEqual(t, pub2, entries[0].KeyPub)
}

func TestRegister(t *testing.T) {
	testRegistry := path.Join("example", "test-registry.yml")
	services := []string{"service A", "service B", "service C"}
	// no file exists
	for _, service := range services {
		pub, priv, err := Register(service, testRegistry)
		require.NoError(t, err)
		require.NotEmpty(t, pub)
		require.NotEmpty(t, priv)
		t.Logf("Registered %q", service)

		registry, err := ReadRegistryFile(testRegistry)
		require.NoError(t, err)
		for _, item := range registry {
			t.Logf("%s\n%s", item.Name, item.KeyPub)
		}
	}
	// replace/update/upsert service A with new key
	pub, priv, err := Register(services[0], testRegistry)
	require.NoError(t, err)
	require.NotEmpty(t, pub)
	require.NotEmpty(t, priv)
	t.Logf("Updated %q", services[0])
	registry, err := ReadRegistryFile(testRegistry)
	require.NoError(t, err)
	for _, item := range registry {
		t.Logf("%s\n%s", item.Name, item.KeyPub)
	}
	// cleanup file
	err = os.Remove(testRegistry)
	require.NoError(t, err)
	t.Logf("Removed test registry file: %s", testRegistry)
}
