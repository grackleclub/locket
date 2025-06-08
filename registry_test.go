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
