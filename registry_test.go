package locket

import (
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

var testRegistryItems = []regEntry{
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

	items, err := ReadRegistry(testExampleReg)
	require.NoError(t, err)
	require.NotNil(t, items)
	require.Equal(t, testRegistryItems, items)
	for _, item := range items {
		t.Logf("item: %v", item)
	}
}
