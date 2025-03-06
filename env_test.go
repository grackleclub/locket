package locket

import (
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

var testEnvFile = path.Join("example", "example.env")

func TestLoadFile(t *testing.T) {
	secrets, err := loadFile(testEnvFile)
	require.NoError(t, err)
	for k, v := range secrets {
		t.Logf("%v=%v", k, v)
	}
}
