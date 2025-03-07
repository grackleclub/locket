package locket

import (
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

var testEnvFile = path.Join("example", "example.env")

func TestLoadFile(t *testing.T) {
	var source = dotenv{
		path: path.Join(testEnvFile),
	}
	secrets, err := source.load()
	require.NoError(t, err)
	for k, v := range secrets {
		t.Logf("%v=%v", k, v)
	}
}

func TestLoadDotenv(t *testing.T) {
	var source = env{}
	secrets, err := source.load()
	require.NoError(t, err)
	for k, _ := range secrets {
		t.Logf("loaded: %v", k)
	}
}
