package main

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestBuildInfoMatchesCompiledFlavor(t *testing.T) {
	info := buildInfo()
	require.Equal(t, buildFlavor, info.BuildFlavor)
	require.Equal(t, fullBuild, info.Features.Postgres)
	require.Equal(t, fullBuild, info.Features.ExternalSecretSources)
	require.Equal(t, fullBuild, info.Features.RemoteConfigS3)
	encoded, err := json.Marshal(info)
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Contains(t, decoded, "buildFlavor")
	require.Contains(t, decoded, "features")
}
