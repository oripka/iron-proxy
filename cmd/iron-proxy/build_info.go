package main

type buildCapabilities struct {
	BuildFlavor string `json:"buildFlavor"`
	Features    struct {
		Postgres              bool `json:"postgres"`
		ExternalSecretSources bool `json:"externalSecretSources"`
		RemoteConfigS3        bool `json:"remoteConfigS3"`
	} `json:"features"`
}

func buildInfo() buildCapabilities {
	var info buildCapabilities
	info.BuildFlavor = buildFlavor
	info.Features.Postgres = fullBuild
	info.Features.ExternalSecretSources = fullBuild
	info.Features.RemoteConfigS3 = fullBuild
	return info
}
