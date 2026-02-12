package cluster

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// InspectImage inspects a container image and extracts relevant metadata
func InspectImage(ctx context.Context, imageRef string, opts ...remote.Option) (*ImageInfo, error) {
	info := &ImageInfo{
		ImageID:   imageRef,
		ImageName: imageRef,
		Labels:    make(map[string]string),
		Env:       make(map[string]string),
	}

	// Parse image reference
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("parse image reference: %w", err)
	}

	// Add context to options
	opts = append(opts, remote.WithContext(ctx))

	// Fetch image config
	img, err := remote.Image(ref, opts...)
	if err != nil {
		return nil, fmt.Errorf("fetch image: %w", err)
	}

	// Get config file
	configFile, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("get config file: %w", err)
	}

	// Extract labels
	if configFile.Config.Labels != nil {
		info.Labels = configFile.Config.Labels
	}

	// Extract environment variables
	for _, envVar := range configFile.Config.Env {
		parts := strings.SplitN(envVar, "=", 2)
		if len(parts) == 2 {
			info.Env[parts[0]] = parts[1]
		}
	}

	// Check for coverage enablement
	// Method 1: Explicit GO_COMPLIANCE_COVER env var (legacy)
	if goCover, ok := info.Env["GO_COMPLIANCE_COVER"]; ok && goCover == "1" {
		info.HasCoverage = true
	}

	// Method 2: Images with OpenShift build source info are built by the same
	// system that injects the coverage server, so treat them as coverage-enabled.
	if !info.HasCoverage {
		_, hasCommitID := info.Labels["io.openshift.build.commit.id"]
		_, hasSourceLoc := info.Labels["io.openshift.build.source-location"]
		if hasCommitID && hasSourceLoc {
			info.HasCoverage = true
		}
	}

	// Set coverage port if coverage is enabled
	if info.HasCoverage {
		if portStr, ok := info.Env["COVERAGE_PORT"]; ok {
			if port, err := strconv.Atoi(portStr); err == nil {
				info.CoveragePort = port
			} else {
				info.CoveragePort = 53700 // Default starting port
			}
		} else {
			info.CoveragePort = 53700 // Default starting port
		}
	}

	// Extract build metadata from labels
	// Try multiple label conventions in order of preference

	// 1. OpenShift-specific labels
	if commitID, ok := info.Labels["io.openshift.build.commit.id"]; ok {
		info.BuildCommitID = commitID
	}

	if commitURL, ok := info.Labels["io.openshift.build.commit.url"]; ok {
		info.BuildCommitURL = commitURL
	}

	if sourceLocation, ok := info.Labels["io.openshift.build.source-location"]; ok {
		info.SourceLocation = sourceLocation
	}

	// 2. Standard OCI labels (org.opencontainers.image.*)
	if info.BuildCommitID == "" {
		if revision, ok := info.Labels["org.opencontainers.image.revision"]; ok {
			info.BuildCommitID = revision
		}
	}

	if info.SourceLocation == "" {
		if source, ok := info.Labels["org.opencontainers.image.source"]; ok {
			info.SourceLocation = source
		}
	}

	// 3. GitHub Actions labels
	if info.SourceLocation == "" {
		if url, ok := info.Labels["org.opencontainers.image.url"]; ok {
			info.SourceLocation = url
		}
	}

	// 4. Legacy labels
	if info.BuildCommitID == "" {
		if vcs, ok := info.Labels["vcs.revision"]; ok {
			info.BuildCommitID = vcs
		} else if vcs, ok := info.Labels["vcs-ref"]; ok {
			info.BuildCommitID = vcs
		}
	}

	if info.SourceLocation == "" {
		if url, ok := info.Labels["vcs.url"]; ok {
			info.SourceLocation = url
		} else if url, ok := info.Labels["vcs-url"]; ok {
			info.SourceLocation = url
		}
	}

	// 5. Try to construct commit URL from source location and commit ID
	if info.BuildCommitURL == "" && info.SourceLocation != "" && info.BuildCommitID != "" {
		// If source location is a GitHub URL, construct commit URL
		if strings.Contains(info.SourceLocation, "github.com") {
			// Remove .git suffix if present
			sourceURL := strings.TrimSuffix(info.SourceLocation, ".git")
			// Construct commit URL
			info.BuildCommitURL = sourceURL + "/commit/" + info.BuildCommitID
		}
	}

	// Generate repository key if we have source information
	if info.BuildCommitURL != "" && info.BuildCommitID != "" {
		info.RepositoryKey = GetRepositoryKey(info.BuildCommitURL, info.BuildCommitID)
	} else if info.SourceLocation != "" && info.BuildCommitID != "" {
		info.RepositoryKey = GetRepositoryKey(info.SourceLocation, info.BuildCommitID)
	}

	return info, nil
}

// ParseRepositoryInfo extracts organization and repo name from build commit URL or source location
// Supports multiple URL formats:
//   - https://github.com/org/repo/commit/commitid
//   - https://github.com/org/repo
//   - https://github.com/org/repo.git
//   - git://github.com/org/repo.git
func ParseRepositoryInfo(commitURL, sourceLocation string) (org, repo, commitID string, err error) {
	// Try to parse from commit URL first
	if commitURL != "" {
		parsedOrg, parsedRepo, parsedCommit := parseGitHubURL(commitURL)
		if parsedOrg != "" && parsedRepo != "" {
			return parsedOrg, parsedRepo, parsedCommit, nil
		}
	}

	// Fallback to source location
	if sourceLocation != "" {
		parsedOrg, parsedRepo, parsedCommit := parseGitHubURL(sourceLocation)
		if parsedOrg != "" && parsedRepo != "" {
			return parsedOrg, parsedRepo, parsedCommit, nil
		}
	}

	return "", "", "", fmt.Errorf("could not parse repository info from URLs")
}

// parseGitHubURL extracts org, repo, and optional commit from a GitHub URL
func parseGitHubURL(url string) (org, repo, commitID string) {
	// Remove protocol prefix
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "git://")
	url = strings.TrimPrefix(url, "ssh://")

	// Remove .git suffix
	url = strings.TrimSuffix(url, ".git")

	// Split by /
	parts := strings.Split(url, "/")

	// Check if it's a GitHub URL
	if len(parts) < 3 || parts[0] != "github.com" {
		return "", "", ""
	}

	org = parts[1]
	repo = parts[2]

	// Check if there's a commit hash
	if len(parts) >= 5 && parts[3] == "commit" {
		commitID = parts[4]
	}

	return org, repo, commitID
}

// GetImageDigest returns the digest of an image
func GetImageDigest(ctx context.Context, imageRef string) (string, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "", fmt.Errorf("parse image reference: %w", err)
	}

	img, err := remote.Image(ref, remote.WithContext(ctx))
	if err != nil {
		return "", fmt.Errorf("fetch image: %w", err)
	}

	digest, err := img.Digest()
	if err != nil {
		return "", fmt.Errorf("get digest: %w", err)
	}

	return digest.String(), nil
}
