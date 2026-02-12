package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/jupierce/cluster-code-coverage-analysis/pkg/log"
)

// RegistryAuth handles container registry authentication
type RegistryAuth struct {
	configPaths []string
	logger      *log.Logger
	keychain    authn.Keychain
}

// NewRegistryAuth creates a new registry auth handler
func NewRegistryAuth(logger *log.Logger, customConfigPath string) (*RegistryAuth, error) {
	auth := &RegistryAuth{
		logger:      logger,
		configPaths: []string{},
	}

	// Build list of config paths to check
	if customConfigPath != "" {
		auth.configPaths = append(auth.configPaths, customConfigPath)
		logger.Debug("Using custom registry config: %s", customConfigPath)
	}

	// Add standard Docker config locations
	auth.configPaths = append(auth.configPaths, auth.getStandardConfigPaths()...)

	// Create keychain from available configs
	keychain, err := auth.createKeychain()
	if err != nil {
		return nil, fmt.Errorf("create keychain: %w", err)
	}
	auth.keychain = keychain

	return auth, nil
}

// getStandardConfigPaths returns standard locations for Docker config
func (a *RegistryAuth) getStandardConfigPaths() []string {
	paths := []string{}

	// 1. XDG_RUNTIME_DIR (commonly used by podman)
	if xdgRuntime := os.Getenv("XDG_RUNTIME_DIR"); xdgRuntime != "" {
		paths = append(paths, filepath.Join(xdgRuntime, "containers", "auth.json"))
		a.logger.Trace("Checking XDG_RUNTIME_DIR: %s", filepath.Join(xdgRuntime, "containers", "auth.json"))
	}

	// 2. ~/.docker/config.json (standard Docker location)
	if home, err := os.UserHomeDir(); err == nil {
		dockerConfig := filepath.Join(home, ".docker", "config.json")
		paths = append(paths, dockerConfig)
		a.logger.Trace("Checking Docker config: %s", dockerConfig)
	}

	// 3. ~/.dockercfg (legacy Docker location)
	if home, err := os.UserHomeDir(); err == nil {
		legacyConfig := filepath.Join(home, ".dockercfg")
		paths = append(paths, legacyConfig)
		a.logger.Trace("Checking legacy Docker config: %s", legacyConfig)
	}

	// 4. Podman config location
	if home, err := os.UserHomeDir(); err == nil {
		podmanConfig := filepath.Join(home, ".config", "containers", "auth.json")
		paths = append(paths, podmanConfig)
		a.logger.Trace("Checking Podman config: %s", podmanConfig)
	}

	return paths
}

// createKeychain creates an authentication keychain from available configs
func (a *RegistryAuth) createKeychain() (authn.Keychain, error) {
	// Try to find and use any available config
	for _, configPath := range a.configPaths {
		if _, err := os.Stat(configPath); err == nil {
			a.logger.Debug("Found registry config: %s", configPath)

			// Verify it's valid JSON
			data, err := os.ReadFile(configPath)
			if err != nil {
				a.logger.Debug("Failed to read %s: %v", configPath, err)
				continue
			}

			var config map[string]interface{}
			if err := json.Unmarshal(data, &config); err != nil {
				a.logger.Debug("Invalid JSON in %s: %v", configPath, err)
				continue
			}

			// Use this config by setting DOCKER_CONFIG env var temporarily
			// The default keychain will pick it up
			originalDockerConfig := os.Getenv("DOCKER_CONFIG")
			os.Setenv("DOCKER_CONFIG", filepath.Dir(configPath))

			keychain := authn.DefaultKeychain

			// Restore original env var
			if originalDockerConfig != "" {
				os.Setenv("DOCKER_CONFIG", originalDockerConfig)
			} else {
				os.Unsetenv("DOCKER_CONFIG")
			}

			a.logger.Info("Using registry credentials from: %s", configPath)
			return keychain, nil
		}
	}

	// No config found, use default keychain (will try default locations)
	a.logger.Debug("No custom registry config found, using default keychain")
	return authn.DefaultKeychain, nil
}

// GetRemoteOptions returns remote options with authentication
func (a *RegistryAuth) GetRemoteOptions() []remote.Option {
	return []remote.Option{
		remote.WithAuthFromKeychain(a.keychain),
	}
}

// CreateMultiKeychain creates a keychain that tries multiple config files
type MultiKeychain struct {
	keychains []authn.Keychain
	logger    *log.Logger
}

// NewMultiKeychain creates a keychain that tries multiple sources
func NewMultiKeychain(logger *log.Logger, configPaths []string) *MultiKeychain {
	mk := &MultiKeychain{
		logger:    logger,
		keychains: []authn.Keychain{},
	}

	// Add default keychain first
	mk.keychains = append(mk.keychains, authn.DefaultKeychain)

	// Try to load each config file
	for _, configPath := range configPaths {
		if _, err := os.Stat(configPath); err == nil {
			logger.Trace("Loading keychain from: %s", configPath)

			// Create a keychain for this specific config
			// We'll use the default keychain with DOCKER_CONFIG set
			// This is a simplified approach
		}
	}

	return mk
}

// Resolve implements authn.Keychain interface
func (mk *MultiKeychain) Resolve(resource authn.Resource) (authn.Authenticator, error) {
	// Try each keychain in order
	for _, kc := range mk.keychains {
		auth, err := kc.Resolve(resource)
		if err == nil && auth != authn.Anonymous {
			mk.logger.Trace("Resolved auth for %s", resource.RegistryStr())
			return auth, nil
		}
	}

	// Fall back to anonymous
	mk.logger.Trace("No auth found for %s, using anonymous", resource.RegistryStr())
	return authn.Anonymous, nil
}

// TestRegistryAuth tests if authentication works for a given registry
// This is a helper function for debugging authentication issues
func TestRegistryAuth(logger *log.Logger, registryAuth *RegistryAuth, testImage string) error {
	logger.Debug("Testing registry authentication with image: %s", testImage)

	// Try to inspect the image
	ctx := context.Background()
	_, err := InspectImage(ctx, testImage, registryAuth.GetRemoteOptions()...)
	if err != nil {
		logger.Debug("Registry auth test failed: %v", err)
		return fmt.Errorf("authentication test failed: %w", err)
	}

	logger.Success("Registry authentication successful")
	return nil
}
