package cluster

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/jupierce/cluster-code-coverage-analysis/pkg/log"
)

// CloneOptions contains options for cloning sources
type CloneOptions struct {
	MaxConcurrency int
	SkipExisting   bool
}

// Cloner handles repository cloning
type Cloner struct {
	logger     *log.Logger
	clusterDir string
	opts       CloneOptions
}

// NewCloner creates a new cloner
func NewCloner(logger *log.Logger, clusterDir string, opts CloneOptions) *Cloner {
	if opts.MaxConcurrency <= 0 {
		opts.MaxConcurrency = 5 // Conservative default for git operations
	}

	return &Cloner{
		logger:     logger,
		clusterDir: clusterDir,
		opts:       opts,
	}
}

// CloneSources clones all repositories from the discovery plan
func (c *Cloner) CloneSources(ctx context.Context, plan *DiscoveryPlan) (*CloneSummary, error) {
	c.logger.Progress("Cloning source repositories for cluster: %s", plan.ClusterName)
	c.logger.Info("Total repositories to clone: %d", len(plan.Repositories))

	summary := &CloneSummary{
		ClusterName:       plan.ClusterName,
		TotalRepositories: len(plan.Repositories),
		Repositories:      make([]*RepositoryInfo, 0, len(plan.Repositories)),
	}

	// Create tasks channel
	type cloneTask struct {
		key      string
		repoInfo *RepositoryInfo
	}

	tasks := make(chan cloneTask, len(plan.Repositories))
	for key, repoInfo := range plan.Repositories {
		tasks <- cloneTask{key, repoInfo}
	}
	close(tasks)

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Worker pool
	for i := 0; i < c.opts.MaxConcurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for task := range tasks {
				c.logger.Debug("[Worker %d] Cloning %s/%s @ %s",
					workerID, task.repoInfo.Organization, task.repoInfo.RepoName, task.repoInfo.CommitID[:8])

				err := c.cloneRepository(ctx, task.repoInfo)

				mu.Lock()
				if err != nil {
					task.repoInfo.CloneError = err.Error()
					summary.FailedClones++
					c.logger.Warning("Failed to clone %s/%s: %v",
						task.repoInfo.Organization, task.repoInfo.RepoName, err)
				} else {
					task.repoInfo.Cloned = true
					summary.SuccessfulClones++
					c.logger.Success("Cloned %s/%s @ %s",
						task.repoInfo.Organization, task.repoInfo.RepoName, task.repoInfo.CommitID[:8])
				}
				summary.Repositories = append(summary.Repositories, task.repoInfo)
				mu.Unlock()

				// Create symlinks for images
				if err == nil {
					c.createImageSymlinks(task.repoInfo)
				}
			}
		}(i)
	}

	wg.Wait()

	// Save summary
	if err := SaveCloneSummary(c.clusterDir, summary); err != nil {
		c.logger.Warning("Failed to save clone summary: %v", err)
	}

	c.logger.Success("Clone operation complete!")
	c.logger.Info("Successful clones: %d", summary.SuccessfulClones)
	c.logger.Info("Failed clones: %d", summary.FailedClones)

	return summary, nil
}

// cloneRepository clones a single repository
func (c *Cloner) cloneRepository(ctx context.Context, repoInfo *RepositoryInfo) error {
	// Build full path
	fullPath := filepath.Join(c.clusterDir, repoInfo.CanonicalPath)

	// Check if already exists
	if c.opts.SkipExisting {
		if _, err := os.Stat(fullPath); err == nil {
			c.logger.Debug("Repository already exists, skipping: %s", fullPath)
			return nil
		}
	}

	// Create parent directory
	parentDir := filepath.Dir(fullPath)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return fmt.Errorf("create parent directory: %w", err)
	}

	// Clone repository
	// We'll try a full clone since we need a specific commit
	c.logger.Trace("Executing: git clone %s %s", repoInfo.URL, fullPath)

	cmd := exec.CommandContext(ctx, "git", "clone", repoInfo.URL, fullPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone failed: %w (output: %s)", err, string(output))
	}

	// Checkout specific commit
	c.logger.Trace("Checking out commit: %s", repoInfo.CommitID)

	cmd = exec.CommandContext(ctx, "git", "-C", fullPath, "checkout", repoInfo.CommitID)
	output, err = cmd.CombinedOutput()
	if err != nil {
		// Try to fetch the commit if it's not available
		c.logger.Debug("Commit not found, trying to fetch: %s", repoInfo.CommitID)

		fetchCmd := exec.CommandContext(ctx, "git", "-C", fullPath, "fetch", "origin", repoInfo.CommitID)
		fetchOutput, fetchErr := fetchCmd.CombinedOutput()
		if fetchErr != nil {
			return fmt.Errorf("git fetch commit failed: %w (output: %s)", fetchErr, string(fetchOutput))
		}

		// Try checkout again
		cmd = exec.CommandContext(ctx, "git", "-C", fullPath, "checkout", repoInfo.CommitID)
		output, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("git checkout failed: %w (output: %s)", err, string(output))
		}
	}

	return nil
}

// createImageSymlinks creates symlinks from image directories to cloned sources
func (c *Cloner) createImageSymlinks(repoInfo *RepositoryInfo) {
	for _, imageID := range repoInfo.ImageIDs {
		// Create image directory
		imageDir := filepath.Join(c.clusterDir, "images", sanitizeImageID(imageID))
		if err := os.MkdirAll(imageDir, 0755); err != nil {
			c.logger.Warning("Failed to create image directory %s: %v", imageDir, err)
			continue
		}

		// Create symlink
		symlinkPath := filepath.Join(imageDir, "source")
		targetPath := filepath.Join("../..", repoInfo.CanonicalPath)

		// Remove existing symlink if present
		os.Remove(symlinkPath)

		if err := os.Symlink(targetPath, symlinkPath); err != nil {
			c.logger.Warning("Failed to create symlink for %s: %v", imageID, err)
			continue
		}

		c.logger.Trace("Created symlink: %s -> %s", symlinkPath, targetPath)
	}
}

// sanitizeImageID sanitizes an image ID for use as a directory name
func sanitizeImageID(imageID string) string {
	// Replace problematic characters
	sanitized := imageID
	sanitized = filepath.Base(sanitized) // Get last component after /
	// Further sanitization if needed
	return sanitized
}
