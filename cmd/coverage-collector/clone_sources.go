package main

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	_ "modernc.org/sqlite"
)

var (
	cloneSkipExisting bool

	cloneSourcesCmd = &cobra.Command{
		Use:   "clone-sources",
		Short: "Clone source repositories identified by image labels",
		Long: `Clone source repositories that were identified during the 'compile' step
by inspecting container image labels.

Each unique (source_repo, commit_id) pair from the image_sources table
is cloned into <cluster>/repos/<host>/<org>/<repo>/<commit-prefix>/.

Requires 'git' to be available in PATH.`,
		Example: `  # Clone all source repos
  coverage-collector cluster clone-sources --cluster my-cluster

  # Clone with higher concurrency
  coverage-collector cluster clone-sources --cluster my-cluster --max-concurrency 10`,
		RunE: runCloneSources,
	}
)

func init() {
	cloneSourcesCmd.Flags().BoolVar(&cloneSkipExisting, "skip-existing", true, "Skip repos that are already cloned")
	clusterCmd.AddCommand(cloneSourcesCmd)
}

type cloneTarget struct {
	SourceRepo string
	CommitID   string
	TargetDir  string
}

func runCloneSources(cmd *cobra.Command, args []string) error {
	clusterDir := clusterName

	// Open database read-only
	dbPath := filepath.Join(clusterDir, "coverage.db")
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("database not found at %s — run 'compile' first", dbPath)
	}

	db, err := sql.Open("sqlite", dbPath+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	// Query distinct (source_repo, commit_id) pairs
	rows, err := db.Query(`
		SELECT DISTINCT source_repo, commit_id FROM image_sources
		WHERE source_repo != '' AND error_msg = ''
	`)
	if err != nil {
		return fmt.Errorf("query image sources: %w", err)
	}
	defer rows.Close()

	reposDir := filepath.Join(clusterDir, "repos")

	var targets []cloneTarget
	skippedCount := 0
	for rows.Next() {
		var repo, commit string
		if err := rows.Scan(&repo, &commit); err != nil {
			return err
		}

		u, err := url.Parse(repo)
		if err != nil || u.Host == "" {
			fmt.Printf("  Skipping invalid URL: %s\n", repo)
			continue
		}

		commitPrefix := commit
		if len(commitPrefix) > 8 {
			commitPrefix = commitPrefix[:8]
		}
		if commitPrefix == "" {
			commitPrefix = "latest"
		}

		targetDir := filepath.Join(reposDir, u.Host, strings.TrimPrefix(u.Path, "/"), commitPrefix)

		if cloneSkipExisting {
			if _, err := os.Stat(filepath.Join(targetDir, "go.mod")); err == nil {
				skippedCount++
				continue
			}
		}

		targets = append(targets, cloneTarget{
			SourceRepo: repo,
			CommitID:   commit,
			TargetDir:  targetDir,
		})
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if len(targets) == 0 {
		if skippedCount > 0 {
			fmt.Printf("All %d repositories already cloned\n", skippedCount)
		} else {
			fmt.Println("No repositories to clone (run 'compile' first to inspect images)")
		}
		return nil
	}

	if skippedCount > 0 {
		fmt.Printf("Skipping %d already-cloned repositories\n", skippedCount)
	}
	fmt.Printf("Cloning %d repositories (concurrency: %d)...\n\n", len(targets), maxConcurrency)

	// Clone concurrently
	sem := make(chan struct{}, maxConcurrency)
	var mu sync.Mutex
	successCount := 0
	errorCount := 0
	var wg sync.WaitGroup

	for i, t := range targets {
		wg.Add(1)
		go func(idx int, target cloneTarget) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fmt.Printf("[%d/%d] Cloning %s → %s\n", idx+1, len(targets), target.SourceRepo, target.TargetDir)

			if err := cloneRepo(target); err != nil {
				fmt.Printf("  Error: %v\n", err)
				mu.Lock()
				errorCount++
				mu.Unlock()
				return
			}

			mu.Lock()
			successCount++
			mu.Unlock()
		}(i, t)
	}

	wg.Wait()

	fmt.Printf("\nCloned: %d, Errors: %d\n", successCount, errorCount)
	return nil
}

func cloneRepo(target cloneTarget) error {
	// Create parent directory
	if err := os.MkdirAll(filepath.Dir(target.TargetDir), 0755); err != nil {
		return fmt.Errorf("create parent dir: %w", err)
	}

	// Clone with depth 1
	cmd := exec.Command("git", "clone", "--depth", "1", target.SourceRepo, target.TargetDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git clone: %v (%s)", err, strings.TrimSpace(string(output)))
	}

	// Try to fetch and checkout specific commit if provided
	if target.CommitID != "" {
		fetchCmd := exec.Command("git", "-C", target.TargetDir, "fetch", "--depth", "1", "origin", target.CommitID)
		if output, err := fetchCmd.CombinedOutput(); err != nil {
			fmt.Printf("  Warning: could not fetch commit %s: %v (%s)\n",
				truncateCommit(target.CommitID), err, strings.TrimSpace(string(output)))
			fmt.Println("  Using default branch HEAD instead")
			return nil
		}

		checkoutCmd := exec.Command("git", "-C", target.TargetDir, "checkout", target.CommitID)
		if output, err := checkoutCmd.CombinedOutput(); err != nil {
			fmt.Printf("  Warning: could not checkout commit %s: %v (%s)\n",
				truncateCommit(target.CommitID), err, strings.TrimSpace(string(output)))
			fmt.Println("  Using default branch HEAD instead")
		}
	}

	return nil
}
