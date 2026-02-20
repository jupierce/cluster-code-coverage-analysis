package main

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/jupierce/cluster-code-coverage-analysis/pkg/log"
)

var (
	// Collection flag
	collectionName string
	verbosity      string
	maxConcurrency int

	// Cluster command
	clusterCmd = &cobra.Command{
		Use:   "cluster",
		Short: "Cluster-wide coverage operations",
		Long: `Perform coverage operations for a cluster.

Run the subcommands in this order:

  1. download      Download coverage data from S3.
  2. compile       Process coverage data into SQLite database.
  3. clone-sources Clone source repos for HTML annotation.
  4. render        Generate HTML reports from database.`,
	}
)

func init() {
	// Add cluster command to root
	rootCmd.AddCommand(clusterCmd)

	// Cluster-wide flags
	clusterCmd.PersistentFlags().StringVar(&collectionName, "collection", "", "Collection name (required, creates directory with this name)")
	clusterCmd.PersistentFlags().StringVar(&verbosity, "verbosity", "info", "Log verbosity (error, info, debug, trace)")
	clusterCmd.PersistentFlags().IntVar(&maxConcurrency, "max-concurrency", 8, "Maximum concurrent operations")
	clusterCmd.MarkPersistentFlagRequired("collection")
}

// createLogger creates a logger for cluster operations
func createLogger(collectionDir string) (*log.Logger, error) {
	// Parse verbosity level
	level, err := log.ParseLevel(verbosity)
	if err != nil {
		return nil, err
	}

	// Create log directory
	logDir := filepath.Join(collectionDir, "logs")
	logger, err := log.New(level, logDir)
	if err != nil {
		return nil, fmt.Errorf("create logger: %w", err)
	}

	return logger, nil
}
