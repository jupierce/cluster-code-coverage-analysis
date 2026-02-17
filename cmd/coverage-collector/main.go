package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "coverage-collector",
	Short: "Download Go code coverage from S3 and render HTML reports",
	Long: `coverage-collector downloads Go code coverage data from an S3 bucket
(uploaded by coverage-instrumented binaries) and renders interactive HTML
coverage reports.`,
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
