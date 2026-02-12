package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	coverageclient "github.com/jupierce/cluster-code-coverage-analysis/pkg/client"
)

var (
	// Global flags
	namespace      string
	outputDir      string
	coverageDir    string
	kubeconfigPath string

	// Collect command flags
	podName       string
	labelSelector string
	containerName string
	coveragePort  int
	testName      string
	sourceDir     string
	noPathRemap   bool
	timeout       int

	// Root command
	rootCmd = &cobra.Command{
		Use:   "coverage-collector",
		Short: "Collect Go code coverage from Kubernetes pods via HTTP",
		Long: `coverage-collector is a CLI tool for collecting Go code coverage
from running applications in Kubernetes pods. It uses HTTP port-forwarding
to retrieve coverage data without requiring GOCOVERDIR or volume mounts.`,
	}

	// Collect command
	collectCmd = &cobra.Command{
		Use:   "collect",
		Short: "Collect coverage from a pod and generate HTML report",
		Long: `Collect coverage data from a Kubernetes pod by port-forwarding to
the coverage server endpoint. You can specify a pod by name or use a label
selector to automatically discover the pod.`,
		Example: `  # Collect from pod by name
  coverage-collector collect --pod my-pod-12345 --test-name my-test

  # Collect using label selector
  coverage-collector collect --label app=my-app --test-name my-test

  # Collect with custom namespace and port
  coverage-collector collect --label app=my-app --namespace prod --port 9095 --test-name prod-test

  # Collect with custom kubeconfig
  coverage-collector collect --label app=my-app --kubeconfig ~/.kube/prod-config --test-name my-test

  # Collect and specify source directory for path remapping
  coverage-collector collect --label app=my-app --source-dir /path/to/project --test-name my-test`,
		RunE: runCollect,
	}
)

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "default", "Kubernetes namespace")
	rootCmd.PersistentFlags().StringVarP(&outputDir, "output-dir", "o", "./coverage-output", "Output directory for coverage data")
	rootCmd.PersistentFlags().StringVar(&kubeconfigPath, "kubeconfig", "", "Path to kubeconfig file (defaults to $KUBECONFIG or ~/.kube/config)")

	// Collect command flags
	collectCmd.Flags().StringVarP(&podName, "pod", "p", "", "Pod name (mutually exclusive with --label)")
	collectCmd.Flags().StringVarP(&labelSelector, "label", "l", "", "Label selector to find pod (mutually exclusive with --pod)")
	collectCmd.Flags().StringVarP(&containerName, "container", "c", "", "Container name (optional, auto-detected if not specified)")
	collectCmd.Flags().IntVar(&coveragePort, "port", 53700, "Coverage server starting port")
	collectCmd.Flags().StringVarP(&testName, "test-name", "t", "", "Test name for organizing coverage output (required)")
	collectCmd.Flags().StringVar(&sourceDir, "source-dir", "", "Source directory for path remapping (defaults to current directory)")
	collectCmd.Flags().BoolVar(&noPathRemap, "no-path-remap", false, "Disable automatic path remapping")
	collectCmd.Flags().IntVar(&timeout, "timeout", 60, "Timeout in seconds for operations")

	collectCmd.MarkFlagRequired("test-name")

	rootCmd.AddCommand(collectCmd)
}

func runCollect(cmd *cobra.Command, args []string) error {
	// Validate pod name and label selector are mutually exclusive
	if podName == "" && labelSelector == "" {
		return fmt.Errorf("either --pod or --label must be specified")
	}
	if podName != "" && labelSelector != "" {
		return fmt.Errorf("--pod and --label are mutually exclusive")
	}

	fmt.Printf("🚀 Starting coverage collection\n")
	fmt.Printf("   Namespace: %s\n", namespace)
	fmt.Printf("   Test name: %s\n", testName)
	fmt.Printf("   Output directory: %s\n", outputDir)
	fmt.Printf("   Coverage port: %d\n", coveragePort)
	if kubeconfigPath != "" {
		fmt.Printf("   Kubeconfig: %s\n", kubeconfigPath)
	}

	// Create coverage client
	client, err := coverageclient.NewClientWithKubeconfig(namespace, outputDir, kubeconfigPath)
	if err != nil {
		return fmt.Errorf("create coverage client: %w", err)
	}

	// Configure source directory
	if sourceDir != "" {
		client.SetSourceDirectory(sourceDir)
		fmt.Printf("   Source directory: %s\n", sourceDir)
	}

	// Configure path remapping
	if noPathRemap {
		client.SetPathRemapping(false)
		fmt.Printf("   Path remapping: disabled\n")
	} else {
		fmt.Printf("   Path remapping: enabled\n")
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	// Discover pod if using label selector
	if labelSelector != "" {
		fmt.Printf("\n🔍 Discovering pod with label selector: %s\n", labelSelector)
		discoveredPod, err := client.GetPodNameWithContext(ctx, labelSelector)
		if err != nil {
			return fmt.Errorf("discover pod: %w", err)
		}
		podName = discoveredPod
	}

	fmt.Printf("\n📊 Collecting coverage from pod: %s\n", podName)

	// Collect coverage
	if containerName != "" {
		err = client.CollectCoverageFromPodWithContainer(ctx, podName, containerName, testName, coveragePort)
	} else {
		err = client.CollectCoverageFromPod(ctx, podName, testName, coveragePort)
	}

	if err != nil {
		return fmt.Errorf("collect coverage: %w", err)
	}

	// Display pod metadata
	fmt.Println("\n📋 Pod Metadata:")
	metadataPath := filepath.Join(outputDir, testName, "metadata.json")
	if metadataData, err := os.ReadFile(metadataPath); err == nil {
		var metadata map[string]interface{}
		if err := json.Unmarshal(metadataData, &metadata); err == nil {
			fmt.Printf("   Pod Name: %v\n", metadata["pod_name"])
			fmt.Printf("   Namespace: %v\n", metadata["namespace"])
			fmt.Printf("   Coverage Port: %v\n", metadata["coverage_port"])
			if container, ok := metadata["container"].(map[string]interface{}); ok {
				fmt.Println("   Coverage Container:")
				fmt.Printf("     Name: %v\n", container["name"])
				fmt.Printf("     Image: %v\n", container["image"])
			}
			fmt.Printf("   Collected At: %v\n", metadata["collected_at"])
		}
	}

	// Process coverage reports (generate text report, filter, and create HTML)
	fmt.Println("\n📊 Processing coverage reports...")
	if err := client.ProcessCoverageReports(testName); err != nil {
		return fmt.Errorf("process coverage reports: %w", err)
	}

	// Success summary
	testDir := filepath.Join(outputDir, testName)
	fmt.Println("\n✅ Coverage collection complete!")
	fmt.Printf("📁 Coverage files saved in: %s\n", testDir)
	fmt.Println("\nGenerated files:")
	fmt.Printf("   • metadata.json - Pod and container information\n")
	fmt.Printf("   • coverage.out - Raw coverage report\n")
	fmt.Printf("   • coverage_filtered.out - Filtered coverage report\n")
	fmt.Printf("   • coverage.html - HTML coverage report\n")

	htmlPath := filepath.Join(testDir, "coverage.html")
	fmt.Printf("\n🌐 Open HTML report: file://%s\n", htmlPath)

	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
