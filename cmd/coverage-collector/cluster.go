package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/jupierce/cluster-code-coverage-analysis/pkg/cluster"
	"github.com/jupierce/cluster-code-coverage-analysis/pkg/log"
)

var (
	// Cluster command flags
	clusterName       string
	verbosity         string
	maxConcurrency    int
	namespaces        []string
	skipInspection    bool
	skipExisting      bool
	processReports    bool
	useSources        bool
	registryConfigPath string

	// Cluster command
	clusterCmd = &cobra.Command{
		Use:   "cluster",
		Short: "Cluster-wide coverage operations",
		Long: `Perform coverage operations across an entire cluster.

Run the subcommands in this order:

  1. discover      Scan the cluster for coverage-enabled pods and images.
                   Produces a discovery plan (discovery-plan.json).
  2. clone-sources Clone the source repositories identified by discovery.
                   Uses the exact commits recorded in the discovery plan.
  3. collect       Connect to every discovered pod and retrieve coverage data.
  4. render        Merge per-pod coverage by owner, generate HTML reports,
                   and build an interactive index.`,
	}

	// Discover subcommand
	discoverCmd = &cobra.Command{
		Use:   "discover",
		Short: "Discover coverage-enabled images and pods in the cluster",
		Long: `Scan the cluster for all pods and identify which containers have coverage enabled.
This creates a discovery plan that can be used by subsequent commands.`,
		Example: `  # Discover all coverage-enabled pods in cluster
  coverage-collector cluster discover --cluster prod

  # Discover in specific namespaces
  coverage-collector cluster discover --cluster prod --namespaces openshift-monitoring,openshift-operators

  # With detailed logging
  coverage-collector cluster discover --cluster prod --verbosity debug`,
		RunE: runDiscover,
	}

	// Clone sources subcommand
	cloneSourcesCmd = &cobra.Command{
		Use:   "clone-sources",
		Short: "Clone source repositories for coverage-enabled images",
		Long: `Clone source repositories based on the discovery plan.
This downloads the exact commit used to build each coverage-enabled image.`,
		Example: `  # Clone sources for discovered images
  coverage-collector cluster clone-sources --cluster prod

  # Skip already cloned repositories
  coverage-collector cluster clone-sources --cluster prod --skip-existing

  # Use more concurrent clones
  coverage-collector cluster clone-sources --cluster prod --max-concurrency 10`,
		RunE: runCloneSources,
	}

	// Collect all subcommand
	collectAllCmd = &cobra.Command{
		Use:   "collect",
		Short: "Collect coverage from all discovered pods",
		Long: `Collect coverage data from all pods identified in the discovery plan.
This attempts to connect to each coverage-enabled container and retrieve coverage data.`,
		Example: `  # Collect coverage from all pods
  coverage-collector cluster collect --cluster prod

  # Collect and process reports
  coverage-collector cluster collect --cluster prod --process-reports

  # Use cloned sources for path remapping
  coverage-collector cluster collect --cluster prod --use-sources`,
		RunE: runCollectAll,
	}
)

func init() {
	// Add cluster command to root
	rootCmd.AddCommand(clusterCmd)

	// Cluster-wide flags
	clusterCmd.PersistentFlags().StringVar(&clusterName, "cluster", "", "Cluster name (required, creates directory with this name)")
	clusterCmd.PersistentFlags().StringVar(&verbosity, "verbosity", "info", "Log verbosity (error, info, debug, trace)")
	clusterCmd.MarkPersistentFlagRequired("cluster")

	// Discover flags
	discoverCmd.Flags().IntVar(&maxConcurrency, "max-concurrency", 10, "Maximum concurrent image inspections")
	discoverCmd.Flags().StringSliceVar(&namespaces, "namespaces", []string{}, "Namespaces to scan (empty means all)")
	discoverCmd.Flags().BoolVar(&skipInspection, "skip-inspection", false, "Skip image inspection (faster but less info)")
	discoverCmd.Flags().StringVar(&registryConfigPath, "registry-config", "", "Path to registry credentials JSON (uses standard locations if not specified)")

	// Clone sources flags
	cloneSourcesCmd.Flags().IntVar(&maxConcurrency, "max-concurrency", 5, "Maximum concurrent git clones")
	cloneSourcesCmd.Flags().BoolVar(&skipExisting, "skip-existing", true, "Skip already cloned repositories")

	// Collect all flags
	collectAllCmd.Flags().IntVar(&maxConcurrency, "max-concurrency", 5, "Maximum concurrent coverage collections")
	collectAllCmd.Flags().BoolVar(&processReports, "process-reports", false, "Generate HTML reports for each collection")
	collectAllCmd.Flags().BoolVar(&useSources, "use-sources", true, "Use cloned sources for path remapping")

	// Add subcommands
	clusterCmd.AddCommand(discoverCmd)
	clusterCmd.AddCommand(cloneSourcesCmd)
	clusterCmd.AddCommand(collectAllCmd)
}

// createLogger creates a logger for cluster operations
func createLogger(clusterDir string) (*log.Logger, error) {
	// Parse verbosity level
	level, err := log.ParseLevel(verbosity)
	if err != nil {
		return nil, err
	}

	// Create log directory
	logDir := filepath.Join(clusterDir, "logs")
	logger, err := log.New(level, logDir)
	if err != nil {
		return nil, fmt.Errorf("create logger: %w", err)
	}

	return logger, nil
}

// createKubeClient creates a Kubernetes client
func createKubeClient() (kubernetes.Interface, *rest.Config, error) {
	// Load kubeconfig
	kubeconfig := kubeconfigPath
	if kubeconfig == "" {
		kubeconfig = os.Getenv("KUBECONFIG")
	}
	if kubeconfig == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, nil, fmt.Errorf("get home dir: %w", err)
		}
		kubeconfig = filepath.Join(home, ".kube", "config")
	}

	// Build config from kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		// Try in-cluster config
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, nil, fmt.Errorf("build kubernetes config: %w", err)
		}
	}

	// Create clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("create kubernetes client: %w", err)
	}

	return clientset, config, nil
}

func runDiscover(cmd *cobra.Command, args []string) error {
	// Create cluster directory
	clusterDir := clusterName
	if err := os.MkdirAll(clusterDir, 0755); err != nil {
		return fmt.Errorf("create cluster directory: %w", err)
	}

	// Create logger
	logger, err := createLogger(clusterDir)
	if err != nil {
		return err
	}
	defer logger.Close()

	logger.Info("Starting cluster discovery")
	logger.Info("Cluster: %s", clusterName)
	logger.Info("Cluster directory: %s", clusterDir)

	// Create Kubernetes client
	clientset, _, err := createKubeClient()
	if err != nil {
		return fmt.Errorf("create kubernetes client: %w", err)
	}

	// Create registry auth
	var registryAuth *cluster.RegistryAuth
	if !skipInspection {
		registryAuth, err = cluster.NewRegistryAuth(logger, registryConfigPath)
		if err != nil {
			logger.Warning("Failed to setup registry auth: %v", err)
			logger.Warning("Image inspection may fail for private registries")
		}
	}

	// Create discoverer
	discoverer := cluster.NewDiscoverer(clientset, logger, clusterDir, cluster.DiscoverOptions{
		ClusterName:    clusterName,
		Namespaces:     namespaces,
		MaxConcurrency: maxConcurrency,
		SkipInspection: skipInspection,
	}, registryAuth)

	// Run discovery
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	plan, err := discoverer.Discover(ctx)
	if err != nil {
		logger.Error("Discovery failed: %v", err)
		return err
	}

	// Print summary
	fmt.Println()
	fmt.Println("Discovery Summary")
	fmt.Println("=================")
	fmt.Printf("Total pods: %d\n", plan.TotalPods)
	fmt.Printf("Unique images: %d\n", plan.TotalImages)
	fmt.Printf("Coverage-enabled images: %d\n", plan.CoverageImages)
	fmt.Printf("Repositories with source info: %d\n", len(plan.Repositories))
	fmt.Println()
	fmt.Printf("📁 Discovery plan saved to: %s/discovery-plan.json\n", clusterDir)

	return nil
}

func runCloneSources(cmd *cobra.Command, args []string) error {
	clusterDir := clusterName

	// Create logger
	logger, err := createLogger(clusterDir)
	if err != nil {
		return err
	}
	defer logger.Close()

	logger.Info("Cloning source repositories for cluster: %s", clusterName)

	// Load discovery plan
	plan, err := cluster.LoadDiscoveryPlan(clusterDir)
	if err != nil {
		return fmt.Errorf("load discovery plan: %w (run 'discover' first)", err)
	}

	// Create cloner
	cloner := cluster.NewCloner(logger, clusterDir, cluster.CloneOptions{
		MaxConcurrency: maxConcurrency,
		SkipExisting:   skipExisting,
	})

	// Run cloning
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()

	summary, err := cloner.CloneSources(ctx, plan)
	if err != nil {
		logger.Error("Clone failed: %v", err)
		return err
	}

	// Print summary
	fmt.Println()
	fmt.Println("Clone Summary")
	fmt.Println("=============")
	fmt.Printf("Total repositories: %d\n", summary.TotalRepositories)
	fmt.Printf("Successful clones: %d\n", summary.SuccessfulClones)
	fmt.Printf("Failed clones: %d\n", summary.FailedClones)
	fmt.Println()
	fmt.Printf("📁 Clone summary saved to: %s/clone-summary.json\n", clusterDir)

	return nil
}

func runCollectAll(cmd *cobra.Command, args []string) error {
	clusterDir := clusterName

	// Create logger
	logger, err := createLogger(clusterDir)
	if err != nil {
		return err
	}
	defer logger.Close()

	logger.Info("Collecting coverage from cluster: %s", clusterName)

	// Load discovery plan
	plan, err := cluster.LoadDiscoveryPlan(clusterDir)
	if err != nil {
		return fmt.Errorf("load discovery plan: %w (run 'discover' first)", err)
	}

	// Set global plan for repository lookups
	cluster.SetPlan(plan)

	// Create Kubernetes client
	_, restConfig, err := createKubeClient()
	if err != nil {
		return fmt.Errorf("create kubernetes client: %w", err)
	}

	// Create collector
	collector := cluster.NewCollector(logger, clusterDir, restConfig, cluster.CollectOptions{
		MaxConcurrency: maxConcurrency,
		ProcessReports: processReports,
		UseSources:     useSources,
	})

	// Run collection
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()

	summary, err := collector.CollectAll(ctx, plan)
	if err != nil {
		logger.Error("Collection failed: %v", err)
		return err
	}

	// Print summary
	fmt.Println()
	fmt.Println("Collection Summary")
	fmt.Println("==================")
	fmt.Printf("Total pods: %d\n", summary.TotalPods)
	fmt.Printf("Successful collections: %d\n", summary.SuccessfulCollects)
	fmt.Printf("Failed collections: %d\n", summary.FailedCollects)
	fmt.Println()
	fmt.Printf("📁 Coverage data saved to: %s/coverage/\n", clusterDir)

	return nil
}
