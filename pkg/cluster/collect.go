package cluster

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	coverageclient "github.com/jupierce/cluster-code-coverage-analysis/pkg/client"
	"github.com/jupierce/cluster-code-coverage-analysis/pkg/log"
	"k8s.io/client-go/rest"
)

// CollectOptions contains options for coverage collection
type CollectOptions struct {
	MaxConcurrency int
	ProcessReports bool // Generate HTML reports
	UseSources     bool // Use cloned sources for path remapping
}

// Collector handles coverage collection from pods
type Collector struct {
	logger      *log.Logger
	clusterDir  string
	restConfig  *rest.Config
	opts        CollectOptions
}

// NewCollector creates a new collector
func NewCollector(logger *log.Logger, clusterDir string, restConfig *rest.Config, opts CollectOptions) *Collector {
	if opts.MaxConcurrency <= 0 {
		opts.MaxConcurrency = 20
	}

	return &Collector{
		logger:     logger,
		clusterDir: clusterDir,
		restConfig: restConfig,
		opts:       opts,
	}
}

// CollectAll collects coverage from all pods in the discovery plan.
// It scans sequential ports on each pod to discover all coverage servers.
func (c *Collector) CollectAll(ctx context.Context, plan *DiscoveryPlan) (*CollectionSummary, error) {
	c.logger.Progress("Collecting coverage from cluster: %s", plan.ClusterName)

	// Filter pods with coverage
	coveragePods := c.filterCoveragePods(plan)
	c.logger.Info("Found %d pods with coverage-enabled containers", len(coveragePods))

	summary := &CollectionSummary{
		ClusterName: plan.ClusterName,
		TotalPods:   len(coveragePods),
		Results:     []CollectionResult{},
	}

	// Create coverage output directory
	coverageDir := filepath.Join(c.clusterDir, "coverage")
	if err := ensureDir(coverageDir); err != nil {
		return nil, fmt.Errorf("create coverage directory: %w", err)
	}

	// Create one task per pod (not per container)
	type collectTask struct {
		pod       PodInfo
		startPort int
	}

	tasks := make(chan collectTask, len(coveragePods))
	for _, pod := range coveragePods {
		// Determine starting port from the first coverage-enabled container
		startPort := 53700
		for _, container := range pod.Containers {
			if container.HasCoverage && container.CoveragePort > 0 {
				startPort = container.CoveragePort
				break
			}
		}
		tasks <- collectTask{pod, startPort}
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
				c.logger.Debug("[Worker %d] Scanning pod %s/%s starting at port %d",
					workerID, task.pod.Namespace, task.pod.Name, task.startPort)

				results := c.collectFromPod(ctx, task.pod, task.startPort, coverageDir)

				mu.Lock()
				for _, result := range results {
					summary.Results = append(summary.Results, result)
					if result.Success {
						summary.SuccessfulCollects++
					} else {
						summary.FailedCollects++
					}
				}
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()

	// Save summary
	if err := SaveCollectionSummary(c.clusterDir, summary); err != nil {
		c.logger.Warning("Failed to save collection summary: %v", err)
	}

	c.logger.Success("Collection complete!")
	c.logger.Info("Successful collections: %d", summary.SuccessfulCollects)
	c.logger.Info("Failed collections: %d", summary.FailedCollects)

	return summary, nil
}

// filterCoveragePods returns pods that have at least one coverage-enabled container
func (c *Collector) filterCoveragePods(plan *DiscoveryPlan) []PodInfo {
	var coveragePods []PodInfo

	for _, pod := range plan.Pods {
		hasCoverage := false
		for _, container := range pod.Containers {
			if container.HasCoverage {
				hasCoverage = true
				break
			}
		}

		if hasCoverage {
			coveragePods = append(coveragePods, pod)
		}
	}

	return coveragePods
}

// collectFromPod scans sequential ports on a pod to discover and collect
// from all coverage servers running in its containers.
func (c *Collector) collectFromPod(ctx context.Context, pod PodInfo, startPort int, coverageDir string) []CollectionResult {
	// Create coverage client using the collector's rest config
	client, err := coverageclient.NewClientWithRestConfig(pod.Namespace, coverageDir, c.restConfig)
	if err != nil {
		c.logger.Warning("Failed to create client for %s/%s: %v", pod.Namespace, pod.Name, err)
		return []CollectionResult{{
			PodName:   pod.Name,
			Namespace: pod.Namespace,
			Error:     fmt.Sprintf("create client: %v", err),
		}}
	}

	c.logger.Trace("Scanning pod %s/%s for coverage servers starting at port %d", pod.Namespace, pod.Name, startPort)

	// Scan and collect from all coverage servers on this pod
	serverResults, err := client.ScanAndCollectFromPod(ctx, pod.Name, startPort)
	if err != nil {
		c.logger.Debug("No coverage servers on pod %s/%s: %v", pod.Namespace, pod.Name, err)
		return []CollectionResult{{
			PodName:   pod.Name,
			Namespace: pod.Namespace,
			Error:     fmt.Sprintf("scan pod: %v", err),
		}}
	}

	var results []CollectionResult
	for _, sr := range serverResults {
		result := CollectionResult{
			PodName:    pod.Name,
			Namespace:  pod.Namespace,
			Container:  sr.BinaryName,
			BinaryName: sr.BinaryName,
			Pid:        sr.Pid,
			Port:       sr.Port,
			Success:    sr.Success,
			Error:      sr.Error,
			OutputPath: sr.OutputPath,
		}

		if sr.Success {
			c.logger.Success("Collected from %s/%s: %s (port %d, pid %s)",
				pod.Namespace, pod.Name, sr.BinaryName, sr.Port, sr.Pid)

			// Process reports if requested
			if c.opts.ProcessReports {
				c.logger.Trace("Processing coverage reports for %s", sr.TestName)
				if err := client.ProcessCoverageReports(sr.TestName); err != nil {
					c.logger.Warning("Failed to process reports for %s: %v", sr.TestName, err)
				}
			}
		}

		results = append(results, result)
	}

	return results
}

// getRepositoryInfo is a helper to get repository info from the plan
// This needs access to the plan, so we'll need to modify the approach
var planMutex sync.RWMutex
var globalPlan *DiscoveryPlan

func (c *Collector) getRepositoryInfo(repoKey string) (*RepositoryInfo, bool) {
	planMutex.RLock()
	defer planMutex.RUnlock()

	if globalPlan == nil {
		return nil, false
	}

	repoInfo, exists := globalPlan.Repositories[repoKey]
	return repoInfo, exists
}

// SetPlan sets the global plan for repository lookups
func SetPlan(plan *DiscoveryPlan) {
	planMutex.Lock()
	defer planMutex.Unlock()
	globalPlan = plan
}

// ensureDir ensures a directory exists
func ensureDir(dir string) error {
	return os.MkdirAll(dir, 0755)
}
