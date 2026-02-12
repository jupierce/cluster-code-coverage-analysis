package cluster

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/jupierce/cluster-code-coverage-analysis/pkg/log"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// DiscoverOptions contains options for cluster discovery
type DiscoverOptions struct {
	ClusterName      string
	Namespaces       []string // Empty means all namespaces
	MaxConcurrency   int      // Max concurrent image inspections
	SkipInspection   bool     // Skip image inspection (faster, but less info)
}

// Discoverer handles cluster discovery
type Discoverer struct {
	clientset    kubernetes.Interface
	logger       *log.Logger
	clusterDir   string
	opts         DiscoverOptions
	registryAuth *RegistryAuth
}

// NewDiscoverer creates a new discoverer
func NewDiscoverer(clientset kubernetes.Interface, logger *log.Logger, clusterDir string, opts DiscoverOptions, registryAuth *RegistryAuth) *Discoverer {
	if opts.MaxConcurrency <= 0 {
		opts.MaxConcurrency = 10
	}

	return &Discoverer{
		clientset:    clientset,
		logger:       logger,
		clusterDir:   clusterDir,
		opts:         opts,
		registryAuth: registryAuth,
	}
}

// Discover scans the cluster and builds a discovery plan
func (d *Discoverer) Discover(ctx context.Context) (*DiscoveryPlan, error) {
	d.logger.Progress("Starting cluster discovery for: %s", d.opts.ClusterName)

	plan := &DiscoveryPlan{
		ClusterName:  d.opts.ClusterName,
		DiscoveredAt: time.Now().Format(time.RFC3339),
		Images:       make(map[string]*ImageInfo),
		Repositories: make(map[string]*RepositoryInfo),
	}

	// Get namespaces to scan
	namespaces, err := d.getNamespaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("get namespaces: %w", err)
	}

	d.logger.Info("Scanning %d namespace(s)", len(namespaces))

	// Collect all pods
	allPods := []corev1.Pod{}
	for _, ns := range namespaces {
		d.logger.Debug("Listing pods in namespace: %s", ns)
		pods, err := d.clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			d.logger.Warning("Failed to list pods in namespace %s: %v", ns, err)
			continue
		}
		allPods = append(allPods, pods.Items...)
		d.logger.Debug("Found %d pods in namespace %s", len(pods.Items), ns)
	}

	plan.TotalPods = len(allPods)
	d.logger.Info("Found %d total pods", plan.TotalPods)

	// Extract unique images and build pod info
	uniqueImages := make(map[string]string) // imageID -> image name
	for _, pod := range allPods {
		podInfo := PodInfo{
			Name:       pod.Name,
			Namespace:  pod.Namespace,
			Containers: []ContainerInfo{},
		}

		for _, container := range pod.Spec.Containers {
			// Get image ID from status if available
			imageID := container.Image
			for _, status := range pod.Status.ContainerStatuses {
				if status.Name == container.Name && status.ImageID != "" {
					imageID = status.ImageID
					break
				}
			}

			containerInfo := ContainerInfo{
				Name:    container.Name,
				ImageID: imageID,
				Image:   container.Image,
			}

			podInfo.Containers = append(podInfo.Containers, containerInfo)
			uniqueImages[imageID] = container.Image
		}

		plan.Pods = append(plan.Pods, podInfo)
	}

	plan.TotalImages = len(uniqueImages)
	d.logger.Info("Found %d unique container images", plan.TotalImages)

	// Inspect images
	if !d.opts.SkipInspection {
		d.logger.Progress("Inspecting container images for coverage metadata...")
		if err := d.inspectImages(ctx, uniqueImages, plan); err != nil {
			d.logger.Warning("Image inspection had errors: %v", err)
		}
	}

	// Update pod info with coverage information
	d.updatePodCoverageInfo(plan)

	// Build repository information
	d.buildRepositoryInfo(plan)

	// Save discovery plan
	if err := plan.Save(d.clusterDir); err != nil {
		return nil, fmt.Errorf("save discovery plan: %w", err)
	}

	d.logger.Success("Discovery complete!")
	d.logger.Info("Total pods: %d", plan.TotalPods)
	d.logger.Info("Total images: %d", plan.TotalImages)
	d.logger.Info("Coverage-enabled images: %d", plan.CoverageImages)
	d.logger.Info("Repositories with source info: %d", len(plan.Repositories))
	d.logger.Info("Discovery plan saved to: %s", filepath.Join(d.clusterDir, "discovery-plan.json"))

	return plan, nil
}

// getNamespaces returns the list of namespaces to scan
func (d *Discoverer) getNamespaces(ctx context.Context) ([]string, error) {
	if len(d.opts.Namespaces) > 0 {
		return d.opts.Namespaces, nil
	}

	// Get all namespaces
	nsList, err := d.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	namespaces := make([]string, len(nsList.Items))
	for i, ns := range nsList.Items {
		namespaces[i] = ns.Name
	}

	return namespaces, nil
}

// inspectImages inspects container images concurrently
func (d *Discoverer) inspectImages(ctx context.Context, images map[string]string, plan *DiscoveryPlan) error {
	type imageTask struct {
		imageID   string
		imageName string
	}

	tasks := make(chan imageTask, len(images))
	for imageID, imageName := range images {
		tasks <- imageTask{imageID, imageName}
	}
	close(tasks)

	var wg sync.WaitGroup
	var mu sync.Mutex
	errorCount := 0

	// Worker pool
	for i := 0; i < d.opts.MaxConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for task := range tasks {
				d.logger.Trace("Inspecting image: %s", task.imageName)

				// Get remote options with auth
				var remoteOpts []remote.Option
				if d.registryAuth != nil {
					remoteOpts = d.registryAuth.GetRemoteOptions()
				}

				info, err := InspectImage(ctx, task.imageName, remoteOpts...)
				if err != nil {
					mu.Lock()
					errorCount++
					plan.Images[task.imageID] = &ImageInfo{
						ImageID:         task.imageID,
						ImageName:       task.imageName,
						InspectionError: err.Error(),
					}
					mu.Unlock()
					d.logger.Debug("Failed to inspect %s: %v", task.imageName, err)
					continue
				}

				info.ImageID = task.imageID
				info.UsedByContainers = 1 // Will be updated later

				mu.Lock()
				plan.Images[task.imageID] = info
				if info.HasCoverage {
					plan.CoverageImages++
					d.logger.Debug("✓ Coverage-enabled: %s (port %d)", task.imageName, info.CoveragePort)
				}
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	if errorCount > 0 {
		d.logger.Warning("Failed to inspect %d images", errorCount)
	}

	return nil
}

// updatePodCoverageInfo updates pod info with coverage information from images
func (d *Discoverer) updatePodCoverageInfo(plan *DiscoveryPlan) {
	for i := range plan.Pods {
		for j := range plan.Pods[i].Containers {
			container := &plan.Pods[i].Containers[j]
			if imageInfo, ok := plan.Images[container.ImageID]; ok {
				container.HasCoverage = imageInfo.HasCoverage
				container.CoveragePort = imageInfo.CoveragePort
				imageInfo.UsedByContainers++
			}
		}
	}
}

// buildRepositoryInfo builds repository information from images
func (d *Discoverer) buildRepositoryInfo(plan *DiscoveryPlan) {
	for imageID, imageInfo := range plan.Images {
		if imageInfo.BuildCommitURL == "" || imageInfo.BuildCommitID == "" {
			continue
		}

		org, repo, commitID, err := ParseRepositoryInfo(imageInfo.BuildCommitURL, imageInfo.SourceLocation)
		if err != nil {
			d.logger.Debug("Failed to parse repository info for %s: %v", imageID, err)
			continue
		}

		// Use commitID from parsing if available, otherwise use BuildCommitID
		if commitID == "" {
			commitID = imageInfo.BuildCommitID
		}

		repoKey := GetRepositoryKey(imageInfo.SourceLocation, commitID)
		imageInfo.RepositoryKey = repoKey

		if repoInfo, exists := plan.Repositories[repoKey]; exists {
			// Add image to existing repo
			repoInfo.ImageIDs = append(repoInfo.ImageIDs, imageID)
		} else {
			// Create new repository entry
			canonicalPath := filepath.Join("repos", "github.com", org, repo, commitID[:8])
			plan.Repositories[repoKey] = &RepositoryInfo{
				URL:           imageInfo.SourceLocation,
				CommitID:      commitID,
				Organization:  org,
				RepoName:      repo,
				CanonicalPath: canonicalPath,
				ImageIDs:      []string{imageID},
			}
		}
	}

	d.logger.Debug("Built repository info for %d repositories", len(plan.Repositories))
}
