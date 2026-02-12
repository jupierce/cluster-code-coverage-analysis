package cluster

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// DiscoveryPlan contains the results of cluster discovery
type DiscoveryPlan struct {
	ClusterName   string                    `json:"cluster_name"`
	DiscoveredAt  string                    `json:"discovered_at"`
	TotalPods     int                       `json:"total_pods"`
	TotalImages   int                       `json:"total_images"`
	CoverageImages int                      `json:"coverage_images"`
	Pods          []PodInfo                 `json:"pods"`
	Images        map[string]*ImageInfo     `json:"images"`          // Key: imageID
	Repositories  map[string]*RepositoryInfo `json:"repositories"`    // Key: repo@commit
}

// PodInfo contains information about a pod
type PodInfo struct {
	Name       string          `json:"name"`
	Namespace  string          `json:"namespace"`
	Containers []ContainerInfo `json:"containers"`
}

// ContainerInfo contains information about a container
type ContainerInfo struct {
	Name         string `json:"name"`
	ImageID      string `json:"image_id"`
	Image        string `json:"image"`
	CoveragePort int    `json:"coverage_port,omitempty"`
	HasCoverage  bool   `json:"has_coverage"`
}

// ImageInfo contains information about a container image
type ImageInfo struct {
	ImageID          string            `json:"image_id"`
	ImageName        string            `json:"image_name"`
	Labels           map[string]string `json:"labels"`
	Env              map[string]string `json:"env"`
	HasCoverage      bool              `json:"has_coverage"`
	CoveragePort     int               `json:"coverage_port"`
	BuildCommitID    string            `json:"build_commit_id,omitempty"`
	BuildCommitURL   string            `json:"build_commit_url,omitempty"`
	SourceLocation   string            `json:"source_location,omitempty"`
	RepositoryKey    string            `json:"repository_key,omitempty"` // Links to Repositories map
	InspectionError  string            `json:"inspection_error,omitempty"`
	UsedByContainers int               `json:"used_by_containers"`
}

// RepositoryInfo contains information about a source repository
type RepositoryInfo struct {
	URL              string   `json:"url"`
	CommitID         string   `json:"commit_id"`
	Organization     string   `json:"organization"`
	RepoName         string   `json:"repo_name"`
	CanonicalPath    string   `json:"canonical_path"`    // Where to clone: repos/github.com/org/repo/commit
	Cloned           bool     `json:"cloned"`
	CloneError       string   `json:"clone_error,omitempty"`
	ImageIDs         []string `json:"image_ids"`         // All images using this repo@commit
}

// CloneSummary contains results of the clone-sources operation
type CloneSummary struct {
	ClusterName       string    `json:"cluster_name"`
	ClonedAt          string    `json:"cloned_at"`
	TotalRepositories int       `json:"total_repositories"`
	SuccessfulClones  int       `json:"successful_clones"`
	FailedClones      int       `json:"failed_clones"`
	Repositories      []*RepositoryInfo `json:"repositories"`
}

// CollectionSummary contains results of coverage collection
type CollectionSummary struct {
	ClusterName        string    `json:"cluster_name"`
	CollectedAt        string    `json:"collected_at"`
	TotalPods          int       `json:"total_pods"`
	SuccessfulCollects int       `json:"successful_collects"`
	FailedCollects     int       `json:"failed_collects"`
	Results            []CollectionResult `json:"results"`
}

// CollectionResult contains the result of coverage collection from one coverage server
type CollectionResult struct {
	PodName    string `json:"pod_name"`
	Namespace  string `json:"namespace"`
	Container  string `json:"container"`
	BinaryName string `json:"binary_name,omitempty"`
	Pid        string `json:"pid,omitempty"`
	Port       int    `json:"port,omitempty"`
	Success    bool   `json:"success"`
	Error      string `json:"error,omitempty"`
	OutputPath string `json:"output_path,omitempty"`
}

// SaveDiscoveryPlan saves the discovery plan to disk
func (p *DiscoveryPlan) Save(clusterDir string) error {
	planPath := filepath.Join(clusterDir, "discovery-plan.json")
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal plan: %w", err)
	}

	if err := os.WriteFile(planPath, data, 0644); err != nil {
		return fmt.Errorf("write plan file: %w", err)
	}

	return nil
}

// LoadDiscoveryPlan loads a discovery plan from disk
func LoadDiscoveryPlan(clusterDir string) (*DiscoveryPlan, error) {
	planPath := filepath.Join(clusterDir, "discovery-plan.json")
	data, err := os.ReadFile(planPath)
	if err != nil {
		return nil, fmt.Errorf("read plan file: %w", err)
	}

	var plan DiscoveryPlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil, fmt.Errorf("unmarshal plan: %w", err)
	}

	return &plan, nil
}

// SaveCloneSummary saves the clone summary to disk
func SaveCloneSummary(clusterDir string, summary *CloneSummary) error {
	summaryPath := filepath.Join(clusterDir, "clone-summary.json")
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal summary: %w", err)
	}

	if err := os.WriteFile(summaryPath, data, 0644); err != nil {
		return fmt.Errorf("write summary file: %w", err)
	}

	return nil
}

// SaveCollectionSummary saves the collection summary to disk
func SaveCollectionSummary(clusterDir string, summary *CollectionSummary) error {
	summaryPath := filepath.Join(clusterDir, fmt.Sprintf("collection-summary-%s.json", time.Now().Format("20060102-150405")))
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal summary: %w", err)
	}

	if err := os.WriteFile(summaryPath, data, 0644); err != nil {
		return fmt.Errorf("write summary file: %w", err)
	}

	return nil
}

// GetRepositoryKey generates a unique key for a repository
func GetRepositoryKey(url, commitID string) string {
	return fmt.Sprintf("%s@%s", url, commitID)
}
