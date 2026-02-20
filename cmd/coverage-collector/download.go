package main

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

var (
	s3Bucket      string
	s3Profile     string
	s3Region      string
	s3Prefix      string
	skipExisting  bool

	downloadCmd = &cobra.Command{
		Use:   "download",
		Short: "Download coverage data from S3",
		Long: `Download coverage data (covmeta and covcounters files) from an S3 bucket
and organize it into the local directory structure expected by the render command.

Generates metadata.json for each coverage entry from S3 path components.
The coverage producer (running in the kubelet) uploads coverage data to S3
in a structured path layout. This command downloads that data and prepares
it for rendering.`,
		Example: `  # Download coverage data
  coverage-collector cluster download --collection my-collection \
    --bucket art-ocp-code-coverage \
    --prefix openshift-ci/coverage \
    --profile saml \
    --region us-east-1

  # Skip already-downloaded entries
  coverage-collector cluster download --collection my-collection \
    --bucket art-ocp-code-coverage \
    --prefix openshift-ci/coverage \
    --skip-existing`,
		RunE: runDownload,
	}
)

func init() {
	downloadCmd.Flags().StringVar(&s3Bucket, "bucket", "", "S3 bucket name (required)")
	downloadCmd.Flags().StringVar(&s3Profile, "profile", "", "AWS CLI profile")
	downloadCmd.Flags().StringVar(&s3Region, "region", "", "AWS region")
	downloadCmd.Flags().StringVar(&s3Prefix, "prefix", "", "S3 path prefix (required)")

	downloadCmd.Flags().BoolVar(&skipExisting, "skip-existing", false, "Skip entries that already have local coverage data")
	downloadCmd.MarkFlagRequired("bucket")
	downloadCmd.MarkFlagRequired("prefix")
	clusterCmd.AddCommand(downloadCmd)
}

// ---------------------------------------------------------------------------
// S3 types
// ---------------------------------------------------------------------------

type s3Object struct {
	Key          string `json:"Key"`
	LastModified string `json:"LastModified"`
	Size         int64  `json:"Size"`
}

type s3ListResponse struct {
	Contents            []s3Object `json:"Contents"`
	IsTruncated         bool       `json:"IsTruncated"`
	NextContinuationToken string   `json:"NextContinuationToken"`
}

// ---------------------------------------------------------------------------
// Coverage entry parsed from S3 paths
// ---------------------------------------------------------------------------

type coverageEntry struct {
	Hostname        string
	Namespace       string // empty for host processes
	PodName         string // empty for host processes
	ContainerName   string // empty for host processes
	DiscoveryTime   string // "20060102T150405Z" format
	SanitizedImage  string // empty for host processes
	SanitizedBinary string
	IsHost          bool

	// Files to download (selected after counter dedup)
	Files []s3Object
}

// groupKey returns a deduplication key that excludes discoveryTime,
// so multiple discoveries of the same source collapse to one entry.
func (e *coverageEntry) groupKey() string {
	if e.IsHost {
		return fmt.Sprintf("%s/_host_/%s", e.Hostname, e.SanitizedBinary)
	}
	return fmt.Sprintf("%s/%s/%s/%s/%s",
		e.Hostname, e.Namespace, e.PodName, e.ContainerName, e.SanitizedBinary)
}

// localDirName returns the name for the local coverage subdirectory.
func (e *coverageEntry) localDirName() string {
	var name string
	if e.IsHost {
		name = fmt.Sprintf("%s-%s", e.Hostname, e.SanitizedBinary)
	} else {
		name = fmt.Sprintf("%s-%s-%s-%s-%s",
			e.Hostname, e.Namespace, e.PodName, e.ContainerName, e.SanitizedBinary)
	}
	if len(name) > 200 {
		hash := fmt.Sprintf("%x", md5.Sum([]byte(name)))
		name = name[:192] + "-" + hash[:7]
	}
	return name
}

// ---------------------------------------------------------------------------
// Main download logic
// ---------------------------------------------------------------------------

func runDownload(cmd *cobra.Command, args []string) error {
	// Check AWS CLI is available
	if _, err := exec.LookPath("aws"); err != nil {
		return fmt.Errorf("aws CLI not found in PATH. Install it from https://aws.amazon.com/cli/")
	}

	collectionDir := collectionName
	coverageDir := filepath.Join(collectionDir, "coverage")
	if err := os.MkdirAll(coverageDir, 0755); err != nil {
		return fmt.Errorf("create coverage directory: %w", err)
	}

	fmt.Printf("Downloading coverage data from s3://%s/%s/\n", s3Bucket, s3Prefix)
	fmt.Printf("Collection directory: %s\n\n", collectionDir)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Step 1: List all S3 objects under the prefix
	fmt.Println("Listing S3 objects...")
	objects, err := listS3Objects(ctx)
	if err != nil {
		return fmt.Errorf("list S3 objects: %w", err)
	}

	// Filter to coverage data files only
	var covObjects []s3Object
	for _, obj := range objects {
		basename := filepath.Base(obj.Key)
		if strings.HasPrefix(basename, "covmeta.") || strings.HasPrefix(basename, "covcounters.") || basename == "info.json" {
			covObjects = append(covObjects, obj)
		}
	}
	fmt.Printf("Found %d coverage files (%d total objects)\n", len(covObjects), len(objects))

	if len(covObjects) == 0 {
		fmt.Println("No coverage data found.")
		return nil
	}

	// Step 2: Parse S3 paths into coverage entries grouped by directory
	dirEntries, err := parseS3Entries(covObjects)
	if err != nil {
		return fmt.Errorf("parse S3 entries: %w", err)
	}

	// Step 3: Deduplicate by discovery time (keep latest per source)
	entries := deduplicateEntries(dirEntries)
	fmt.Printf("Found %d unique coverage entries (after deduplication)\n", len(entries))

	// Step 4: Select counter files (pick latest toggle suffix)
	for i := range entries {
		selectCounterFiles(&entries[i])
	}

	// Count stats
	hostCount := 0
	podCount := 0
	for _, e := range entries {
		if e.IsHost {
			hostCount++
		} else {
			podCount++
		}
	}

	hostnames := make(map[string]struct{})
	for _, e := range entries {
		hostnames[e.Hostname] = struct{}{}
	}

	fmt.Printf("  Hostnames: %d\n", len(hostnames))
	fmt.Printf("  Pod entries: %d\n", podCount)
	fmt.Printf("  Host entries: %d\n\n", hostCount)

	// Step 5: Download files concurrently
	fmt.Println("Downloading coverage files...")
	var (
		downloadedFiles int
		skippedEntries  int
		errorCount      int
		mu              sync.Mutex
		sem             = make(chan struct{}, maxConcurrency)
		wg              sync.WaitGroup
	)

	for i, entry := range entries {
		localDir := filepath.Join(coverageDir, entry.localDirName())

		// Check if entry already exists locally
		if skipExisting && isEntryComplete(localDir) {
			mu.Lock()
			skippedEntries++
			mu.Unlock()
			continue
		}

		if err := os.MkdirAll(localDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "  Error creating directory %s: %v\n", localDir, err)
			mu.Lock()
			errorCount++
			mu.Unlock()
			continue
		}

		wg.Add(1)
		sem <- struct{}{} // acquire semaphore
		go func(idx int, e coverageEntry, dir string) {
			defer wg.Done()
			defer func() { <-sem }() // release semaphore

			downloaded := 0
			for _, obj := range e.Files {
				filename := filepath.Base(obj.Key)
				localPath := filepath.Join(dir, filename)

				if err := downloadS3File(ctx, obj.Key, localPath); err != nil {
					fmt.Fprintf(os.Stderr, "  Error downloading %s: %v\n", obj.Key, err)
					mu.Lock()
					errorCount++
					mu.Unlock()
					continue
				}
				downloaded++
			}

			// Generate metadata.json
			metadataPath := filepath.Join(dir, "metadata.json")
			if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
				if err := generateMetadata(e, metadataPath); err != nil {
					fmt.Fprintf(os.Stderr, "  Error generating metadata for %s: %v\n", e.localDirName(), err)
					mu.Lock()
					errorCount++
					mu.Unlock()
				}
			}

			mu.Lock()
			downloadedFiles += downloaded
			mu.Unlock()

			fmt.Printf("  [%d/%d] %s (%d files)\n", idx+1, len(entries), e.localDirName(), downloaded)
		}(i, entry, localDir)
	}
	wg.Wait()

	// Summary
	fmt.Printf("\nDownload Summary\n")
	fmt.Printf("================\n")
	fmt.Printf("Hostnames: %d\n", len(hostnames))
	fmt.Printf("Pod entries: %d\n", podCount)
	fmt.Printf("Host entries: %d\n", hostCount)
	fmt.Printf("Downloaded: %d files\n", downloadedFiles)
	if skippedEntries > 0 {
		fmt.Printf("Skipped: %d (already present)\n", skippedEntries)
	}
	if errorCount > 0 {
		fmt.Printf("Errors: %d\n", errorCount)
	}
	fmt.Printf("\nCoverage data saved to: %s/coverage/\n", collectionDir)

	return nil
}

// ---------------------------------------------------------------------------
// S3 listing
// ---------------------------------------------------------------------------

func buildAWSArgs() []string {
	var args []string
	if s3Profile != "" {
		args = append(args, "--profile", s3Profile)
	}
	if s3Region != "" {
		args = append(args, "--region", s3Region)
	}
	return args
}

func listS3Objects(ctx context.Context) ([]s3Object, error) {
	var allObjects []s3Object
	var continuationToken string

	prefix := strings.TrimRight(s3Prefix, "/") + "/"

	for {
		args := []string{"s3api", "list-objects-v2",
			"--bucket", s3Bucket,
			"--prefix", prefix,
			"--output", "json",
		}
		args = append(args, buildAWSArgs()...)
		if continuationToken != "" {
			args = append(args, "--continuation-token", continuationToken)
		}

		cmd := exec.CommandContext(ctx, "aws", args...)
		output, err := cmd.Output()
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				return nil, fmt.Errorf("aws s3api list-objects-v2 failed: %s", string(exitErr.Stderr))
			}
			return nil, fmt.Errorf("aws s3api list-objects-v2 failed: %w", err)
		}

		var resp s3ListResponse
		if err := json.Unmarshal(output, &resp); err != nil {
			return nil, fmt.Errorf("parse S3 listing response: %w", err)
		}

		allObjects = append(allObjects, resp.Contents...)
		fmt.Printf("  Listed %d objects so far...\r", len(allObjects))

		if !resp.IsTruncated {
			break
		}
		continuationToken = resp.NextContinuationToken
	}

	fmt.Printf("  Listed %d objects total.     \n", len(allObjects))
	return allObjects, nil
}

// ---------------------------------------------------------------------------
// S3 path parsing
// ---------------------------------------------------------------------------

// parseS3Entries groups S3 objects by their directory and parses path components.
func parseS3Entries(objects []s3Object) ([]coverageEntry, error) {
	prefix := strings.TrimRight(s3Prefix, "/") + "/"

	// Group objects by their directory (everything before the filename)
	type dirInfo struct {
		entry coverageEntry
		files []s3Object
	}
	dirs := make(map[string]*dirInfo)

	for _, obj := range objects {
		relPath := strings.TrimPrefix(obj.Key, prefix)
		parts := strings.Split(relPath, "/")
		if len(parts) < 2 {
			continue // need at least dir/filename
		}

		filename := parts[len(parts)-1]
		dirParts := parts[:len(parts)-1]

		// Skip if not a coverage file
		if !strings.HasPrefix(filename, "covmeta.") && !strings.HasPrefix(filename, "covcounters.") && filename != "info.json" {
			continue
		}

		dirKey := strings.Join(dirParts, "/")

		if _, exists := dirs[dirKey]; !exists {
			entry, err := parseDirParts(dirParts)
			if err != nil {
				continue // skip unparseable paths
			}
			dirs[dirKey] = &dirInfo{entry: *entry}
		}
		dirs[dirKey].files = append(dirs[dirKey].files, obj)
	}

	var entries []coverageEntry
	for _, di := range dirs {
		di.entry.Files = di.files
		entries = append(entries, di.entry)
	}

	return entries, nil
}

// parseDirParts parses the directory segments after the prefix.
func parseDirParts(parts []string) (*coverageEntry, error) {
	if len(parts) < 4 {
		return nil, fmt.Errorf("path too short: %d segments", len(parts))
	}

	hostname := parts[0]

	// Host process: hostname/_host_/discoveryTime/sanitizedBinary
	if parts[1] == "_host_" {
		if len(parts) != 4 {
			return nil, fmt.Errorf("unexpected host path depth: %d segments", len(parts))
		}
		return &coverageEntry{
			Hostname:        hostname,
			DiscoveryTime:   parts[2],
			SanitizedBinary: parts[3],
			IsHost:          true,
		}, nil
	}

	// Pod container: hostname/namespace/podName/containerName/discoveryTime/sanitizedImage/sanitizedBinary
	if len(parts) != 7 {
		return nil, fmt.Errorf("unexpected pod path depth: %d segments", len(parts))
	}
	return &coverageEntry{
		Hostname:        hostname,
		Namespace:       parts[1],
		PodName:         parts[2],
		ContainerName:   parts[3],
		DiscoveryTime:   parts[4],
		SanitizedImage:  parts[5],
		SanitizedBinary: parts[6],
		IsHost:          false,
	}, nil
}

// ---------------------------------------------------------------------------
// Deduplication: keep only the latest discoveryTime per source
// ---------------------------------------------------------------------------

func deduplicateEntries(entries []coverageEntry) []coverageEntry {
	groups := make(map[string][]coverageEntry)
	for _, e := range entries {
		key := e.groupKey()
		groups[key] = append(groups[key], e)
	}

	var result []coverageEntry
	for _, group := range groups {
		// Sort by discoveryTime descending, pick latest
		sort.Slice(group, func(i, j int) bool {
			return group[i].DiscoveryTime > group[j].DiscoveryTime
		})
		result = append(result, group[0])
	}

	// Sort result for deterministic output
	sort.Slice(result, func(i, j int) bool {
		return result[i].localDirName() < result[j].localDirName()
	})

	return result
}

// ---------------------------------------------------------------------------
// Counter file selection: pick the latest toggle suffix (.1 or .2)
// ---------------------------------------------------------------------------

func selectCounterFiles(entry *coverageEntry) {
	var metaFiles []s3Object
	var otherFiles []s3Object // non-coverage files like info.json
	var counter1Files []s3Object
	var counter2Files []s3Object
	var counter1Latest time.Time
	var counter2Latest time.Time

	for _, f := range entry.Files {
		basename := filepath.Base(f.Key)
		if strings.HasPrefix(basename, "covmeta.") {
			metaFiles = append(metaFiles, f)
			continue
		}
		if basename == "info.json" {
			otherFiles = append(otherFiles, f)
			continue
		}
		if strings.HasPrefix(basename, "covcounters.") {
			t, _ := time.Parse(time.RFC3339, f.LastModified)
			if strings.HasSuffix(basename, ".1") {
				counter1Files = append(counter1Files, f)
				if t.After(counter1Latest) {
					counter1Latest = t
				}
			} else if strings.HasSuffix(basename, ".2") {
				counter2Files = append(counter2Files, f)
				if t.After(counter2Latest) {
					counter2Latest = t
				}
			} else {
				// Counter file without toggle suffix — include as-is
				metaFiles = append(metaFiles, f)
			}
		}
	}

	// Pick the counter suffix group with the latest modification time
	var selectedCounters []s3Object
	if len(counter1Files) == 0 && len(counter2Files) == 0 {
		// No toggled counter files
	} else if len(counter2Files) == 0 || counter1Latest.After(counter2Latest) {
		selectedCounters = counter1Files
	} else {
		selectedCounters = counter2Files
	}

	entry.Files = append(metaFiles, selectedCounters...)
	entry.Files = append(entry.Files, otherFiles...)
}

// ---------------------------------------------------------------------------
// File download
// ---------------------------------------------------------------------------

func downloadS3File(ctx context.Context, key, localPath string) error {
	args := []string{"s3", "cp",
		fmt.Sprintf("s3://%s/%s", s3Bucket, key),
		localPath,
		"--only-show-errors",
	}
	args = append(args, buildAWSArgs()...)

	cmd := exec.CommandContext(ctx, "aws", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("aws s3 cp failed: %s (%w)", strings.TrimSpace(string(output)), err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// metadata.json generation
// ---------------------------------------------------------------------------

func generateMetadata(entry coverageEntry, path string) error {
	// Parse discoveryTime to RFC3339
	collectedAt := entry.DiscoveryTime
	if t, err := time.Parse("20060102T150405Z", entry.DiscoveryTime); err == nil {
		collectedAt = t.Format(time.RFC3339)
	}

	var metadata map[string]any

	if entry.IsHost {
		metadata = map[string]any{
			"pod_name":     entry.Hostname,
			"namespace":    "",
			"container":    map[string]string{"name": "", "image": ""},
			"binary_name":  entry.SanitizedBinary,
			"collected_at": collectedAt,
			"hostname":     entry.Hostname,
			"host_process": true,
		}
	} else {
		metadata = map[string]any{
			"pod_name":     entry.PodName,
			"namespace":    entry.Namespace,
			"container":    map[string]string{"name": entry.ContainerName, "image": entry.SanitizedImage},
			"binary_name":  entry.SanitizedBinary,
			"collected_at": collectedAt,
			"hostname":     entry.Hostname,
		}
	}

	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// isEntryComplete checks if a local directory already has metadata.json and
// at least one covmeta file.
func isEntryComplete(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, "metadata.json")); err != nil {
		return false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "covmeta.") {
			return true
		}
	}
	return false
}
