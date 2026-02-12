package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var (
	renderOutputDir string
	renderSkipHTML  bool
)

type CoverageReport struct {
	TestName       string
	Namespace      string
	Pod            string
	Container      string
	BinaryName     string
	Image          string
	CollectedAt    string
	CoverageFile   string
	HTMLFile       string
	Coverage       float64
	TotalStmts     int
	CoveredStmts   int
	SourceRepo     string
	HasHTML        bool
	Error          string
}

type OwnerReport struct {
	Namespace      string
	OwnerType      string   // Deployment, DaemonSet, StatefulSet, Job
	OwnerName      string
	Containers     []string // unique container names in this owner
	PodCount       int
	Pods           []string
	Coverage       float64
	TotalStmts     int
	CoveredStmts   int
	HTMLFile       string
	HasHTML        bool
	MergedCovFile  string
	SourceReports  []CoverageReport
}

var renderCmd = &cobra.Command{
	Use:   "render",
	Short: "Generate HTML coverage reports and interactive index",
	Long: `Generate HTML coverage reports for all collected coverage data.
Aggregates coverage by pod owner (Deployment, DaemonSet, StatefulSet, Job)
and creates individual HTML reports for each owner with an interactive
index.html featuring filtering, sorting, and color-coded coverage indicators.`,
	Run: runRender,
}

func init() {
	renderCmd.Flags().StringVar(&renderOutputDir, "output-dir", "", "Output directory for HTML reports (default: <cluster>/html)")
	renderCmd.Flags().BoolVar(&renderSkipHTML, "skip-html", false, "Skip generating individual HTML reports (only create index)")
	clusterCmd.AddCommand(renderCmd)
}

func runRender(cmd *cobra.Command, args []string) {
	clusterDir := clusterName
	if renderOutputDir == "" {
		renderOutputDir = filepath.Join(clusterDir, "html")
	}

	fmt.Printf("🎨 Rendering coverage reports for cluster: %s\n", clusterName)
	fmt.Printf("📁 Output directory: %s\n\n", renderOutputDir)

	// Create output directory
	if err := os.MkdirAll(renderOutputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	// Scan coverage directory
	coverageDir := filepath.Join(clusterDir, "coverage")
	reports, err := scanCoverageReports(clusterDir, coverageDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning coverage reports: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d coverage reports\n", len(reports))

	// Group by owner
	ownerReports := groupByOwner(reports)
	fmt.Printf("Grouped into %d unique pod owners\n\n", len(ownerReports))

	if !renderSkipHTML {
		// Merge coverage and generate HTML reports
		fmt.Println("🔨 Merging coverage and generating HTML reports...")
		successCount := 0
		for i := range ownerReports {
			fmt.Printf("[%d/%d] Processing %s %s/%s (%d pods)...\n",
				i+1, len(ownerReports),
				ownerReports[i].OwnerType,
				ownerReports[i].Namespace,
				ownerReports[i].OwnerName,
				ownerReports[i].PodCount)

			if err := mergeCoverageForOwner(clusterDir, &ownerReports[i]); err != nil {
				fmt.Printf("  ⚠️  Warning merging coverage: %v\n", err)
			}

			if ownerReports[i].MergedCovFile != "" {
				if err := generateHTMLForOwner(clusterDir, &ownerReports[i]); err != nil {
					fmt.Printf("  ⚠️  Warning generating HTML: %v\n", err)
				} else {
					successCount++
					fmt.Printf("  ✓ Generated: %s\n", ownerReports[i].HTMLFile)
				}
			}
		}
		fmt.Printf("\n✅ Generated %d/%d HTML reports\n\n", successCount, len(ownerReports))
	}

	// Generate index.html
	fmt.Println("📊 Generating interactive index.html...")
	if err := generateOwnerIndexHTML(renderOutputDir, ownerReports); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating index: %v\n", err)
		os.Exit(1)
	}

	indexPath := filepath.Join(renderOutputDir, "index.html")
	fmt.Printf("\n✅ Coverage report index generated: %s\n", indexPath)
	fmt.Printf("\nOpen in browser:\n  xdg-open %s\n", indexPath)
}

func scanCoverageReports(clusterDir, coverageDir string) ([]CoverageReport, error) {
	var reports []CoverageReport

	entries, err := os.ReadDir(coverageDir)
	if err != nil {
		return nil, fmt.Errorf("read coverage directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		reportDir := filepath.Join(coverageDir, entry.Name())
		metadataFile := filepath.Join(reportDir, "metadata.json")
		coverageFile := filepath.Join(reportDir, "coverage_filtered.out")
		rawCoverageFile := filepath.Join(reportDir, "coverage.out")

		// Check for covmeta files (raw binary coverage data)
		hasCovData := false
		subEntries, _ := os.ReadDir(reportDir)
		for _, se := range subEntries {
			if strings.HasPrefix(se.Name(), "covmeta.") {
				hasCovData = true
				break
			}
		}

		if hasCovData {
			// Always regenerate from binary data so that new covcounters
			// files added by subsequent collect runs are included.
			cmd := exec.Command("go", "tool", "covdata", "textfmt",
				"-i="+reportDir,
				"-o="+rawCoverageFile)
			if output, err := cmd.CombinedOutput(); err != nil {
				fmt.Printf("  ⚠️  Failed to process %s: %v (%s)\n", entry.Name(), err, strings.TrimSpace(string(output)))
				continue
			}
			if err := createFilteredCoverage(rawCoverageFile, coverageFile); err != nil {
				continue
			}
		} else if _, err := os.Stat(coverageFile); os.IsNotExist(err) {
			// No binary data and no filtered file; try generating from
			// a pre-existing coverage.out text file.
			if _, err := os.Stat(rawCoverageFile); os.IsNotExist(err) {
				continue
			}
			if err := createFilteredCoverage(rawCoverageFile, coverageFile); err != nil {
				continue
			}
		}

		report := CoverageReport{
			TestName:     entry.Name(),
			CoverageFile: coverageFile,
		}

		// Parse metadata if available
		if data, err := os.ReadFile(metadataFile); err == nil {
			var metadata struct {
				PodName     string `json:"pod_name"`
				Namespace   string `json:"namespace"`
				Container   struct {
					Name  string `json:"name"`
					Image string `json:"image"`
				} `json:"container"`
				CollectedAt string `json:"collected_at"`
				BinaryName  string `json:"binary_name"`
			}
			if err := json.Unmarshal(data, &metadata); err == nil {
				report.Pod = metadata.PodName
				report.Namespace = metadata.Namespace
				report.Container = metadata.Container.Name
				report.Image = metadata.Container.Image
				report.CollectedAt = metadata.CollectedAt
				report.BinaryName = metadata.BinaryName
			}
		}

		// Parse coverage statistics
		if err := parseCoverageStats(&report); err == nil {
			reports = append(reports, report)
		}
	}

	return reports, nil
}

// createFilteredCoverage filters out coverage_server.go lines from a coverage file
func createFilteredCoverage(inputFile, outputFile string) error {
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	var filtered []string
	for _, line := range lines {
		if !strings.Contains(line, "coverage_server.go") {
			filtered = append(filtered, line)
		}
	}

	return os.WriteFile(outputFile, []byte(strings.Join(filtered, "\n")), 0644)
}

func parseCoverageStats(report *CoverageReport) error {
	data, err := os.ReadFile(report.CoverageFile)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	covered := 0
	total := 0

	for _, line := range lines {
		if strings.HasPrefix(line, "mode:") || line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		var stmtCount, execCount int
		fmt.Sscanf(parts[1], "%d", &stmtCount)
		fmt.Sscanf(parts[2], "%d", &execCount)

		total += stmtCount
		if execCount > 0 {
			covered += stmtCount
		}
	}

	if total > 0 {
		report.Coverage = float64(covered) / float64(total) * 100
		report.TotalStmts = total
		report.CoveredStmts = covered
	}

	return nil
}

func extractOwnerInfo(podName string) (ownerType, ownerName string) {
	// Pattern matching for different pod types
	// Deployment: name-<replicaset-hash>-<pod-hash>
	// StatefulSet: name-<ordinal>
	// DaemonSet: name-<pod-hash>
	// Job: name-<job-hash>

	// StatefulSet pattern: ends with -<number>
	if match := regexp.MustCompile(`^(.+)-(\d+)$`).FindStringSubmatch(podName); match != nil {
		return "StatefulSet", match[1]
	}

	// Deployment/ReplicaSet pattern: name-<hash>-<hash>
	if match := regexp.MustCompile(`^(.+)-([a-z0-9]{8,10})-([a-z0-9]{5})$`).FindStringSubmatch(podName); match != nil {
		return "Deployment", match[1]
	}

	// Job pattern: name-<hash> (completed jobs)
	if strings.Contains(podName, "installer-") || strings.Contains(podName, "pruner-") {
		if match := regexp.MustCompile(`^(.+-\d+)-[a-z0-9]+$`).FindStringSubmatch(podName); match != nil {
			return "Job", match[1]
		}
	}

	// DaemonSet pattern: name-<5-char-hash>
	if match := regexp.MustCompile(`^(.+)-([a-z0-9]{5})$`).FindStringSubmatch(podName); match != nil {
		return "DaemonSet", match[1]
	}

	// Default: treat as standalone pod
	return "Pod", podName
}

func groupByOwner(reports []CoverageReport) []OwnerReport {
	ownerMap := make(map[string]*OwnerReport)

	for _, report := range reports {
		ownerType, ownerName := extractOwnerInfo(report.Pod)

		// Prefer binary name over container name for display
		binaryName := report.BinaryName
		if binaryName == "" {
			binaryName = report.Container
		}

		// Group by owner + binary name so different binaries get separate rows
		key := fmt.Sprintf("%s/%s/%s/%s", report.Namespace, ownerType, ownerName, binaryName)

		if owner, exists := ownerMap[key]; exists {
			// Deduplicate pod names
			podSeen := false
			for _, p := range owner.Pods {
				if p == report.Pod {
					podSeen = true
					break
				}
			}
			if !podSeen {
				owner.Pods = append(owner.Pods, report.Pod)
				owner.PodCount++
			}
			owner.SourceReports = append(owner.SourceReports, report)
		} else {
			containers := []string{}
			if binaryName != "" {
				containers = []string{binaryName}
			}
			ownerMap[key] = &OwnerReport{
				Namespace:     report.Namespace,
				OwnerType:     ownerType,
				OwnerName:     ownerName,
				Containers:    containers,
				PodCount:      1,
				Pods:          []string{report.Pod},
				SourceReports: []CoverageReport{report},
			}
		}
	}

	// Convert map to slice and sort
	var owners []OwnerReport
	for _, owner := range ownerMap {
		sort.Strings(owner.Containers)
		owners = append(owners, *owner)
	}

	sort.Slice(owners, func(i, j int) bool {
		if owners[i].Namespace != owners[j].Namespace {
			return owners[i].Namespace < owners[j].Namespace
		}
		if owners[i].OwnerType != owners[j].OwnerType {
			return owners[i].OwnerType < owners[j].OwnerType
		}
		if owners[i].OwnerName != owners[j].OwnerName {
			return owners[i].OwnerName < owners[j].OwnerName
		}
		// Sort by binary name within the same owner
		ci := ""
		cj := ""
		if len(owners[i].Containers) > 0 {
			ci = owners[i].Containers[0]
		}
		if len(owners[j].Containers) > 0 {
			cj = owners[j].Containers[0]
		}
		return ci < cj
	})

	return owners
}

func mergeCoverageForOwner(clusterDir string, owner *OwnerReport) error {
	if len(owner.SourceReports) == 0 {
		return fmt.Errorf("no source reports")
	}

	// Create merged coverage file - include binary name if available
	binaryLabel := ""
	if len(owner.Containers) > 0 {
		binaryLabel = "-" + owner.Containers[0]
	}
	mergedFile := filepath.Join(renderOutputDir,
		fmt.Sprintf("%s-%s-%s%s-merged.out",
			owner.Namespace, owner.OwnerType, owner.OwnerName, binaryLabel))

	// Merge all coverage files
	coverageMap := make(map[string]CoverageLine)
	var mode string

	for _, report := range owner.SourceReports {
		if err := mergeCoverageFile(report.CoverageFile, coverageMap, &mode); err != nil {
			return fmt.Errorf("merge %s: %w", report.CoverageFile, err)
		}
	}

	// Write merged coverage
	f, err := os.Create(mergedFile)
	if err != nil {
		return fmt.Errorf("create merged file: %w", err)
	}
	defer f.Close()

	if mode == "" {
		mode = "set"
	}
	fmt.Fprintf(f, "mode: %s\n", mode)

	// Sort keys for consistent output
	var keys []string
	for key := range coverageMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	totalStmts := 0
	coveredStmts := 0

	for _, key := range keys {
		line := coverageMap[key]
		fmt.Fprintf(f, "%s %d %d\n", line.Block, line.NumStmt, line.Count)

		totalStmts += line.NumStmt
		if line.Count > 0 {
			coveredStmts += line.NumStmt
		}
	}

	owner.MergedCovFile = mergedFile
	owner.TotalStmts = totalStmts
	owner.CoveredStmts = coveredStmts
	if totalStmts > 0 {
		owner.Coverage = float64(coveredStmts) / float64(totalStmts) * 100
	}

	return nil
}

type CoverageLine struct {
	Block   string
	NumStmt int
	Count   int
}

func extractPackagePathFromCoverage(coverageFile string) string {
	f, err := os.Open(coverageFile)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "mode:") || line == "" {
			continue
		}

		// Parse package path from coverage line
		// Format: package/path/file.go:line.col,line.col statements count
		parts := strings.Fields(line)
		if len(parts) > 0 {
			fileAndLine := parts[0]
			if idx := strings.Index(fileAndLine, ":"); idx > 0 {
				filePath := fileAndLine[:idx]

				// Skip non-module paths (container build paths like /workspace/)
				// and keep scanning for a proper Go module path
				if strings.HasPrefix(filePath, "/") && !strings.Contains(filePath, "/src/github.com/") {
					continue
				}

				// Handle container build paths like /go/src/github.com/...
				if strings.Contains(filePath, "/src/github.com/") {
					if idx := strings.Index(filePath, "/src/"); idx >= 0 {
						filePath = filePath[idx+5:] // Skip "/src/"
					}
				}

				// Remove filename to get package path
				if lastSlash := strings.LastIndex(filePath, "/"); lastSlash > 0 {
					return filePath[:lastSlash]
				}
			}
		}
	}
	return ""
}

// findMatchingRepository finds a repository that matches the given package path
// Handles package path migrations, forks, and organization changes
func findMatchingRepository(reposDir, packagePath string) string {
	type repoCandidate struct {
		path       string
		moduleName string
		score      int
	}

	var candidates []repoCandidate

	// Extract repository name from package path for fuzzy matching
	// e.g., "github.com/coreos/prometheus-operator" -> "prometheus-operator"
	packageParts := strings.Split(packagePath, "/")
	var packageRepoName string
	if len(packageParts) >= 3 {
		packageRepoName = packageParts[2] // The repo name part
	}

	// Walk all repositories and score them
	filepath.Walk(reposDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() {
			return nil
		}

		goMod := filepath.Join(path, "go.mod")
		if _, err := os.Stat(goMod); err != nil {
			return nil
		}

		// Read module name from go.mod
		data, err := os.ReadFile(goMod)
		if err != nil {
			return nil
		}

		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "module ") {
				moduleName := strings.TrimSpace(strings.TrimPrefix(line, "module "))

				score := 0

				// Exact match (highest priority)
				if strings.HasPrefix(packagePath, moduleName) {
					score = 100
				}

				// Repository name match (handles org changes)
				// e.g., "github.com/coreos/prometheus-operator" matches "github.com/prometheus-operator/prometheus-operator"
				if packageRepoName != "" {
					moduleParts := strings.Split(moduleName, "/")
					if len(moduleParts) >= 2 {
						moduleRepoName := moduleParts[len(moduleParts)-1]
						if moduleRepoName == packageRepoName {
							score = 50
						} else if strings.Contains(moduleRepoName, packageRepoName) || strings.Contains(packageRepoName, moduleRepoName) {
							score = 25
						}
					}
				}

				// Special case: prometheus-operator package path migrations
				// coreos/prometheus-operator -> prometheus-operator/prometheus-operator
				if strings.Contains(packagePath, "coreos/prometheus-operator") &&
					strings.Contains(moduleName, "prometheus-operator/prometheus-operator") {
					score = 90
				}
				if strings.Contains(packagePath, "prometheus-operator") &&
					strings.Contains(moduleName, "prometheus-operator") {
					score = max(score, 40)
				}

				if score > 0 {
					candidates = append(candidates, repoCandidate{
						path:       path,
						moduleName: moduleName,
						score:      score,
					})
				}

				break
			}
		}
		return nil
	})

	// Return the best match
	if len(candidates) == 0 {
		return ""
	}

	// Sort by score (descending)
	bestCandidate := candidates[0]
	for _, c := range candidates {
		if c.score > bestCandidate.score {
			bestCandidate = c
		}
	}

	return bestCandidate.path
}

func mergeCoverageFile(filename string, coverageMap map[string]CoverageLine, mode *string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "mode:") {
			if *mode == "" {
				*mode = strings.TrimPrefix(line, "mode: ")
			}
			continue
		}

		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		block := parts[0]
		var numStmt, count int
		fmt.Sscanf(parts[1], "%d", &numStmt)
		fmt.Sscanf(parts[2], "%d", &count)

		if existing, exists := coverageMap[block]; exists {
			// Merge: take max count
			if count > existing.Count {
				existing.Count = count
				coverageMap[block] = existing
			}
		} else {
			coverageMap[block] = CoverageLine{
				Block:   block,
				NumStmt: numStmt,
				Count:   count,
			}
		}
	}

	return scanner.Err()
}

// getModuleName reads the module name from a repository's go.mod file
func getModuleName(repoPath string) string {
	goMod := filepath.Join(repoPath, "go.mod")
	data, err := os.ReadFile(goMod)
	if err != nil {
		return ""
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return ""
}

// extractModulePrefix extracts the module-level prefix from a package path
// e.g., "github.com/coreos/prometheus-operator/cmd/reloader" -> "github.com/coreos/prometheus-operator"
func extractModulePrefix(packagePath string) string {
	parts := strings.Split(packagePath, "/")
	// For github.com paths, the module is the first 3 segments: github.com/org/repo
	if len(parts) >= 3 && parts[0] == "github.com" {
		return strings.Join(parts[:3], "/")
	}
	// For other paths (k8s.io, golang.org, etc.), use first 2 segments
	if len(parts) >= 2 {
		return strings.Join(parts[:2], "/")
	}
	return packagePath
}

// rewriteCoveragePaths creates a new coverage file with rewritten package paths
// This handles cases where the coverage file references old package paths (e.g., github.com/coreos/prometheus-operator)
// but the actual module uses a different path (e.g., github.com/prometheus-operator/prometheus-operator)
// It also handles container build paths like /workspace/ or /go/src/
func rewriteCoveragePaths(coverageFile, oldPath, newPath string) (string, error) {
	data, err := os.ReadFile(coverageFile)
	if err != nil {
		return "", err
	}

	content := string(data)

	// For /workspace/ paths, replace directly (not a module path)
	if oldPath == "/workspace/" {
		content = strings.ReplaceAll(content, "/workspace/", newPath+"/")
	} else {
		// Extract just the module-level prefix from the old path
		oldModulePrefix := extractModulePrefix(oldPath)

		// Replace the module prefix, preserving sub-package paths
		content = strings.ReplaceAll(content, "/go/src/"+oldModulePrefix, newPath)
		content = strings.ReplaceAll(content, oldModulePrefix, newPath)
	}

	tmpFile, err := os.CreateTemp("", "coverage-rewritten-*.out")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	if _, err := tmpFile.WriteString(content); err != nil {
		os.Remove(tmpFile.Name())
		return "", err
	}

	return tmpFile.Name(), nil
}

// filterMissingSourceFiles creates a new coverage file with lines removed for source files
// that don't exist in the repository (e.g., generated files like bindata.go)
func filterMissingSourceFiles(coverageFile, repoPath string) (string, bool) {
	data, err := os.ReadFile(coverageFile)
	if err != nil {
		return coverageFile, false
	}

	lines := strings.Split(string(data), "\n")
	var filtered []string
	removedCount := 0
	moduleName := getModuleName(repoPath)

	for _, line := range lines {
		if strings.HasPrefix(line, "mode:") || line == "" {
			filtered = append(filtered, line)
			continue
		}

		// Extract file path from coverage line
		parts := strings.Fields(line)
		if len(parts) < 1 {
			filtered = append(filtered, line)
			continue
		}

		fileAndLine := parts[0]
		idx := strings.Index(fileAndLine, ":")
		if idx <= 0 {
			filtered = append(filtered, line)
			continue
		}

		filePath := fileAndLine[:idx]

		// Convert module path to filesystem path relative to repo
		relPath := filePath
		if moduleName != "" && strings.HasPrefix(filePath, moduleName) {
			relPath = strings.TrimPrefix(filePath, moduleName)
			relPath = strings.TrimPrefix(relPath, "/")
		}

		absPath := filepath.Join(repoPath, relPath)
		if _, err := os.Stat(absPath); os.IsNotExist(err) {
			removedCount++
			continue
		}

		filtered = append(filtered, line)
	}

	if removedCount == 0 {
		return coverageFile, false
	}

	tmpFile, err := os.CreateTemp("", "coverage-filtered-*.out")
	if err != nil {
		return coverageFile, false
	}

	content := strings.Join(filtered, "\n")
	if _, err := tmpFile.WriteString(content); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return coverageFile, false
	}
	tmpFile.Close()

	return tmpFile.Name(), true
}

// findRepoByOwnerName tries to find a repository by matching the owner name
// to repository directory names. This handles cases like /workspace/ paths
// where the coverage file has no Go module path information.
func findRepoByOwnerName(reposDir, ownerName string) string {
	var bestMatch string
	bestScore := 0

	filepath.Walk(reposDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() {
			return nil
		}

		goMod := filepath.Join(path, "go.mod")
		if _, err := os.Stat(goMod); err != nil {
			return nil
		}

		// Get the repo directory name (last component before the commit hash dir)
		dirParts := strings.Split(path, "/")
		if len(dirParts) < 2 {
			return nil
		}

		// The repo name is the parent of the commit hash directory
		repoName := dirParts[len(dirParts)-2]

		// Score the match
		score := 0
		ownerLower := strings.ToLower(ownerName)
		repoLower := strings.ToLower(repoName)

		if ownerLower == repoLower {
			score = 100
		} else if strings.Contains(repoLower, ownerLower) || strings.Contains(ownerLower, repoLower) {
			// Partial match - use length of overlap as score
			score = 30
		}

		if score > bestScore {
			bestScore = score
			bestMatch = path
		}

		return nil
	})

	return bestMatch
}

func generateHTMLForOwner(clusterDir string, owner *OwnerReport) error {
	// Find source repository by analyzing coverage file
	reposDir := filepath.Join(clusterDir, "repos")
	var repoPath string

	// Read coverage file to find package path
	packagePath := ""
	if owner.MergedCovFile != "" {
		packagePath = extractPackagePathFromCoverage(owner.MergedCovFile)
		if packagePath != "" {
			repoPath = findMatchingRepository(reposDir, packagePath)
		}
	}

	// Fallback: try to match by owner name when package path matching fails
	// This handles /workspace/ paths and other non-standard coverage formats
	if repoPath == "" {
		repoPath = findRepoByOwnerName(reposDir, owner.OwnerName)
	}

	if repoPath == "" {
		return fmt.Errorf("no source repository found for package path")
	}

	// Read module name from repository's go.mod
	moduleName := getModuleName(repoPath)

	covFileToUse := owner.MergedCovFile

	// Check if coverage file needs path rewriting
	needsRewrite := false
	rewriteOldPath := packagePath

	if moduleName != "" && packagePath != "" && !strings.HasPrefix(packagePath, moduleName) {
		needsRewrite = true
	}

	// Handle /workspace/ paths: rewrite to the module name
	if !needsRewrite {
		if data, err := os.ReadFile(owner.MergedCovFile); err == nil {
			content := string(data)
			if strings.Contains(content, "/workspace/") && moduleName != "" {
				needsRewrite = true
				rewriteOldPath = "/workspace/"
			}
		}
	}

	if !needsRewrite {
		// Also rewrite if coverage file contains /go/src/ prefixed paths (container build artifact)
		if data, err := os.ReadFile(owner.MergedCovFile); err == nil {
			if strings.Contains(string(data), "/go/src/") {
				needsRewrite = true
				// When module name matches but paths have /go/src/ prefix,
				// rewrite /go/src/<module> to <module>
				if moduleName != "" {
					rewriteOldPath = "/go/src/" + moduleName
				}
			}
		}
	}

	if needsRewrite {
		rewrittenFile, err := rewriteCoveragePaths(covFileToUse, rewriteOldPath, moduleName)
		if err == nil {
			covFileToUse = rewrittenFile
			defer os.Remove(rewrittenFile)
		}
	}

	// Filter out coverage lines for source files that don't exist in the repo
	// (e.g., generated files like bindata.go)
	if filteredFile, wasFiltered := filterMissingSourceFiles(covFileToUse, repoPath); wasFiltered {
		if covFileToUse != owner.MergedCovFile {
			os.Remove(covFileToUse) // Clean up previous temp file
		}
		covFileToUse = filteredFile
		defer os.Remove(filteredFile)
	}

	// Generate custom HTML report
	htmlBinaryLabel := ""
	if len(owner.Containers) > 0 {
		htmlBinaryLabel = "-" + owner.Containers[0]
	}
	htmlFile := fmt.Sprintf("%s-%s-%s%s.html",
		owner.Namespace, owner.OwnerType, owner.OwnerName, htmlBinaryLabel)

	absOutputDir, err := filepath.Abs(renderOutputDir)
	if err != nil {
		return fmt.Errorf("get absolute output dir: %w", err)
	}

	absOutputPath := filepath.Join(absOutputDir, htmlFile)

	fileReports, err := buildFileCoverageReports(covFileToUse, repoPath, moduleName)
	if err != nil {
		return fmt.Errorf("build file coverage reports: %w", err)
	}

	if err := renderCustomCoverageHTML(absOutputPath, owner, fileReports); err != nil {
		return fmt.Errorf("render custom HTML: %w", err)
	}

	owner.HTMLFile = htmlFile
	owner.HasHTML = true

	return nil
}

func generateOwnerIndexHTML(outputDir string, owners []OwnerReport) error {
	indexPath := filepath.Join(outputDir, "index.html")

	tmpl := template.Must(template.New("index").Funcs(template.FuncMap{
		"colorClass": func(coverage float64) string {
			if coverage >= 70 {
				return "excellent"
			} else if coverage >= 50 {
				return "good"
			} else if coverage >= 30 {
				return "moderate"
			} else if coverage >= 15 {
				return "poor"
			}
			return "critical"
		},
		"formatPct": func(coverage float64) string {
			return fmt.Sprintf("%.1f%%", coverage)
		},
		"showPctInBar": func(coverage float64) bool {
			return coverage >= 20
		},
		"joinContainers": func(containers []string) string {
			return strings.Join(containers, ", ")
		},
		"formatInt": func(n int) string {
			s := fmt.Sprintf("%d", n)
			if len(s) <= 3 {
				return s
			}
			var result []byte
			for i, c := range s {
				if i > 0 && (len(s)-i)%3 == 0 {
					result = append(result, ',')
				}
				result = append(result, byte(c))
			}
			return string(result)
		},
	}).Parse(ownerIndexTemplate))

	f, err := os.Create(indexPath)
	if err != nil {
		return err
	}
	defer f.Close()

	stats := calculateOwnerStats(owners)

	data := struct {
		Owners []OwnerReport
		Stats  OwnerStats
	}{
		Owners: owners,
		Stats:  stats,
	}

	return tmpl.Execute(f, data)
}

type OwnerStats struct {
	TotalOwners     int
	TotalPods       int
	TotalStmts      int
	CoveredStmts    int
	OverallCoverage float64
	Excellent       int
	Good            int
	Moderate        int
	Poor            int
	Critical        int
	WithHTML        int
	ByType          map[string]int
}

func calculateOwnerStats(owners []OwnerReport) OwnerStats {
	stats := OwnerStats{
		TotalOwners: len(owners),
		ByType:      make(map[string]int),
	}

	for _, o := range owners {
		stats.TotalPods += o.PodCount
		stats.TotalStmts += o.TotalStmts
		stats.CoveredStmts += o.CoveredStmts
		stats.ByType[o.OwnerType]++

		if o.HasHTML {
			stats.WithHTML++
		}

		if o.Coverage >= 70 {
			stats.Excellent++
		} else if o.Coverage >= 50 {
			stats.Good++
		} else if o.Coverage >= 30 {
			stats.Moderate++
		} else if o.Coverage >= 15 {
			stats.Poor++
		} else {
			stats.Critical++
		}
	}

	if stats.TotalStmts > 0 {
		stats.OverallCoverage = float64(stats.CoveredStmts) / float64(stats.TotalStmts) * 100
	}

	return stats
}

const ownerIndexTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Coverage Report - By Pod Owner</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #f5f5f5;
            padding: 20px;
            line-height: 1.6;
        }

        .container {
            max-width: 1600px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
        }

        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            border-radius: 8px;
            color: white;
        }

        .stat-card.secondary {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }

        .stat-card.tertiary {
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        }

        .stat-card.quaternary {
            background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);
        }

        .stat-label {
            font-size: 11px;
            opacity: 0.9;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }

        .stat-value {
            font-size: 32px;
            font-weight: bold;
        }

        .stat-unit {
            font-size: 14px;
            opacity: 0.9;
            margin-left: 5px;
        }

        .coverage-distribution {
            display: flex;
            gap: 10px;
            margin-bottom: 30px;
            flex-wrap: wrap;
        }

        .coverage-badge {
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .coverage-badge .count {
            background: rgba(255,255,255,0.3);
            padding: 2px 8px;
            border-radius: 10px;
        }

        .badge-excellent { background: #28a745; color: white; }
        .badge-good { background: #5cb85c; color: white; }
        .badge-moderate { background: #ffc107; color: #333; }
        .badge-poor { background: #fd7e14; color: white; }
        .badge-critical { background: #dc3545; color: white; }

        .controls {
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
            flex-wrap: wrap;
            align-items: center;
        }

        .search-box {
            flex: 1;
            min-width: 250px;
        }

        input[type="text"] {
            width: 100%;
            padding: 10px 15px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }

        input[type="text"]:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        select {
            padding: 10px 15px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            background: white;
            cursor: pointer;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }

        th {
            background: #f8f9fa;
            padding: 14px 12px;
            text-align: left;
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #666;
            border-bottom: 2px solid #dee2e6;
            position: sticky;
            top: 0;
            cursor: pointer;
            user-select: none;
        }

        th:hover {
            background: #e9ecef;
        }

        th.sortable::after {
            content: " ⇅";
            opacity: 0.3;
        }

        th.sorted-asc::after {
            content: " ▲";
            opacity: 1;
        }

        th.sorted-desc::after {
            content: " ▼";
            opacity: 1;
        }

        td {
            padding: 14px 12px;
            border-bottom: 1px solid #f0f0f0;
            font-size: 14px;
        }

        tr:hover {
            background: #f8f9fa;
        }

        .namespace {
            background: #e7f3ff;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            color: #0056b3;
            display: inline-block;
        }

        .owner-type {
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: 600;
            display: inline-block;
            margin-right: 6px;
        }

        .owner-type.Deployment { background: #d1ecf1; color: #0c5460; }
        .owner-type.StatefulSet { background: #d4edda; color: #155724; }
        .owner-type.DaemonSet { background: #fff3cd; color: #856404; }
        .owner-type.Job { background: #f8d7da; color: #721c24; }
        .owner-type.Pod { background: #e2e3e5; color: #383d41; }

        .pod-count {
            background: #6c757d;
            color: white;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 11px;
            font-weight: 600;
            display: inline-block;
            margin-left: 8px;
        }

        .coverage-bar {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .bar-container {
            flex: 1;
            background: #e9ecef;
            height: 24px;
            border-radius: 12px;
            overflow: hidden;
        }

        .bar-fill {
            height: 100%;
            transition: width 0.3s;
            display: flex;
            align-items: center;
            justify-content: flex-end;
            padding-right: 10px;
            font-size: 11px;
            font-weight: bold;
            color: white;
            text-shadow: 0 1px 2px rgba(0,0,0,0.2);
        }

        .bar-fill.excellent { background: linear-gradient(90deg, #28a745, #20c997); }
        .bar-fill.good { background: linear-gradient(90deg, #5cb85c, #28a745); }
        .bar-fill.moderate { background: linear-gradient(90deg, #ffc107, #fd7e14); }
        .bar-fill.poor { background: linear-gradient(90deg, #fd7e14, #dc3545); }
        .bar-fill.critical { background: linear-gradient(90deg, #dc3545, #c82333); }

        .coverage-text {
            font-weight: 600;
            min-width: 60px;
            text-align: right;
            font-size: 15px;
        }

        .coverage-text.excellent { color: #28a745; }
        .coverage-text.good { color: #5cb85c; }
        .coverage-text.moderate { color: #f39c12; }
        .coverage-text.poor { color: #fd7e14; }
        .coverage-text.critical { color: #dc3545; }

        a {
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
        }

        a:hover {
            text-decoration: underline;
        }

        .containers {
            font-size: 12px;
            color: #555;
            word-break: break-word;
        }

        .no-html {
            color: #999;
            font-style: italic;
            font-size: 12px;
        }

        .statements {
            color: #666;
            font-size: 13px;
            font-family: 'Courier New', monospace;
        }

        .filter-info {
            margin-top: 20px;
            padding: 12px 16px;
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            border-radius: 4px;
            font-size: 14px;
            display: none;
        }

        .filter-info.active {
            display: block;
        }

        @media (max-width: 768px) {
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }

            .controls {
                flex-direction: column;
            }

            .search-box {
                width: 100%;
            }

            table {
                font-size: 12px;
            }

            .coverage-bar {
                flex-direction: column;
                align-items: flex-start;
                gap: 5px;
            }

            .bar-container {
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎯 Coverage Report - By Pod Owner</h1>
        <div class="subtitle">Aggregated coverage by Deployment, DaemonSet, StatefulSet, and Job</div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Pod Owners</div>
                <div class="stat-value">{{.Stats.TotalOwners}}</div>
            </div>
            <div class="stat-card secondary">
                <div class="stat-label">Overall Coverage</div>
                <div class="stat-value">{{formatPct .Stats.OverallCoverage}}</div>
            </div>
            <div class="stat-card tertiary">
                <div class="stat-label">Total Statements</div>
                <div class="stat-value">{{formatInt .Stats.TotalStmts}}</div>
            </div>
            <div class="stat-card quaternary">
                <div class="stat-label">Total Pods</div>
                <div class="stat-value">{{.Stats.TotalPods}}</div>
            </div>
        </div>

        <div class="coverage-distribution">
            <div class="coverage-badge badge-excellent">
                <span>Excellent (≥70%)</span>
                <span class="count">{{.Stats.Excellent}}</span>
            </div>
            <div class="coverage-badge badge-good">
                <span>Good (50-69%)</span>
                <span class="count">{{.Stats.Good}}</span>
            </div>
            <div class="coverage-badge badge-moderate">
                <span>Moderate (30-49%)</span>
                <span class="count">{{.Stats.Moderate}}</span>
            </div>
            <div class="coverage-badge badge-poor">
                <span>Poor (15-29%)</span>
                <span class="count">{{.Stats.Poor}}</span>
            </div>
            <div class="coverage-badge badge-critical">
                <span>Critical (<15%)</span>
                <span class="count">{{.Stats.Critical}}</span>
            </div>
        </div>

        <div class="controls">
            <div class="search-box">
                <input type="text" id="searchBox" placeholder="🔍 Search namespace or owner name...">
            </div>
            <select id="namespaceFilter">
                <option value="">All Namespaces</option>
            </select>
            <select id="ownerTypeFilter">
                <option value="">All Types</option>
                <option value="Deployment">Deployments</option>
                <option value="DaemonSet">DaemonSets</option>
                <option value="StatefulSet">StatefulSets</option>
                <option value="Job">Jobs</option>
                <option value="Pod">Pods</option>
            </select>
            <select id="coverageFilter">
                <option value="">All Coverage Levels</option>
                <option value="excellent">Excellent (≥70%)</option>
                <option value="good">Good (50-69%)</option>
                <option value="moderate">Moderate (30-49%)</option>
                <option value="poor">Poor (15-29%)</option>
                <option value="critical">Critical (<15%)</option>
            </select>
        </div>

        <div id="filterInfo" class="filter-info"></div>

        <table id="ownersTable">
            <thead>
                <tr>
                    <th class="sortable" data-sort="namespace">Namespace</th>
                    <th class="sortable" data-sort="owner">Owner</th>
                    <th class="sortable" data-sort="container">Container</th>
                    <th class="sortable" data-sort="pods">Pods</th>
                    <th class="sortable" data-sort="coverage">Coverage</th>
                    <th class="sortable" data-sort="statements">Statements</th>
                    <th>Report</th>
                </tr>
            </thead>
            <tbody>
                {{range .Owners}}
                <tr data-namespace="{{.Namespace}}"
                    data-owner="{{.OwnerName}}"
                    data-owner-type="{{.OwnerType}}"
                    data-container="{{joinContainers .Containers}}"
                    data-pods="{{.PodCount}}"
                    data-coverage="{{.Coverage}}"
                    data-statements="{{.TotalStmts}}"
                    data-coverage-class="{{colorClass .Coverage}}">
                    <td><span class="namespace">{{.Namespace}}</span></td>
                    <td>
                        <span class="owner-type {{.OwnerType}}">{{.OwnerType}}</span>
                        <strong>{{.OwnerName}}</strong>
                    </td>
                    <td><code class="containers">{{joinContainers .Containers}}</code></td>
                    <td><span class="pod-count">{{.PodCount}} pod{{if ne .PodCount 1}}s{{end}}</span></td>
                    <td>
                        <div class="coverage-bar">
                            <div class="bar-container">
                                <div class="bar-fill {{colorClass .Coverage}}" style="width: {{.Coverage}}%">
                                    {{if showPctInBar .Coverage}}{{formatPct .Coverage}}{{end}}
                                </div>
                            </div>
                            <span class="coverage-text {{colorClass .Coverage}}">{{formatPct .Coverage}}</span>
                        </div>
                    </td>
                    <td class="statements">{{.CoveredStmts}}/{{.TotalStmts}}</td>
                    <td>
                        {{if .HasHTML}}
                        <a href="{{.HTMLFile}}" target="_blank">📊 View HTML</a>
                        {{else}}
                        <span class="no-html">No HTML</span>
                        {{end}}
                    </td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>

    <script>
        // Populate filters
        const namespaceFilter = document.getElementById('namespaceFilter');
        const namespaces = new Set();
        document.querySelectorAll('tr[data-namespace]').forEach(row => {
            namespaces.add(row.dataset.namespace);
        });
        [...namespaces].sort().forEach(ns => {
            const option = document.createElement('option');
            option.value = ns;
            option.textContent = ns;
            namespaceFilter.appendChild(option);
        });

        // Filter functionality
        const searchBox = document.getElementById('searchBox');
        const ownerTypeFilter = document.getElementById('ownerTypeFilter');
        const coverageFilter = document.getElementById('coverageFilter');
        const filterInfo = document.getElementById('filterInfo');
        const table = document.getElementById('ownersTable');
        const rows = table.querySelectorAll('tbody tr');

        function applyFilters() {
            const searchTerm = searchBox.value.toLowerCase();
            const selectedNamespace = namespaceFilter.value;
            const selectedOwnerType = ownerTypeFilter.value;
            const selectedCoverage = coverageFilter.value;

            let visibleCount = 0;

            rows.forEach(row => {
                const namespace = row.dataset.namespace.toLowerCase();
                const owner = row.dataset.owner.toLowerCase();
                const container = row.dataset.container.toLowerCase();
                const ownerType = row.dataset.ownerType;
                const coverageClass = row.dataset.coverageClass;

                const matchesSearch = !searchTerm ||
                    namespace.includes(searchTerm) ||
                    owner.includes(searchTerm) ||
                    container.includes(searchTerm);

                const matchesNamespace = !selectedNamespace ||
                    row.dataset.namespace === selectedNamespace;

                const matchesOwnerType = !selectedOwnerType ||
                    ownerType === selectedOwnerType;

                const matchesCoverage = !selectedCoverage ||
                    coverageClass === selectedCoverage;

                if (matchesSearch && matchesNamespace && matchesOwnerType && matchesCoverage) {
                    row.style.display = '';
                    visibleCount++;
                } else {
                    row.style.display = 'none';
                }
            });

            // Update filter info
            if (searchTerm || selectedNamespace || selectedOwnerType || selectedCoverage) {
                filterInfo.classList.add('active');
                filterInfo.textContent = 'Showing ' + visibleCount + ' of ' + rows.length + ' owners';
            } else {
                filterInfo.classList.remove('active');
            }
        }

        searchBox.addEventListener('input', applyFilters);
        namespaceFilter.addEventListener('change', applyFilters);
        ownerTypeFilter.addEventListener('change', applyFilters);
        coverageFilter.addEventListener('change', applyFilters);

        // Sorting functionality
        let currentSort = { column: null, direction: 'asc' };

        document.querySelectorAll('th.sortable').forEach(th => {
            th.addEventListener('click', () => {
                const sortBy = th.dataset.sort;

                if (currentSort.column === sortBy) {
                    currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
                } else {
                    currentSort.column = sortBy;
                    currentSort.direction = 'asc';
                }

                document.querySelectorAll('th.sortable').forEach(header => {
                    header.classList.remove('sorted-asc', 'sorted-desc');
                });
                th.classList.add('sorted-' + currentSort.direction);

                sortTable(sortBy, currentSort.direction);
            });
        });

        function sortTable(column, direction) {
            const tbody = table.querySelector('tbody');
            const rowsArray = Array.from(rows);

            rowsArray.sort((a, b) => {
                let aVal, bVal;

                if (column === 'coverage' || column === 'statements' || column === 'pods') {
                    aVal = parseFloat(a.dataset[column]);
                    bVal = parseFloat(b.dataset[column]);
                } else if (column === 'owner') {
                    aVal = a.dataset.ownerType + a.dataset.owner.toLowerCase();
                    bVal = b.dataset.ownerType + b.dataset.owner.toLowerCase();
                } else if (column === 'container') {
                    aVal = a.dataset.container.toLowerCase();
                    bVal = b.dataset.container.toLowerCase();
                } else {
                    aVal = a.dataset[column].toLowerCase();
                    bVal = b.dataset[column].toLowerCase();
                }

                if (aVal < bVal) return direction === 'asc' ? -1 : 1;
                if (aVal > bVal) return direction === 'asc' ? 1 : -1;
                return 0;
            });

            rowsArray.forEach(row => tbody.appendChild(row));
        }

        // Format numbers
        document.querySelectorAll('.stat-value').forEach(el => {
            const text = el.textContent.trim();
            if (text.includes('%')) return;
            const value = parseInt(text.replace(/,/g, ''));
            if (!isNaN(value) && value > 999) {
                el.textContent = value.toLocaleString();
            }
        });
    </script>
</body>
</html>
`
