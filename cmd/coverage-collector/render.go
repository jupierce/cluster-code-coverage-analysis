package main

import (
	"bufio"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/spf13/cobra"

	_ "modernc.org/sqlite"
)

var (
	renderOutputDir string
	renderSkipComponentHTML  bool
)

// HashGroupOwnerInfo describes one owner contributing to a hash-group HTML report.
type HashGroupOwnerInfo struct {
	Namespace  string
	OwnerType  string
	OwnerName  string
	BinaryName string
	Containers string // comma-joined
	Pods       string // comma-joined
	PodCount   int
	Hosts      string // comma-joined
}

type OwnerReport struct {
	Namespace          string
	OwnerType          string   // Deployment, DaemonSet, StatefulSet, Job, Host, Pod (No Owner)
	OwnerName          string
	Containers         []string // unique container/binary names
	PodCount           int
	Pods               []string
	Hosts              []string // unique hostnames
	Coverage           float64
	TotalStmts         int
	CoveredStmts       int
	HTMLFile           string
	HasHTML            bool
	Image              string // image reference from owners table
	MergedCovFile      string // temp file written from DB for HTML generation
	MergedCoverageText string // merged coverage text from DB
	MergeInputHash     string // hash for HTML caching
	BinaryName         string // binary name from owners table
	CovmetaHash        string // hash of statement definitions (for deduplication)
	FirstSeen          string // earliest collected_at timestamp
	LastSeen           string // latest collected_at timestamp
	CommitID           string // git commit from image source labels
	HashGroupOwners    []HashGroupOwnerInfo // populated at render time for hash-based reports
}

var renderCmd = &cobra.Command{
	Use:   "render",
	Short: "Generate HTML coverage reports and interactive index",
	Long: `Generate HTML coverage reports from the compiled coverage database.

Reads owner data from the SQLite database (created by 'compile') and generates
individual HTML reports for each owner with an interactive index.html featuring
filtering, sorting, and color-coded coverage indicators.

Requires source repositories in <collection>/repos/ for annotated HTML reports.`,
	RunE: runRenderE,
}

func init() {
	renderCmd.Flags().StringVar(&renderOutputDir, "output-dir", "", "Output directory for HTML reports (default: <collection>/html)")
	renderCmd.Flags().BoolVar(&renderSkipComponentHTML, "skip-component-html", false, "Skip generating individual component HTML reports (only create index)")
	clusterCmd.AddCommand(renderCmd)
}

func runRenderE(cmd *cobra.Command, args []string) error {
	collectionDir := collectionName
	if renderOutputDir == "" {
		renderOutputDir = filepath.Join(collectionDir, "html")
	}

	fmt.Printf("Rendering coverage reports for collection: %s\n", collectionName)
	fmt.Printf("Output directory: %s\n\n", renderOutputDir)

	// Create output directory
	if err := os.MkdirAll(renderOutputDir, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	// Open SQLite database (read-only)
	dbPath := filepath.Join(collectionDir, "coverage.db")
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("database not found at %s — run 'compile' first", dbPath)
	}

	db, err := sql.Open("sqlite", dbPath+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	// Load owner reports from DB
	ownerReports, err := loadOwnersForRender(db)
	if err != nil {
		return fmt.Errorf("load owners: %w", err)
	}

	fmt.Printf("Loaded %d owners from database\n", len(ownerReports))

	// Load image sources for fast repo lookup
	imageSources, err := loadImageSources(db)
	if err != nil {
		fmt.Printf("Warning: could not load image sources: %v\n", err)
		imageSources = make(map[string]imageSource)
	}
	fmt.Printf("Loaded %d image source mappings\n\n", len(imageSources))

	// Enrich owners with commit IDs and covmeta hashes
	for i := range ownerReports {
		if ownerReports[i].Image != "" {
			if src, ok := imageSources[ownerReports[i].Image]; ok {
				ownerReports[i].CommitID = src.CommitID
			}
		}
		ownerReports[i].CovmetaHash = computeCovmetaHash(ownerReports[i].MergedCoverageText)
	}

	if !renderSkipComponentHTML {
		fmt.Printf("Generating HTML reports by hash group (concurrency: %d)...\n", maxConcurrency)

		var successCount, cachedCount, skippedCount, errorCount int64

		// Group owners by covmeta hash — one HTML per unique binary hash
		type hashGroup struct {
			hash     string
			owners   []*OwnerReport
			cacheKey string
		}
		hashGroupMap := make(map[string]*hashGroup)
		for i := range ownerReports {
			hash := ownerReports[i].CovmetaHash
			if hash == "" || ownerReports[i].MergedCoverageText == "" {
				skippedCount++
				continue
			}
			hg, ok := hashGroupMap[hash]
			if !ok {
				hg = &hashGroup{hash: hash}
				hashGroupMap[hash] = hg
			}
			hg.owners = append(hg.owners, &ownerReports[i])
		}

		// For hash groups with multiple owners, merge coverage stats so the
		// index shows the combined coverage for each owner sharing the binary.
		for _, hg := range hashGroupMap {
			if len(hg.owners) <= 1 {
				continue
			}
			var texts []string
			for _, o := range hg.owners {
				if o.MergedCoverageText != "" {
					texts = append(texts, o.MergedCoverageText)
				}
			}
			mergedText := mergeCoverageTexts(texts)
			totalStmts, coveredStmts, coveragePct := parseCoverageText(mergedText)
			for _, o := range hg.owners {
				o.TotalStmts = totalStmts
				o.CoveredStmts = coveredStmts
				o.Coverage = coveragePct
			}
		}

		// Check cache for each hash group
		var toGenerate []*hashGroup
		for _, hg := range hashGroupMap {
			htmlFile := hg.hash + ".html"
			htmlPath := filepath.Join(renderOutputDir, htmlFile)

			// Compute combined cache key from sorted MergeInputHash values
			var hashes []string
			for _, o := range hg.owners {
				hashes = append(hashes, o.MergeInputHash)
			}
			sort.Strings(hashes)
			h := md5.New()
			for _, s := range hashes {
				io.WriteString(h, s)
			}
			hg.cacheKey = hex.EncodeToString(h.Sum(nil))

			existingHash := extractHTMLCoverageHash(htmlPath)
			if existingHash == hg.cacheKey {
				for _, o := range hg.owners {
					o.HTMLFile = htmlFile
					o.HasHTML = true
				}
				cachedCount++
				continue
			}

			toGenerate = append(toGenerate, hg)
		}

		totalGroups := int64(len(hashGroupMap))
		fmt.Printf("  %d hash groups: %d cached, %d skipped, %d to generate\n",
			totalGroups, cachedCount, skippedCount, len(toGenerate))

		// Generate in parallel
		sem := make(chan struct{}, maxConcurrency)
		var wg sync.WaitGroup
		var progress atomic.Int64

		for _, hg := range toGenerate {
			wg.Add(1)
			go func(hg *hashGroup) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				htmlFile := hg.hash + ".html"
				htmlPath := filepath.Join(renderOutputDir, htmlFile)

				syntheticOwner := buildSyntheticOwner(hg.owners, imageSources)
				syntheticOwner.HTMLFile = htmlFile // pre-set so generateHTMLForOwner uses this filename
				if err := generateHTMLForOwnerFromDB(collectionDir, syntheticOwner, imageSources); err != nil {
					n := progress.Add(1)
					fmt.Printf("[%d/%d] %s: %v\n", n+int64(cachedCount), totalGroups, htmlFile, err)
					atomic.AddInt64(&errorCount, 1)
				} else {
					appendCoverageHash(htmlPath, hg.cacheKey)

					for _, o := range hg.owners {
						o.HTMLFile = htmlFile
						o.HasHTML = true
					}
					n := progress.Add(1)
					atomic.AddInt64(&successCount, 1)
					fmt.Printf("[%d/%d] Generated: %s (%d owner groups)\n",
						n+int64(cachedCount), totalGroups, htmlFile, len(hg.owners))
				}
			}(hg)
		}

		wg.Wait()

		totalSuccess := successCount + cachedCount
		fmt.Printf("\nHTML reports: %d generated, %d cached, %d errors, %d skipped (total: %d/%d hash groups)\n\n",
			successCount, cachedCount, errorCount, skippedCount, totalSuccess, totalGroups)
	}

	// Generate index.html
	fmt.Println("Generating interactive index.html...")
	if err := generateOwnerIndexHTML(renderOutputDir, ownerReports); err != nil {
		return fmt.Errorf("generate index: %w", err)
	}

	indexPath := filepath.Join(renderOutputDir, "index.html")
	fmt.Printf("\nCoverage report index generated: %s\n", indexPath)

	// Clean up stale HTML files no longer referenced by the index
	validFiles := map[string]bool{"index.html": true}
	for _, o := range ownerReports {
		if o.HTMLFile != "" {
			validFiles[o.HTMLFile] = true
		}
	}
	entries, err := os.ReadDir(renderOutputDir)
	if err == nil {
		var removed int
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".html") {
				continue
			}
			if !validFiles[e.Name()] {
				os.Remove(filepath.Join(renderOutputDir, e.Name()))
				removed++
			}
		}
		if removed > 0 {
			fmt.Printf("Cleaned up %d stale HTML files\n", removed)
		}
	}

	fmt.Printf("\nOpen in browser:\n  xdg-open %s\n", indexPath)
	return nil
}

// loadOwnersForRender queries the owners table and returns OwnerReport structs.
func loadOwnersForRender(db *sql.DB) ([]OwnerReport, error) {
	rows, err := db.Query(`
		SELECT group_key, namespace, owner_type, owner_name, binary_name,
			image, pods_json, pod_count, containers_json, hosts_json,
			total_stmts, covered_stmts, coverage_pct,
			merged_coverage_text, merge_input_hash,
			first_seen, last_seen
		FROM owners
		ORDER BY namespace, owner_type, owner_name, binary_name, first_seen
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var owners []OwnerReport
	for rows.Next() {
		var (
			groupKey       string
			o              OwnerReport
			binaryName     string
			podsJSON       string
			containersJSON string
			hostsJSON      string
		)
		if err := rows.Scan(&groupKey, &o.Namespace, &o.OwnerType, &o.OwnerName,
			&binaryName, &o.Image, &podsJSON, &o.PodCount, &containersJSON, &hostsJSON,
			&o.TotalStmts, &o.CoveredStmts, &o.Coverage,
			&o.MergedCoverageText, &o.MergeInputHash,
			&o.FirstSeen, &o.LastSeen); err != nil {
			return nil, err
		}

		o.BinaryName = binaryName
		json.Unmarshal([]byte(podsJSON), &o.Pods)
		json.Unmarshal([]byte(containersJSON), &o.Containers)
		json.Unmarshal([]byte(hostsJSON), &o.Hosts)

		if o.Pods == nil {
			o.Pods = []string{}
		}
		if o.Containers == nil {
			o.Containers = []string{}
		}
		if o.Hosts == nil {
			o.Hosts = []string{}
		}

		owners = append(owners, o)
	}

	return owners, rows.Err()
}

// buildSyntheticOwner creates a synthetic OwnerReport that combines all owners in a
// hash group. The merged coverage text is the union of all owners' coverage data.
// The resulting owner has HashGroupOwners populated for the HTML template.
func buildSyntheticOwner(owners []*OwnerReport, imageSources map[string]imageSource) *OwnerReport {
	// Merge all coverage texts
	var texts []string
	for _, o := range owners {
		if o.MergedCoverageText != "" {
			texts = append(texts, o.MergedCoverageText)
		}
	}
	mergedText := mergeCoverageTexts(texts)

	// Collect all unique values
	podSet := make(map[string]bool)
	containerSet := make(map[string]bool)
	hostSet := make(map[string]bool)
	binaryName := ""
	for _, o := range owners {
		for _, p := range o.Pods {
			podSet[p] = true
		}
		for _, c := range o.Containers {
			containerSet[c] = true
		}
		for _, h := range o.Hosts {
			hostSet[h] = true
		}
		if binaryName == "" && o.BinaryName != "" {
			binaryName = o.BinaryName
		}
	}

	pods := make([]string, 0, len(podSet))
	for p := range podSet {
		pods = append(pods, p)
	}
	sort.Strings(pods)

	containers := make([]string, 0, len(containerSet))
	for c := range containerSet {
		containers = append(containers, c)
	}
	sort.Strings(containers)

	hosts := make([]string, 0, len(hostSet))
	for h := range hostSet {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	// Pick the best image for source resolution
	bestImage := ""
	for _, o := range owners {
		if o.Image == "" {
			continue
		}
		if bestImage == "" {
			bestImage = o.Image
		}
		// Prefer an image with a resolved source repo
		if src, ok := imageSources[o.Image]; ok && src.SourceRepo != "" {
			bestImage = o.Image
			break
		}
	}

	// Compute total stmts from merged text (not sum of individual owners)
	totalStmts, coveredStmts, coveragePct := parseCoverageText(mergedText)

	// Build hash group owner info for the collapsible details section
	hashGroupOwners := make([]HashGroupOwnerInfo, 0, len(owners))
	for _, o := range owners {
		hashGroupOwners = append(hashGroupOwners, HashGroupOwnerInfo{
			Namespace:  o.Namespace,
			OwnerType:  o.OwnerType,
			OwnerName:  o.OwnerName,
			BinaryName: o.BinaryName,
			Containers: strings.Join(o.Containers, ", "),
			Pods:       strings.Join(o.Pods, ", "),
			PodCount:   o.PodCount,
			Hosts:      strings.Join(o.Hosts, ", "),
		})
	}

	return &OwnerReport{
		Namespace:          owners[0].Namespace,
		OwnerType:          owners[0].OwnerType,
		OwnerName:          owners[0].OwnerName,
		Containers:         containers,
		PodCount:           len(pods),
		Pods:               pods,
		Hosts:              hosts,
		Coverage:           coveragePct,
		TotalStmts:         totalStmts,
		CoveredStmts:       coveredStmts,
		Image:              bestImage,
		MergedCoverageText: mergedText,
		BinaryName:         binaryName,
		HashGroupOwners:    hashGroupOwners,
	}
}

// generateHTMLForOwnerFromDB writes the merged coverage text from DB to a temp file,
// then runs the existing HTML generation pipeline.
func generateHTMLForOwnerFromDB(collectionDir string, owner *OwnerReport, imageSources map[string]imageSource) error {
	// Write merged coverage text to temp file
	tmpFile, err := os.CreateTemp("", "coverage-merged-*.out")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.WriteString(owner.MergedCoverageText); err != nil {
		tmpFile.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	tmpFile.Close()

	owner.MergedCovFile = tmpPath

	return generateHTMLForOwner(collectionDir, owner, imageSources)
}

// generateHTMLForOwner generates an HTML coverage report for an owner.
// It expects owner.MergedCovFile to be set to a file containing the merged coverage text.
func generateHTMLForOwner(collectionDir string, owner *OwnerReport, imageSources map[string]imageSource) error {
	reposDir := filepath.Join(collectionDir, "repos")
	var repoPath string

	// Extract package path from coverage (needed for path rewriting regardless of repo lookup strategy)
	packagePath := ""
	if owner.MergedCovFile != "" {
		packagePath = extractPackagePathFromCoverage(owner.MergedCovFile)
	}

	// Strategy 1: Find repo via image source labels (fast, O(1))
	if owner.Image != "" {
		if src, ok := imageSources[owner.Image]; ok {
			candidate := findRepoByImageSource(reposDir, src)
			if candidate != "" {
				// Validate: does the repo's module match the coverage package path?
				// Images can contain multiple binaries from different repos, so the
				// image label may point to the wrong repo for this binary.
				if packagePath != "" {
					modName := getModuleName(candidate)
					if modName != "" && !strings.HasPrefix(packagePath, modName) {
						// Check workspace modules too
						wsMods := parseGoWorkModules(candidate)
						matched := false
						if wsMods != nil {
							for mod := range wsMods {
								if strings.HasPrefix(packagePath, mod) {
									matched = true
									break
								}
							}
						}
						if !matched {
							fmt.Printf("  Image label repo %s (module %s) doesn't match package %s, trying other strategies\n",
								src.SourceRepo, modName, packagePath)
							candidate = ""
						}
					}
				}
				if candidate != "" {
					repoPath = candidate
					fmt.Printf("  Found repo via image labels: %s\n", src.SourceRepo)
				}
			}
		}
	}

	// Strategy 2: Find repo via package path matching (slower, walks repos/)
	if repoPath == "" && packagePath != "" {
		repoPath = findMatchingRepository(reposDir, packagePath)
	}

	// Strategy 3: Fallback by owner name (slowest, walks repos/)
	if repoPath == "" {
		repoPath = findRepoByOwnerName(reposDir, owner.OwnerName)
	}

	if repoPath == "" {
		return fmt.Errorf("no source repository found for package path")
	}

	// Check for go.work workspace (monorepo with multiple modules).
	// If the matched repo is a sub-module inside a workspace, walk up
	// to find the workspace root so all modules resolve correctly.
	workspaceModules := parseGoWorkModules(repoPath)
	if workspaceModules == nil {
		if wsRoot := findWorkspaceRoot(repoPath, reposDir); wsRoot != "" {
			workspaceModules = parseGoWorkModules(wsRoot)
			if workspaceModules != nil {
				repoPath = wsRoot
				fmt.Printf("  Found workspace root: %s\n", wsRoot)
			}
		}
	}

	moduleName := getModuleName(repoPath)
	covFileToUse := owner.MergedCovFile

	if workspaceModules == nil {
		// Non-workspace repo: use existing path rewrite logic
		needsRewrite := false
		rewriteOldPath := packagePath

		if moduleName != "" && packagePath != "" && !strings.HasPrefix(packagePath, moduleName) {
			needsRewrite = true
		}

		// Handle /workspace/ paths
		if !needsRewrite {
			if data, err := os.ReadFile(owner.MergedCovFile); err == nil {
				content := string(data)
				if strings.Contains(content, "/workspace/") && moduleName != "" {
					needsRewrite = true
					rewriteOldPath = "/workspace/"
				}
			}
		}

		// Handle /go/src/ prefixed paths
		if !needsRewrite {
			if data, err := os.ReadFile(owner.MergedCovFile); err == nil {
				if strings.Contains(string(data), "/go/src/") {
					needsRewrite = true
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
	} else {
		fmt.Printf("  go.work detected with %d workspace modules\n", len(workspaceModules))
	}

	// Generate custom HTML report
	// Use pre-set HTMLFile (e.g. hash-based name) if available, else compute from owner info
	htmlFile := owner.HTMLFile
	if htmlFile == "" {
		htmlFile = ownerHTMLFilename(owner)
	}

	absOutputDir, err := filepath.Abs(renderOutputDir)
	if err != nil {
		return fmt.Errorf("get absolute output dir: %w", err)
	}

	absOutputPath := filepath.Join(absOutputDir, htmlFile)

	fileReports, err := buildFileCoverageReports(covFileToUse, repoPath, moduleName, workspaceModules)
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

// ---------------------------------------------------------------------------
// Image source helpers
// ---------------------------------------------------------------------------

type imageSource struct {
	SourceRepo string
	CommitID   string
}

// loadImageSources loads the image→source mapping from the database.
func loadImageSources(db *sql.DB) (map[string]imageSource, error) {
	rows, err := db.Query("SELECT image, source_repo, commit_id FROM image_sources WHERE error_msg = '' AND source_repo != ''")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sources := make(map[string]imageSource)
	for rows.Next() {
		var img, repo, commit string
		if err := rows.Scan(&img, &repo, &commit); err != nil {
			return nil, err
		}
		sources[img] = imageSource{SourceRepo: repo, CommitID: commit}
	}
	return sources, rows.Err()
}

// findRepoByImageSource looks up a repo directory using the source repo URL
// and commit ID from image labels. This is O(1) — no directory walking.
func findRepoByImageSource(reposDir string, src imageSource) string {
	if src.SourceRepo == "" {
		return ""
	}

	u, err := url.Parse(src.SourceRepo)
	if err != nil || u.Host == "" {
		return ""
	}

	repoPath := filepath.Join(reposDir, u.Host, strings.TrimPrefix(u.Path, "/"))

	// Check if go.mod exists directly in repo path
	if _, err := os.Stat(filepath.Join(repoPath, "go.mod")); err == nil {
		return repoPath
	}

	// Check subdirectories (e.g., commit hash dirs from clone-sources)
	entries, err := os.ReadDir(repoPath)
	if err != nil {
		return ""
	}

	commitPrefix := ""
	if len(src.CommitID) >= 8 {
		commitPrefix = src.CommitID[:8]
	}

	var fallback string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		subPath := filepath.Join(repoPath, e.Name())
		if _, err := os.Stat(filepath.Join(subPath, "go.mod")); err != nil {
			continue
		}
		// Prefer commit-matching directory
		if commitPrefix != "" && strings.HasPrefix(e.Name(), commitPrefix) {
			return subPath
		}
		if fallback == "" {
			fallback = subPath
		}
	}

	return fallback
}

// ---------------------------------------------------------------------------
// Hash / cache helpers
// ---------------------------------------------------------------------------

// computeMultiFileMD5 computes a combined MD5 hash over multiple files
// (sorted by name for consistency). Returns "" on any error.
func computeMultiFileMD5(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	sorted := make([]string, len(paths))
	copy(sorted, paths)
	sort.Strings(sorted)

	h := md5.New()
	for _, p := range sorted {
		f, err := os.Open(p)
		if err != nil {
			return ""
		}
		if _, err := io.Copy(h, f); err != nil {
			f.Close()
			return ""
		}
		f.Close()
	}
	return hex.EncodeToString(h.Sum(nil))
}

// htmlCacheTag is the prefix used to embed coverage hashes in HTML files.
const htmlCacheTag = "<!-- coverage-hash: "

// extractHTMLCoverageHash reads the last few bytes of an HTML file looking
// for a coverage hash comment.
func extractHTMLCoverageHash(htmlPath string) string {
	f, err := os.Open(htmlPath)
	if err != nil {
		return ""
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || info.Size() < 50 {
		return ""
	}
	offset := info.Size() - 128
	if offset < 0 {
		offset = 0
	}
	buf := make([]byte, info.Size()-offset)
	if _, err := f.ReadAt(buf, offset); err != nil && err != io.EOF {
		return ""
	}

	content := string(buf)
	idx := strings.Index(content, htmlCacheTag)
	if idx < 0 {
		return ""
	}
	rest := content[idx+len(htmlCacheTag):]
	endIdx := strings.Index(rest, " -->")
	if endIdx < 0 {
		return ""
	}
	return rest[:endIdx]
}

// appendCoverageHash appends the coverage hash tag to an existing HTML file.
func appendCoverageHash(htmlPath, hash string) {
	f, err := os.OpenFile(htmlPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "\n%s%s -->\n", htmlCacheTag, hash)
}

// computeCovmetaHash computes a hash of the statement definitions in coverage text,
// ignoring execution counts. Owners with the same hash measure the same set of statements.
func computeCovmetaHash(coverageText string) string {
	if coverageText == "" {
		return ""
	}
	var stmtLines []string
	for _, line := range strings.Split(coverageText, "\n") {
		if strings.HasPrefix(line, "mode:") || line == "" {
			continue
		}
		// Strip the execution count (last space-separated field)
		if lastSpace := strings.LastIndex(line, " "); lastSpace > 0 {
			stmtLines = append(stmtLines, line[:lastSpace])
		}
	}
	sort.Strings(stmtLines)
	h := md5.New()
	for _, s := range stmtLines {
		io.WriteString(h, s)
		io.WriteString(h, "\n")
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ownerHTMLFilename returns the expected HTML filename for an owner report.
func ownerHTMLFilename(owner *OwnerReport) string {
	htmlBinaryLabel := ""
	if len(owner.Containers) > 0 {
		htmlBinaryLabel = "-" + owner.Containers[0]
	}
	commitSuffix := ""
	if owner.CommitID != "" {
		short := owner.CommitID
		if len(short) > 8 {
			short = short[:8]
		}
		commitSuffix = "-" + short
	}
	return fmt.Sprintf("%s-%s-%s%s%s.html",
		owner.Namespace, owner.OwnerType, owner.OwnerName, htmlBinaryLabel, commitSuffix)
}

// ---------------------------------------------------------------------------
// Source repository helpers
// ---------------------------------------------------------------------------

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

		parts := strings.Fields(line)
		if len(parts) > 0 {
			fileAndLine := parts[0]
			if idx := strings.Index(fileAndLine, ":"); idx > 0 {
				filePath := fileAndLine[:idx]

				if strings.HasPrefix(filePath, "/") && !strings.Contains(filePath, "/src/github.com/") {
					continue
				}

				if strings.Contains(filePath, "/src/github.com/") {
					if idx := strings.Index(filePath, "/src/"); idx >= 0 {
						filePath = filePath[idx+5:]
					}
				}

				if lastSlash := strings.LastIndex(filePath, "/"); lastSlash > 0 {
					return filePath[:lastSlash]
				}
			}
		}
	}
	return ""
}

func findMatchingRepository(reposDir, packagePath string) string {
	type repoCandidate struct {
		path       string
		moduleName string
		score      int
	}

	var candidates []repoCandidate

	packageParts := strings.Split(packagePath, "/")
	var packageRepoName string
	if len(packageParts) >= 3 {
		packageRepoName = packageParts[2]
	}

	filepath.Walk(reposDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() {
			return nil
		}

		goMod := filepath.Join(path, "go.mod")
		if _, err := os.Stat(goMod); err != nil {
			return nil
		}

		data, err := os.ReadFile(goMod)
		if err != nil {
			return nil
		}

		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "module ") {
				moduleName := strings.TrimSpace(strings.TrimPrefix(line, "module "))

				score := 0

				if strings.HasPrefix(packagePath, moduleName) {
					score = 100
				}

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

	if len(candidates) == 0 {
		return ""
	}

	bestCandidate := candidates[0]
	for _, c := range candidates {
		if c.score > bestCandidate.score {
			bestCandidate = c
		}
	}

	return bestCandidate.path
}

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

func extractModulePrefix(packagePath string) string {
	parts := strings.Split(packagePath, "/")
	if len(parts) >= 3 && parts[0] == "github.com" {
		return strings.Join(parts[:3], "/")
	}
	if len(parts) >= 2 {
		return strings.Join(parts[:2], "/")
	}
	return packagePath
}

// parseGoWorkModules parses go.work in repoPath and returns a map of
// moduleName → relativeDir for each workspace member. Returns nil if
// no go.work exists. This enables correct path resolution for monorepos
// like kubernetes where coverage data spans multiple modules.
func parseGoWorkModules(repoPath string) map[string]string {
	goWork := filepath.Join(repoPath, "go.work")
	data, err := os.ReadFile(goWork)
	if err != nil {
		return nil
	}

	moduleMap := make(map[string]string)
	inUseBlock := false

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "use (") {
			inUseBlock = true
			continue
		}
		if inUseBlock && line == ")" {
			inUseBlock = false
			continue
		}
		if strings.HasPrefix(line, "use ") && !strings.Contains(line, "(") {
			// Single-line use directive
			dir := strings.TrimSpace(strings.TrimPrefix(line, "use "))
			dir = strings.TrimPrefix(dir, "./")
			modName := getModuleName(filepath.Join(repoPath, dir))
			if modName != "" {
				moduleMap[modName] = dir
			}
			continue
		}
		if inUseBlock {
			dir := strings.TrimPrefix(line, "./")
			if dir == "" || strings.HasPrefix(dir, "//") {
				continue
			}
			modName := getModuleName(filepath.Join(repoPath, dir))
			if modName != "" {
				moduleMap[modName] = dir
			}
		}
	}

	if len(moduleMap) == 0 {
		return nil
	}
	return moduleMap
}

// findWorkspaceRoot walks up from repoPath looking for a parent directory
// that contains a go.work file, stopping at reposDir (the repos/ root).
// Returns the workspace root path, or "" if none found.
func findWorkspaceRoot(repoPath, reposDir string) string {
	absRepo, _ := filepath.Abs(repoPath)
	absRepos, _ := filepath.Abs(reposDir)

	dir := filepath.Dir(absRepo)
	for {
		// Don't walk above the repos directory
		if len(dir) <= len(absRepos) {
			break
		}
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// resolveWorkspacePath resolves a coverage file path (e.g. "k8s.io/api/admission/v1/types.go")
// to a repo-relative path (e.g. "staging/src/k8s.io/api/admission/v1/types.go") using
// the workspace module map. Returns "" if no matching module is found.
func resolveWorkspacePath(fileName string, moduleMap map[string]string) string {
	bestMod := ""
	bestDir := ""
	for mod, dir := range moduleMap {
		if strings.HasPrefix(fileName, mod+"/") || fileName == mod {
			if len(mod) > len(bestMod) {
				bestMod = mod
				bestDir = dir
			}
		}
	}
	if bestMod == "" {
		return ""
	}
	relPath := strings.TrimPrefix(fileName, bestMod)
	relPath = strings.TrimPrefix(relPath, "/")
	if bestDir == "." || bestDir == "" {
		return relPath
	}
	return filepath.Join(bestDir, relPath)
}

func rewriteCoveragePaths(coverageFile, oldPath, newPath string) (string, error) {
	data, err := os.ReadFile(coverageFile)
	if err != nil {
		return "", err
	}

	content := string(data)

	if oldPath == "/workspace/" {
		content = strings.ReplaceAll(content, "/workspace/", newPath+"/")
	} else {
		oldModulePrefix := extractModulePrefix(oldPath)
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

		dirParts := strings.Split(path, "/")
		if len(dirParts) < 2 {
			return nil
		}

		repoName := dirParts[len(dirParts)-2]

		score := 0
		ownerLower := strings.ToLower(ownerName)
		repoLower := strings.ToLower(repoName)

		if ownerLower == repoLower {
			score = 100
		} else if strings.Contains(repoLower, ownerLower) || strings.Contains(ownerLower, repoLower) {
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

// ---------------------------------------------------------------------------
// Index HTML generation
// ---------------------------------------------------------------------------

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
		"containerBinary": func(containers []string, binaryName string) string {
			c := strings.Join(containers, ", ")
			if c == "" {
				return binaryName
			}
			return c + " / " + binaryName
		},
		"shortCommit": func(commitID string) string {
			if len(commitID) > 8 {
				return commitID[:8]
			}
			return commitID
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

	// Deduplicate statement counts by covmeta hash so binaries shared
	// across multiple owners are counted only once in the overall total.
	seenHash := make(map[string]bool)

	for _, o := range owners {
		stats.TotalPods += o.PodCount
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

		// Only count stmts once per unique binary hash
		if o.CovmetaHash != "" && seenHash[o.CovmetaHash] {
			continue
		}
		if o.CovmetaHash != "" {
			seenHash[o.CovmetaHash] = true
		}
		stats.TotalStmts += o.TotalStmts
		stats.CoveredStmts += o.CoveredStmts
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
    <title>Coverage Report - By Owner</title>
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
            max-width: 98vw;
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
        .owner-type.pod-no-owner { background: #e2e3e5; color: #383d41; }
        .owner-type.Host { background: #fff3cd; color: #856404; }
        .namespace.na { background: #fff3cd; color: #856404; }

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

        .commit-hash {
            color: #888;
            font-size: 11px;
            font-weight: normal;
        }

        .container-cell {
            position: relative;
        }

        .container-cell .tooltip {
            display: none;
            position: absolute;
            bottom: 100%;
            left: 0;
            background: #333;
            color: #fff;
            padding: 6px 10px;
            border-radius: 4px;
            font-size: 11px;
            white-space: nowrap;
            z-index: 100;
            box-shadow: 0 2px 8px rgba(0,0,0,0.2);
        }

        .container-cell:hover .tooltip {
            display: block;
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

        .checkbox-filters {
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }

        .checkbox-filters label {
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 13px;
            color: #555;
            cursor: pointer;
            user-select: none;
        }

        .checkbox-filters input[type="checkbox"] {
            cursor: pointer;
        }

        .owner-row {
            cursor: pointer;
        }

        .owner-row:hover {
            background-color: #e8f0fe;
        }

        .owner-row.expanded {
            background-color: #e8f0fe;
        }

        .details-row td {
            padding: 0 !important;
            border-top: none !important;
        }

        .details-content {
            padding: 8px 16px 12px 32px;
            background: #f8f9fa;
            border-bottom: 2px solid #e0e0e0;
        }

        .details-table {
            border-collapse: collapse;
            font-size: 13px;
        }

        .details-table td {
            padding: 3px 12px 3px 0;
            border: none;
        }

        .details-label {
            color: #666;
            font-weight: 600;
            white-space: nowrap;
        }

        .details-value code {
            background: #e8e8e8;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 12px;
            word-break: break-all;
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
        <h1>Coverage Report - By Owner</h1>
        <div class="subtitle">Aggregated coverage by Deployment, DaemonSet, StatefulSet, Job, and Host</div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Owners</div>
                <div class="stat-value" id="statOwners">{{.Stats.TotalOwners}}</div>
            </div>
            <div class="stat-card secondary">
                <div class="stat-label">Overall Coverage</div>
                <div class="stat-value" id="statCoverage">{{formatPct .Stats.OverallCoverage}}</div>
            </div>
            <div class="stat-card tertiary">
                <div class="stat-label">Unique Statements</div>
                <div class="stat-value" id="statStmts">—</div>
            </div>
        </div>

        <div class="coverage-distribution">
            <div class="coverage-badge badge-excellent">
                <span>Excellent (≥70%)</span>
                <span class="count" id="badgeExcellent">{{.Stats.Excellent}}</span>
            </div>
            <div class="coverage-badge badge-good">
                <span>Good (50-69%)</span>
                <span class="count" id="badgeGood">{{.Stats.Good}}</span>
            </div>
            <div class="coverage-badge badge-moderate">
                <span>Moderate (30-49%)</span>
                <span class="count" id="badgeModerate">{{.Stats.Moderate}}</span>
            </div>
            <div class="coverage-badge badge-poor">
                <span>Poor (15-29%)</span>
                <span class="count" id="badgePoor">{{.Stats.Poor}}</span>
            </div>
            <div class="coverage-badge badge-critical">
                <span>Critical (<15%)</span>
                <span class="count" id="badgeCritical">{{.Stats.Critical}}</span>
            </div>
        </div>

        <div class="controls">
            <div class="search-box">
                <input type="text" id="searchBox" placeholder="Search namespace or owner name...">
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
                <option value="Pod (No Owner)">Pods (No Owner)</option>
                <option value="Host">Host</option>
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

        <div class="checkbox-filters">
            <label><input type="checkbox" id="hideTestBinaries" checked> Hide openshift-tests entries</label>
            <label><input type="checkbox" id="hideE2eNamespaces" checked> Hide e2e-* namespace entries</label>
            <label><input type="checkbox" id="hideMustGatherNamespaces" checked> Hide openshift-must-gather-* namespace entries</label>
        </div>

        <div id="filterInfo" class="filter-info"></div>

        <table id="ownersTable">
            <thead>
                <tr>
                    <th class="sortable" data-sort="namespace">Namespace</th>
                    <th class="sortable" data-sort="owner">Owner</th>
                    <th class="sortable" data-sort="container">Container / Binary</th>
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
                    data-binary="{{.BinaryName}}"
                    data-pods="{{.PodCount}}"
                    data-coverage="{{.Coverage}}"
                    data-statements="{{.TotalStmts}}"
                    data-covered-stmts="{{.CoveredStmts}}"
                    data-image="{{.Image}}"
                    data-covmeta-hash="{{.CovmetaHash}}"
                    data-coverage-class="{{colorClass .Coverage}}"
                    data-first-seen="{{.FirstSeen}}"
                    class="owner-row">
                    <td>{{if ne .OwnerType "Host"}}<span class="namespace{{if eq .Namespace "host"}} na{{end}}">{{.Namespace}}</span>{{end}}</td>
                    <td>
                        <span class="owner-type {{if eq .OwnerType "Pod (No Owner)"}}pod-no-owner{{else}}{{.OwnerType}}{{end}}">{{.OwnerType}}</span>
                        {{if and (ne .OwnerType "Host") (ne .OwnerType "Pod (No Owner)")}}<strong>{{.OwnerName}}</strong>{{end}}
                    </td>
                    <td class="container-cell">
                        {{if eq .OwnerType "Host"}}<code class="containers">/ {{.BinaryName}}</code>
                        {{else}}<code class="containers">{{containerBinary .Containers .BinaryName}}{{if .CommitID}} <span class="commit-hash">({{shortCommit .CommitID}})</span>{{end}}</code>
                        {{if or .FirstSeen .LastSeen}}<div class="tooltip">{{if .FirstSeen}}First seen: {{.FirstSeen}}{{end}}{{if and .FirstSeen .LastSeen}}<br>{{end}}{{if .LastSeen}}Last seen: {{.LastSeen}}{{end}}</div>{{end}}{{end}}
                    </td>
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
                        <a href="{{.HTMLFile}}" target="_blank">View HTML</a>
                        {{else}}
                        <span class="no-html">No HTML</span>
                        {{end}}
                    </td>
                </tr>
                <tr class="details-row" style="display:none">
                    <td colspan="6">
                        <div class="details-content">
                            <table class="details-table">
                                {{if .Image}}<tr><td class="details-label">Image</td><td class="details-value"><code>{{.Image}}</code></td></tr>{{end}}
                                {{if .CovmetaHash}}<tr><td class="details-label">Binary Hash</td><td class="details-value"><code>{{.CovmetaHash}}</code></td></tr>{{end}}
                                {{if .Hosts}}<tr><td class="details-label">Hosts</td><td class="details-value">{{joinContainers .Hosts}}</td></tr>{{end}}
                            </table>
                        </div>
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
        const hideTestBinaries = document.getElementById('hideTestBinaries');
        const hideE2eNamespaces = document.getElementById('hideE2eNamespaces');
        const hideMustGatherNamespaces = document.getElementById('hideMustGatherNamespaces');
        const filterInfo = document.getElementById('filterInfo');
        const table = document.getElementById('ownersTable');
        const rows = table.querySelectorAll('tbody tr.owner-row');

        function covClass(pct) {
            if (pct >= 70) return 'excellent';
            if (pct >= 50) return 'good';
            if (pct >= 30) return 'moderate';
            if (pct >= 15) return 'poor';
            return 'critical';
        }

        function updateStats() {
            let owners = 0;
            let excellent = 0, good = 0, moderate = 0, poor = 0, critical = 0;
            const seenHashes = new Set();
            let uniqueStmts = 0, uniqueCovered = 0;

            rows.forEach(row => {
                if (row.style.display === 'none') return;
                owners++;

                // Deduplicate by covmeta hash for overall stats
                const hash = row.dataset.covmetaHash;
                if (hash && !seenHashes.has(hash)) {
                    seenHashes.add(hash);
                    uniqueStmts += parseInt(row.dataset.statements) || 0;
                    uniqueCovered += parseInt(row.dataset.coveredStmts) || 0;
                } else if (!hash) {
                    uniqueStmts += parseInt(row.dataset.statements) || 0;
                    uniqueCovered += parseInt(row.dataset.coveredStmts) || 0;
                }

                const cls = row.dataset.coverageClass;
                if (cls === 'excellent') excellent++;
                else if (cls === 'good') good++;
                else if (cls === 'moderate') moderate++;
                else if (cls === 'poor') poor++;
                else critical++;
            });

            const pct = uniqueStmts > 0 ? (uniqueCovered / uniqueStmts * 100) : 0;
            document.getElementById('statOwners').textContent = owners.toLocaleString();
            document.getElementById('statCoverage').textContent = pct.toFixed(1) + '%';
            document.getElementById('statStmts').textContent = uniqueStmts.toLocaleString();
            document.getElementById('badgeExcellent').textContent = excellent;
            document.getElementById('badgeGood').textContent = good;
            document.getElementById('badgeModerate').textContent = moderate;
            document.getElementById('badgePoor').textContent = poor;
            document.getElementById('badgeCritical').textContent = critical;
        }

        function applyFilters() {
            const searchTerm = searchBox.value.toLowerCase();
            const selectedNamespace = namespaceFilter.value;
            const selectedOwnerType = ownerTypeFilter.value;
            const selectedCoverage = coverageFilter.value;
            const hideTests = hideTestBinaries.checked;
            const hideE2e = hideE2eNamespaces.checked;
            const hideMustGather = hideMustGatherNamespaces.checked;

            let visibleCount = 0;
            let anyFilter = searchTerm || selectedNamespace || selectedOwnerType || selectedCoverage || hideTests || hideE2e || hideMustGather;

            rows.forEach(row => {
                const namespace = row.dataset.namespace;
                const namespaceLower = namespace.toLowerCase();
                const owner = row.dataset.owner.toLowerCase();
                const container = row.dataset.container.toLowerCase();
                const binary = row.dataset.binary.toLowerCase();
                const ownerType = row.dataset.ownerType;
                const coverageClass = row.dataset.coverageClass;

                const matchesSearch = !searchTerm ||
                    namespaceLower.includes(searchTerm) ||
                    owner.includes(searchTerm) ||
                    container.includes(searchTerm) ||
                    binary.includes(searchTerm);

                const matchesNamespace = !selectedNamespace ||
                    namespace === selectedNamespace;

                const matchesOwnerType = !selectedOwnerType ||
                    ownerType === selectedOwnerType;

                const matchesCoverage = !selectedCoverage ||
                    coverageClass === selectedCoverage;

                const matchesTestFilter = !hideTests ||
                    binary !== 'openshift-tests';

                const matchesE2eFilter = !hideE2e ||
                    !namespace.startsWith('e2e-');

                const matchesMustGatherFilter = !hideMustGather ||
                    !namespace.startsWith('openshift-must-gather-');

                if (matchesSearch && matchesNamespace && matchesOwnerType && matchesCoverage && matchesTestFilter && matchesE2eFilter && matchesMustGatherFilter) {
                    row.style.display = '';
                    visibleCount++;
                } else {
                    row.style.display = 'none';
                    // Collapse details row when owner is filtered out
                    if (row._detailsRow) {
                        row._detailsRow.style.display = 'none';
                        row.classList.remove('expanded');
                    }
                }
            });

            // Update filter info
            if (anyFilter) {
                filterInfo.classList.add('active');
                filterInfo.textContent = 'Showing ' + visibleCount + ' of ' + rows.length + ' owners';
            } else {
                filterInfo.classList.remove('active');
            }

            updateStats();
        }

        searchBox.addEventListener('input', applyFilters);
        namespaceFilter.addEventListener('change', applyFilters);
        ownerTypeFilter.addEventListener('change', applyFilters);
        coverageFilter.addEventListener('change', applyFilters);
        hideTestBinaries.addEventListener('change', applyFilters);
        hideE2eNamespaces.addEventListener('change', applyFilters);
        hideMustGatherNamespaces.addEventListener('change', applyFilters);

        // Cache each owner row's details row reference
        rows.forEach(row => {
            const next = row.nextElementSibling;
            if (next && next.classList.contains('details-row')) {
                row._detailsRow = next;
            }
        });

        // Apply default filters on page load
        applyFilters();

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

                if (column === 'coverage' || column === 'statements') {
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
                // Tiebreaker: sort by first_seen ascending
                const aFS = a.dataset.firstSeen || '';
                const bFS = b.dataset.firstSeen || '';
                if (aFS < bFS) return -1;
                if (aFS > bFS) return 1;
                return 0;
            });

            rowsArray.forEach(row => {
                const detailsRow = row._detailsRow;
                tbody.appendChild(row);
                if (detailsRow) tbody.appendChild(detailsRow);
            });
        }


        // Row expand/collapse
        document.querySelectorAll('.owner-row').forEach(row => {
            row.addEventListener('click', (e) => {
                // Don't toggle if clicking a link
                if (e.target.tagName === 'A') return;
                const detailsRow = row.nextElementSibling;
                if (!detailsRow || !detailsRow.classList.contains('details-row')) return;
                const isExpanded = row.classList.toggle('expanded');
                detailsRow.style.display = isExpanded ? '' : 'none';
            });
        });

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
