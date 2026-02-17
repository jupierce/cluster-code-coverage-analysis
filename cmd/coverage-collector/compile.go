package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	_ "modernc.org/sqlite"
)

var (
	updateFilters []string

	compileCmd = &cobra.Command{
		Use:   "compile",
		Short: "Process coverage data into SQLite database",
		Long: `Process raw coverage data (covmeta/covcounters files) into an SQLite database.

The compile step:
  - Runs 'go tool covdata textfmt' to convert binary coverage to text
  - Filters out coverage_server.go lines
  - Computes per-report and per-owner coverage statistics
  - Merges coverage from multiple pods of the same owner
  - Stores everything in an SQLite database for efficient rendering

Change detection uses MD5 hashes of input files. Only changed reports are
reprocessed. Use --update to force recomputation of specific entries.`,
		Example: `  # Compile all coverage data (incremental)
  coverage-collector cluster compile --cluster my-cluster

  # Force full recompilation
  coverage-collector cluster compile --cluster my-cluster --update '*'

  # Force recompilation for a namespace
  coverage-collector cluster compile --cluster my-cluster --update 'namespace=openshift-apiserver'

  # Force recompilation with multiple filters (AND logic)
  coverage-collector cluster compile --cluster my-cluster \
    --update 'namespace=openshift-*' --update 'container=machine-config*'`,
		RunE: runCompile,
	}
)

func init() {
	compileCmd.Flags().StringArrayVar(&updateFilters, "update", nil,
		"Force recomputation for matching entries (repeatable, AND logic). "+
			"Supported: namespace=<glob>, node=<glob>, container=<glob>, image=<glob>, or '*' for all")
	clusterCmd.AddCommand(compileCmd)
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const schemaVersion = 4

func createSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);

		CREATE TABLE IF NOT EXISTS report_sources (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			dir_name        TEXT NOT NULL UNIQUE,
			input_hash      TEXT NOT NULL,
			namespace       TEXT NOT NULL DEFAULT '',
			pod_name        TEXT NOT NULL DEFAULT '',
			container_name  TEXT NOT NULL DEFAULT '',
			image           TEXT NOT NULL DEFAULT '',
			binary_name     TEXT NOT NULL DEFAULT '',
			collected_at    TEXT NOT NULL DEFAULT '',
			hostname        TEXT NOT NULL DEFAULT '',
			is_host         INTEGER NOT NULL DEFAULT 0,
			total_stmts     INTEGER NOT NULL DEFAULT 0,
			covered_stmts   INTEGER NOT NULL DEFAULT 0,
			coverage_pct    REAL NOT NULL DEFAULT 0.0,
			coverage_text   TEXT NOT NULL DEFAULT '',
			error_msg       TEXT NOT NULL DEFAULT ''
		);

		CREATE TABLE IF NOT EXISTS owners (
			id                   INTEGER PRIMARY KEY AUTOINCREMENT,
			group_key            TEXT NOT NULL UNIQUE,
			namespace            TEXT NOT NULL,
			owner_type           TEXT NOT NULL,
			owner_name           TEXT NOT NULL,
			binary_name          TEXT NOT NULL DEFAULT '',
			image                TEXT NOT NULL DEFAULT '',
			pods_json            TEXT NOT NULL DEFAULT '[]',
			pod_count            INTEGER NOT NULL DEFAULT 0,
			containers_json      TEXT NOT NULL DEFAULT '[]',
			hosts_json           TEXT NOT NULL DEFAULT '[]',
			total_stmts          INTEGER NOT NULL DEFAULT 0,
			covered_stmts        INTEGER NOT NULL DEFAULT 0,
			coverage_pct         REAL NOT NULL DEFAULT 0.0,
			merged_coverage_text TEXT NOT NULL DEFAULT '',
			merge_input_hash     TEXT NOT NULL DEFAULT '',
			first_seen           TEXT NOT NULL DEFAULT '',
			last_seen            TEXT NOT NULL DEFAULT ''
		);

		CREATE TABLE IF NOT EXISTS owner_reports (
			owner_id  INTEGER NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
			report_id INTEGER NOT NULL REFERENCES report_sources(id) ON DELETE CASCADE,
			PRIMARY KEY (owner_id, report_id)
		);

		CREATE TABLE IF NOT EXISTS owner_file_stats (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			owner_id    INTEGER NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
			file_path   TEXT NOT NULL,
			total_stmts INTEGER NOT NULL DEFAULT 0,
			covered_stmts INTEGER NOT NULL DEFAULT 0,
			coverage_pct REAL NOT NULL DEFAULT 0.0
		);

		CREATE TABLE IF NOT EXISTS image_sources (
			image           TEXT PRIMARY KEY,
			source_repo     TEXT NOT NULL DEFAULT '',
			commit_id       TEXT NOT NULL DEFAULT '',
			inspected_at    TEXT NOT NULL DEFAULT '',
			error_msg       TEXT NOT NULL DEFAULT ''
		);

		CREATE INDEX IF NOT EXISTS idx_report_sources_namespace ON report_sources(namespace);
		CREATE INDEX IF NOT EXISTS idx_report_sources_hostname ON report_sources(hostname);
		CREATE INDEX IF NOT EXISTS idx_report_sources_container ON report_sources(container_name);
		CREATE INDEX IF NOT EXISTS idx_report_sources_image ON report_sources(image);
		CREATE INDEX IF NOT EXISTS idx_owner_file_stats_owner ON owner_file_stats(owner_id);
	`)
	if err != nil {
		return fmt.Errorf("create schema: %w", err)
	}

	// Ensure schema version is set
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM schema_version").Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		_, err = db.Exec("INSERT INTO schema_version (version) VALUES (?)", schemaVersion)
		return err
	}

	// Migrate if needed
	var currentVersion int
	if err := db.QueryRow("SELECT version FROM schema_version").Scan(&currentVersion); err != nil {
		return err
	}
	if currentVersion < 2 {
		// v1 → v2: add image column to owners table (image_sources table created above)
		_, alterErr := db.Exec("ALTER TABLE owners ADD COLUMN image TEXT NOT NULL DEFAULT ''")
		if alterErr != nil && !strings.Contains(alterErr.Error(), "duplicate column") {
			return fmt.Errorf("migrate v1→v2: %w", alterErr)
		}
	}
	if currentVersion < 3 {
		// v2 → v3: add first_seen, last_seen columns to owners table
		for _, col := range []string{"first_seen", "last_seen"} {
			_, alterErr := db.Exec(fmt.Sprintf("ALTER TABLE owners ADD COLUMN %s TEXT NOT NULL DEFAULT ''", col))
			if alterErr != nil && !strings.Contains(alterErr.Error(), "duplicate column") {
				return fmt.Errorf("migrate v2→v3 (%s): %w", col, alterErr)
			}
		}
	}
	if currentVersion < 4 {
		// v3 → v4: add hosts_json column to owners table
		_, alterErr := db.Exec("ALTER TABLE owners ADD COLUMN hosts_json TEXT NOT NULL DEFAULT '[]'")
		if alterErr != nil && !strings.Contains(alterErr.Error(), "duplicate column") {
			return fmt.Errorf("migrate v3→v4: %w", alterErr)
		}
	}
	if currentVersion < schemaVersion {
		if _, err := db.Exec("UPDATE schema_version SET version = ?", schemaVersion); err != nil {
			return err
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Update filters
// ---------------------------------------------------------------------------

type updateFilter struct {
	field   string // "namespace", "node", "container", "image"
	pattern string // glob pattern
}

func parseUpdateFilterFlags(flags []string) ([]updateFilter, bool, error) {
	if len(flags) == 0 {
		return nil, false, nil
	}

	for _, f := range flags {
		if f == "*" {
			return nil, true, nil
		}
	}

	var filters []updateFilter
	for _, f := range flags {
		eqIdx := strings.Index(f, "=")
		if eqIdx < 0 {
			return nil, false, fmt.Errorf("invalid --update flag %q: expected field=pattern", f)
		}
		field := f[:eqIdx]
		pattern := f[eqIdx+1:]

		switch field {
		case "namespace", "node", "container", "image":
		default:
			return nil, false, fmt.Errorf("unknown --update field %q: expected namespace, node, container, or image", field)
		}
		filters = append(filters, updateFilter{field: field, pattern: pattern})
	}

	return filters, false, nil
}

// matchesFilters returns true if ALL filters match the given report metadata.
func matchesFilters(filters []updateFilter, forceAll bool,
	namespace, hostname, container, image string) bool {

	if forceAll {
		return true
	}
	if len(filters) == 0 {
		return false
	}

	for _, f := range filters {
		var value string
		switch f.field {
		case "namespace":
			value = namespace
		case "node":
			value = hostname
		case "container":
			value = container
		case "image":
			value = image
		}
		matched, _ := filepath.Match(f.pattern, value)
		if !matched {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Report metadata reading
// ---------------------------------------------------------------------------

type reportMetadata struct {
	PodName     string
	Namespace   string
	Container   string
	Image       string
	BinaryName  string
	CollectedAt string
	Hostname    string
	IsHost      bool
}

func readReportMetadata(reportDir string) reportMetadata {
	metadataFile := filepath.Join(reportDir, "metadata.json")
	data, err := os.ReadFile(metadataFile)
	if err != nil {
		return reportMetadata{}
	}

	var raw struct {
		PodName     string `json:"pod_name"`
		Namespace   string `json:"namespace"`
		Container   struct {
			Name  string `json:"name"`
			Image string `json:"image"`
		} `json:"container"`
		CollectedAt string `json:"collected_at"`
		BinaryName  string `json:"binary_name"`
		Hostname    string `json:"hostname"`
		HostProcess bool   `json:"host_process"`
		TestName    string `json:"test_name"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return reportMetadata{}
	}

	m := reportMetadata{
		PodName:     raw.PodName,
		Namespace:   raw.Namespace,
		Container:   raw.Container.Name,
		Image:       raw.Container.Image,
		BinaryName:  raw.BinaryName,
		CollectedAt: raw.CollectedAt,
		Hostname:    raw.Hostname,
		IsHost:      raw.HostProcess,
	}

	// Fallback: old metadata format had test_name but no binary_name
	if m.BinaryName == "" && raw.TestName != "" {
		// Extract binary name from test_name (last component after splitting by '-')
		// This is a best-effort fallback
	}

	return m
}

// ---------------------------------------------------------------------------
// Hash computation
// ---------------------------------------------------------------------------

func computeReportInputHash(reportDir string) string {
	entries, err := os.ReadDir(reportDir)
	if err != nil {
		return ""
	}

	var covFiles []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "covmeta.") || strings.HasPrefix(e.Name(), "covcounters.") {
			covFiles = append(covFiles, filepath.Join(reportDir, e.Name()))
		}
	}

	return computeMultiFileMD5(covFiles)
}

// ---------------------------------------------------------------------------
// Coverage processing
// ---------------------------------------------------------------------------

// filterCoverageServerLines filters out coverage_server.go lines from coverage text
func filterCoverageServerLines(text string) string {
	lines := strings.Split(text, "\n")
	var filtered []string
	for _, line := range lines {
		if !strings.Contains(line, "coverage_server.go") {
			filtered = append(filtered, line)
		}
	}
	return strings.Join(filtered, "\n")
}

// parseCoverageText parses coverage text and returns total stmts, covered stmts, coverage pct
func parseCoverageText(text string) (totalStmts, coveredStmts int, coveragePct float64) {
	for _, line := range strings.Split(text, "\n") {
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
		totalStmts += stmtCount
		if execCount > 0 {
			coveredStmts += stmtCount
		}
	}
	if totalStmts > 0 {
		coveragePct = float64(coveredStmts) / float64(totalStmts) * 100
	}
	return
}

// processReport runs textfmt and returns the filtered coverage text.
func processReport(reportDir string) (string, error) {
	// Check for covmeta files
	entries, err := os.ReadDir(reportDir)
	if err != nil {
		return "", fmt.Errorf("read dir: %w", err)
	}

	hasCovData := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "covmeta.") {
			hasCovData = true
			break
		}
	}

	if !hasCovData {
		// Try to read existing coverage.out
		rawFile := filepath.Join(reportDir, "coverage.out")
		data, err := os.ReadFile(rawFile)
		if err != nil {
			return "", fmt.Errorf("no coverage data found")
		}
		return filterCoverageServerLines(string(data)), nil
	}

	// Run textfmt
	rawFile := filepath.Join(reportDir, "coverage.out")
	cmd := exec.Command("go", "tool", "covdata", "textfmt",
		"-i="+reportDir,
		"-o="+rawFile)
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("textfmt failed: %v (%s)", err, strings.TrimSpace(string(output)))
	}

	data, err := os.ReadFile(rawFile)
	if err != nil {
		return "", fmt.Errorf("read textfmt output: %w", err)
	}

	return filterCoverageServerLines(string(data)), nil
}

// ---------------------------------------------------------------------------
// Owner detection (moved from render.go)
// ---------------------------------------------------------------------------

func extractOwnerInfoCompile(podName string) (ownerType, ownerName string) {
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

	return "Pod", podName
}

// ---------------------------------------------------------------------------
// Coverage merging
// ---------------------------------------------------------------------------

// CoverageLineCompile represents a single coverage block for merging.
type CoverageLineCompile struct {
	Block   string
	NumStmt int
	Count   int
}

// mergeCoverageTexts merges multiple coverage texts (max count per block).
func mergeCoverageTexts(texts []string) string {
	coverageMap := make(map[string]CoverageLineCompile)
	var mode string

	for _, text := range texts {
		scanner := bufio.NewScanner(strings.NewReader(text))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "mode:") {
				if mode == "" {
					mode = strings.TrimPrefix(line, "mode: ")
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
				if count > existing.Count {
					existing.Count = count
					coverageMap[block] = existing
				}
			} else {
				coverageMap[block] = CoverageLineCompile{
					Block:   block,
					NumStmt: numStmt,
					Count:   count,
				}
			}
		}
	}

	if mode == "" {
		mode = "set"
	}

	var keys []string
	for key := range coverageMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var sb strings.Builder
	fmt.Fprintf(&sb, "mode: %s\n", mode)
	for _, key := range keys {
		line := coverageMap[key]
		fmt.Fprintf(&sb, "%s %d %d\n", line.Block, line.NumStmt, line.Count)
	}

	return sb.String()
}

// computePerFileStats parses merged coverage text and returns per-file stats.
type fileStats struct {
	FilePath    string
	TotalStmts  int
	CoveredStmts int
	CoveragePct float64
}

func computePerFileStats(text string) []fileStats {
	fileMap := make(map[string]*fileStats)

	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "mode:") || line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		fileAndLine := parts[0]
		colonIdx := strings.Index(fileAndLine, ":")
		if colonIdx <= 0 {
			continue
		}
		filePath := fileAndLine[:colonIdx]

		var stmtCount, execCount int
		fmt.Sscanf(parts[1], "%d", &stmtCount)
		fmt.Sscanf(parts[2], "%d", &execCount)

		fs, exists := fileMap[filePath]
		if !exists {
			fs = &fileStats{FilePath: filePath}
			fileMap[filePath] = fs
		}
		fs.TotalStmts += stmtCount
		if execCount > 0 {
			fs.CoveredStmts += stmtCount
		}
	}

	var result []fileStats
	for _, fs := range fileMap {
		if fs.TotalStmts > 0 {
			fs.CoveragePct = float64(fs.CoveredStmts) / float64(fs.TotalStmts) * 100
		}
		result = append(result, *fs)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].FilePath < result[j].FilePath
	})

	return result
}

// ---------------------------------------------------------------------------
// Image inspection
// ---------------------------------------------------------------------------

// inspectImages queries distinct images from report_sources and inspects them
// using 'oc image info' to extract source repository labels.
func inspectImages(db *sql.DB) error {
	// Check if 'oc' is available
	if _, err := exec.LookPath("oc"); err != nil {
		fmt.Println("  'oc' command not found — skipping image inspection")
		return nil
	}

	// Get distinct images from non-host report sources
	rows, err := db.Query(`
		SELECT DISTINCT image FROM report_sources
		WHERE is_host = 0 AND image != ''
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var images []string
	for rows.Next() {
		var img string
		rows.Scan(&img)
		images = append(images, img)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if len(images) == 0 {
		fmt.Println("  No images to inspect")
		return nil
	}

	// Filter out already-inspected images (with no error)
	var toInspect []string
	for _, img := range images {
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM image_sources WHERE image = ? AND error_msg = ''", img).Scan(&count)
		if err != nil || count == 0 {
			toInspect = append(toInspect, img)
		}
	}

	fmt.Printf("  Found %d unique images (%d already inspected)\n", len(images), len(images)-len(toInspect))

	if len(toInspect) == 0 {
		return nil
	}

	inspectedCount := 0
	errorCount := 0

	for _, img := range toInspect {
		// Unsanitize: S3 paths replace /, @, : with dashes
		imageRef := unsanitizeImageRef(img)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cmd := exec.CommandContext(ctx, "oc", "image", "info", imageRef, "-o", "json")
		output, err := cmd.CombinedOutput()
		cancel()

		if err != nil {
			fmt.Printf("  Error inspecting %s: %v\n", truncateImageRef(img), err)
			db.Exec(`
				INSERT INTO image_sources (image, error_msg, inspected_at)
				VALUES (?, ?, datetime('now'))
				ON CONFLICT(image) DO UPDATE SET
					error_msg = excluded.error_msg,
					inspected_at = excluded.inspected_at
			`, img, fmt.Sprintf("%v: %s", err, strings.TrimSpace(string(output))))
			errorCount++
			continue
		}

		// Parse JSON response from 'oc image info -o json'
		var info struct {
			Config struct {
				Config struct {
					Labels map[string]string `json:"Labels"`
				} `json:"config"`
			} `json:"config"`
		}
		if err := json.Unmarshal(output, &info); err != nil {
			fmt.Printf("  Error parsing JSON for %s: %v\n", truncateImageRef(img), err)
			db.Exec(`
				INSERT INTO image_sources (image, error_msg, inspected_at)
				VALUES (?, ?, datetime('now'))
				ON CONFLICT(image) DO UPDATE SET
					error_msg = excluded.error_msg,
					inspected_at = excluded.inspected_at
			`, img, fmt.Sprintf("parse JSON: %v", err))
			errorCount++
			continue
		}

		sourceRepo := info.Config.Config.Labels["io.openshift.build.source-location"]
		commitID := info.Config.Config.Labels["io.openshift.build.commit.id"]

		db.Exec(`
			INSERT INTO image_sources (image, source_repo, commit_id, inspected_at, error_msg)
			VALUES (?, ?, ?, datetime('now'), '')
			ON CONFLICT(image) DO UPDATE SET
				source_repo = excluded.source_repo,
				commit_id = excluded.commit_id,
				inspected_at = excluded.inspected_at,
				error_msg = ''
		`, img, sourceRepo, commitID)

		inspectedCount++
		if sourceRepo != "" {
			fmt.Printf("  [%d/%d] %s → %s @ %s\n", inspectedCount+errorCount, len(toInspect),
				truncateImageRef(img), sourceRepo, truncateCommit(commitID))
		} else {
			fmt.Printf("  [%d/%d] %s → no source labels\n", inspectedCount+errorCount, len(toInspect),
				truncateImageRef(img))
		}
	}

	fmt.Printf("  Inspected: %d, Errors: %d\n", inspectedCount, errorCount)
	return nil
}

// unsanitizeImageRef converts a sanitized image reference (where /, @, : are
// replaced with -) back to a valid container image reference.
//
// Sanitized format from S3 paths:
//
//	quay.io-openshift-release-dev-ocp-v4.0-art-dev-sha256-<64hex>
//
// Original format:
//
//	quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:<64hex>
var digestSuffixRe = regexp.MustCompile(`-sha256-([a-f0-9]{64})$`)

// knownRegistryPrefixes maps sanitized registry+org prefixes to their unsanitized form.
// Each entry: "sanitized-prefix" → "registry/org/"
var knownRegistryPrefixes = []struct {
	sanitized   string
	unsanitized string
}{
	{"quay.io-openshift-release-dev-", "quay.io/openshift-release-dev/"},
	{"registry.ci.openshift.org-ocp-", "registry.ci.openshift.org/ocp/"},
}

func unsanitizeImageRef(sanitized string) string {
	// First, extract the sha256 digest from the end
	dm := digestSuffixRe.FindStringSubmatchIndex(sanitized)
	if dm == nil {
		return sanitized // no sha256 digest found
	}

	digest := sanitized[dm[2]:dm[3]]
	prefix := sanitized[:dm[0]] // everything before -sha256-HASH

	// Try known registry+org prefixes
	for _, known := range knownRegistryPrefixes {
		if strings.HasPrefix(prefix, known.sanitized) {
			repo := strings.TrimPrefix(prefix, known.sanitized)
			return fmt.Sprintf("%s%s@sha256:%s", known.unsanitized, repo, digest)
		}
	}

	return sanitized
}

// truncateImageRef shortens an image reference for display.
func truncateImageRef(img string) string {
	if idx := strings.LastIndex(img, "/"); idx >= 0 {
		return "..." + img[idx:]
	}
	return img
}

// truncateCommit shortens a commit hash for display.
func truncateCommit(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}

// ---------------------------------------------------------------------------
// Main compile flow
// ---------------------------------------------------------------------------

func runCompile(cmd *cobra.Command, args []string) error {
	clusterDir := clusterName
	coverageDir := filepath.Join(clusterDir, "coverage")

	// Parse update filters
	filters, forceAll, err := parseUpdateFilterFlags(updateFilters)
	if err != nil {
		return err
	}

	fmt.Printf("Compiling coverage data for cluster: %s\n", clusterName)

	// Open/create SQLite database
	dbPath := filepath.Join(clusterDir, "coverage.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)")
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	if err := createSchema(db); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}

	// Phase 1: Ingest reports
	fmt.Println("\nPhase 1: Ingesting reports...")
	changedDirs, err := ingestReports(db, coverageDir, filters, forceAll)
	if err != nil {
		return fmt.Errorf("ingest reports: %w", err)
	}

	// Phase 1.5: Inspect images for source repo labels
	fmt.Println("\nPhase 1.5: Inspecting images...")
	if err := inspectImages(db); err != nil {
		fmt.Printf("Warning: image inspection failed: %v\n", err)
	}

	// Phase 2: Compute owners
	fmt.Println("\nPhase 2: Computing owners...")
	if err := computeOwners(db, changedDirs, filters, forceAll); err != nil {
		return fmt.Errorf("compute owners: %w", err)
	}

	fmt.Printf("\nCompilation complete. Database: %s\n", dbPath)
	return nil
}

// ingestReports processes each coverage subdirectory and upserts into report_sources.
// Returns a set of dir_names that were newly processed or reprocessed.
func ingestReports(db *sql.DB, coverageDir string, filters []updateFilter, forceAll bool) (map[string]bool, error) {
	entries, err := os.ReadDir(coverageDir)
	if err != nil {
		return nil, fmt.Errorf("read coverage directory: %w", err)
	}

	changedDirs := make(map[string]bool)
	processedCount := 0
	skippedCount := 0
	errorCount := 0

	// Collect existing dir_names in DB for stale detection
	existingDirs := make(map[string]bool)
	rows, err := db.Query("SELECT dir_name FROM report_sources")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var name string
		rows.Scan(&name)
		existingDirs[name] = true
	}
	rows.Close()

	diskDirs := make(map[string]bool)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		dirName := entry.Name()
		diskDirs[dirName] = true
		reportDir := filepath.Join(coverageDir, dirName)

		// Read metadata for filter matching
		meta := readReportMetadata(reportDir)

		// Compute input hash
		inputHash := computeReportInputHash(reportDir)
		if inputHash == "" {
			// No covmeta/covcounters files — check for coverage.out
			rawFile := filepath.Join(reportDir, "coverage.out")
			if _, err := os.Stat(rawFile); err != nil {
				continue
			}
			inputHash = computeMultiFileMD5([]string{rawFile})
			if inputHash == "" {
				continue
			}
		}

		// Check if report needs processing
		forceUpdate := matchesFilters(filters, forceAll,
			meta.Namespace, meta.Hostname, meta.Container, meta.Image)

		var existingHash string
		err := db.QueryRow("SELECT input_hash FROM report_sources WHERE dir_name = ?", dirName).Scan(&existingHash)
		if err == nil && existingHash == inputHash && !forceUpdate {
			skippedCount++
			continue
		}

		// Process report
		coverageText, procErr := processReport(reportDir)
		if procErr != nil {
			fmt.Printf("  Error processing %s: %v\n", dirName, procErr)
			// Upsert with error
			upsertReportSource(db, dirName, inputHash, meta, 0, 0, 0, "", procErr.Error())
			errorCount++
			changedDirs[dirName] = true
			continue
		}

		totalStmts, coveredStmts, coveragePct := parseCoverageText(coverageText)

		if err := upsertReportSource(db, dirName, inputHash, meta,
			totalStmts, coveredStmts, coveragePct, coverageText, ""); err != nil {
			fmt.Printf("  Error saving %s: %v\n", dirName, err)
			errorCount++
			continue
		}

		changedDirs[dirName] = true
		processedCount++

		if (processedCount+skippedCount+errorCount)%100 == 0 {
			fmt.Printf("  Progress: %d processed, %d skipped, %d errors...\n",
				processedCount, skippedCount, errorCount)
		}
	}

	// Delete stale reports (dirs no longer on disk)
	staleCount := 0
	for dirName := range existingDirs {
		if !diskDirs[dirName] {
			db.Exec("DELETE FROM report_sources WHERE dir_name = ?", dirName)
			staleCount++
		}
	}

	fmt.Printf("  Processed: %d, Skipped (unchanged): %d, Errors: %d",
		processedCount, skippedCount, errorCount)
	if staleCount > 0 {
		fmt.Printf(", Removed stale: %d", staleCount)
	}
	fmt.Println()

	return changedDirs, nil
}

func upsertReportSource(db *sql.DB, dirName, inputHash string, meta reportMetadata,
	totalStmts, coveredStmts int, coveragePct float64, coverageText, errorMsg string) error {

	isHost := 0
	if meta.IsHost || meta.Namespace == "" {
		isHost = 1
	}

	_, err := db.Exec(`
		INSERT INTO report_sources (dir_name, input_hash, namespace, pod_name, container_name,
			image, binary_name, collected_at, hostname, is_host,
			total_stmts, covered_stmts, coverage_pct, coverage_text, error_msg)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(dir_name) DO UPDATE SET
			input_hash = excluded.input_hash,
			namespace = excluded.namespace,
			pod_name = excluded.pod_name,
			container_name = excluded.container_name,
			image = excluded.image,
			binary_name = excluded.binary_name,
			collected_at = excluded.collected_at,
			hostname = excluded.hostname,
			is_host = excluded.is_host,
			total_stmts = excluded.total_stmts,
			covered_stmts = excluded.covered_stmts,
			coverage_pct = excluded.coverage_pct,
			coverage_text = excluded.coverage_text,
			error_msg = excluded.error_msg
	`, dirName, inputHash, meta.Namespace, meta.PodName, meta.Container,
		meta.Image, meta.BinaryName, meta.CollectedAt, meta.Hostname, isHost,
		totalStmts, coveredStmts, coveragePct, coverageText, errorMsg)
	return err
}

// ---------------------------------------------------------------------------
// Owner computation
// ---------------------------------------------------------------------------

type reportRecord struct {
	ID            int
	DirName       string
	InputHash     string
	Namespace     string
	PodName       string
	ContainerName string
	Image         string
	BinaryName    string
	Hostname      string
	IsHost        bool
	CoverageText  string
	TotalStmts    int
	CoveredStmts  int
	CollectedAt   string
}

func computeOwners(db *sql.DB, changedDirs map[string]bool, filters []updateFilter, forceAll bool) error {
	// Load all reports from DB
	rows, err := db.Query(`
		SELECT id, dir_name, input_hash, namespace, pod_name, container_name,
			image, binary_name, hostname, is_host, coverage_text, total_stmts, covered_stmts,
			collected_at
		FROM report_sources WHERE error_msg = ''
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var reports []reportRecord
	for rows.Next() {
		var r reportRecord
		var isHost int
		if err := rows.Scan(&r.ID, &r.DirName, &r.InputHash, &r.Namespace, &r.PodName,
			&r.ContainerName, &r.Image, &r.BinaryName, &r.Hostname, &isHost,
			&r.CoverageText, &r.TotalStmts, &r.CoveredStmts, &r.CollectedAt); err != nil {
			return err
		}
		r.IsHost = isHost != 0
		reports = append(reports, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	// Deduplicate host reports that are actually containers running on the host network.
	// If a host report has the same binary_name, hostname, and coverage structure as a pod report,
	// it's the same process seen from both perspectives — keep only the pod attribution.
	// We compare using covmeta hash (statement definitions without execution counts) rather than
	// exact coverage text, since different pod instances accumulate different execution counts.
	type podKey struct {
		BinaryName  string
		Hostname    string
		CovmetaHash string
	}
	podCoverageSet := make(map[podKey]bool)
	for _, r := range reports {
		if !r.IsHost && r.Namespace != "" && r.CoverageText != "" {
			hash := computeCovmetaHash(r.CoverageText)
			podCoverageSet[podKey{r.BinaryName, r.Hostname, hash}] = true
		}
	}
	dedupedReports := make([]reportRecord, 0, len(reports))
	hostDedupCount := 0
	for _, r := range reports {
		if (r.IsHost || r.Namespace == "") && r.CoverageText != "" {
			hash := computeCovmetaHash(r.CoverageText)
			if podCoverageSet[podKey{r.BinaryName, r.Hostname, hash}] {
				hostDedupCount++
				continue
			}
		}
		dedupedReports = append(dedupedReports, r)
	}
	if hostDedupCount > 0 {
		fmt.Printf("  Deduplicated %d host reports (same process visible as pod container)\n", hostDedupCount)
	}
	reports = dedupedReports

	// Group by owner
	type ownerGroup struct {
		Namespace  string
		OwnerType  string
		OwnerName  string
		BinaryName string
		Image      string
		GroupKey    string
		Pods       map[string]bool
		Containers map[string]bool
		Hosts      map[string]bool
		Reports    []reportRecord
	}

	ownerMap := make(map[string]*ownerGroup)

	for _, r := range reports {
		var namespace, ownerType, ownerName, binaryName string

		if r.IsHost || r.Namespace == "" {
			namespace = "host"
			ownerType = "Host"
			ownerName = r.BinaryName
			if ownerName == "" {
				ownerName = r.PodName
			}
			binaryName = ownerName
		} else {
			namespace = r.Namespace
			ownerType, ownerName = extractOwnerInfoCompile(r.PodName)
			binaryName = r.BinaryName
			if binaryName == "" {
				binaryName = r.ContainerName
			}
		}

		groupKey := fmt.Sprintf("%s/%s/%s/%s/%s", namespace, ownerType, ownerName, binaryName, r.Image)

		og, exists := ownerMap[groupKey]
		if !exists {
			og = &ownerGroup{
				Namespace:  namespace,
				OwnerType:  ownerType,
				OwnerName:  ownerName,
				BinaryName: binaryName,
				Image:      r.Image,
				GroupKey:    groupKey,
				Pods:       make(map[string]bool),
				Containers: make(map[string]bool),
				Hosts:      make(map[string]bool),
			}
			ownerMap[groupKey] = og
		}
		if r.PodName != "" {
			og.Pods[r.PodName] = true
		}
		if r.Hostname != "" {
			og.Hosts[r.Hostname] = true
		}
		containerName := r.ContainerName
		if containerName == "" {
			containerName = binaryName
		}
		if containerName != "" {
			og.Containers[containerName] = true
		}
		og.Reports = append(og.Reports, r)
	}

	// Process each owner
	processedCount := 0
	skippedCount := 0

	// Collect existing owner group_keys for stale detection
	existingOwners := make(map[string]bool)
	ownerRows, err := db.Query("SELECT group_key FROM owners")
	if err != nil {
		return err
	}
	for ownerRows.Next() {
		var key string
		ownerRows.Scan(&key)
		existingOwners[key] = true
	}
	ownerRows.Close()

	currentOwnerKeys := make(map[string]bool)

	for _, og := range ownerMap {
		currentOwnerKeys[og.GroupKey] = true

		// Compute merge_input_hash from sorted report input hashes
		var hashes []string
		hasChanged := false
		for _, r := range og.Reports {
			hashes = append(hashes, r.InputHash)
			if changedDirs[r.DirName] {
				hasChanged = true
			}
		}
		sort.Strings(hashes)
		h := md5.New()
		for _, hash := range hashes {
			io.WriteString(h, hash)
		}
		mergeInputHash := hex.EncodeToString(h.Sum(nil))

		// Check if any constituent report was force-updated
		forceUpdate := false
		if forceAll {
			forceUpdate = true
		} else if len(filters) > 0 {
			for _, r := range og.Reports {
				if matchesFilters(filters, false, r.Namespace, r.Hostname, r.ContainerName, r.Image) {
					forceUpdate = true
					break
				}
			}
		}

		// Check cache
		var existingMergeHash string
		db.QueryRow("SELECT merge_input_hash FROM owners WHERE group_key = ?", og.GroupKey).Scan(&existingMergeHash)
		if existingMergeHash == mergeInputHash && !hasChanged && !forceUpdate {
			skippedCount++
			continue
		}

		// Merge coverage texts
		var texts []string
		for _, r := range og.Reports {
			if r.CoverageText != "" {
				texts = append(texts, r.CoverageText)
			}
		}
		mergedText := ""
		if len(texts) > 0 {
			mergedText = mergeCoverageTexts(texts)
		}

		totalStmts, coveredStmts, coveragePct := parseCoverageText(mergedText)

		// Pods and containers as JSON
		pods := make([]string, 0, len(og.Pods))
		for p := range og.Pods {
			pods = append(pods, p)
		}
		sort.Strings(pods)
		podsJSON, _ := json.Marshal(pods)

		containers := make([]string, 0, len(og.Containers))
		for c := range og.Containers {
			containers = append(containers, c)
		}
		sort.Strings(containers)
		containersJSON, _ := json.Marshal(containers)

		hosts := make([]string, 0, len(og.Hosts))
		for h := range og.Hosts {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		hostsJSON, _ := json.Marshal(hosts)

		// Image comes from the group (all reports in group share the same image)
		ownerImage := og.Image

		// Compute first_seen and last_seen from collected_at timestamps
		firstSeen := ""
		lastSeen := ""
		for _, r := range og.Reports {
			if r.CollectedAt == "" {
				continue
			}
			if firstSeen == "" || r.CollectedAt < firstSeen {
				firstSeen = r.CollectedAt
			}
			if lastSeen == "" || r.CollectedAt > lastSeen {
				lastSeen = r.CollectedAt
			}
		}

		// Upsert owner
		tx, err := db.Begin()
		if err != nil {
			return err
		}

		res, err := tx.Exec(`
			INSERT INTO owners (group_key, namespace, owner_type, owner_name, binary_name,
				image, pods_json, pod_count, containers_json, hosts_json,
				total_stmts, covered_stmts, coverage_pct,
				merged_coverage_text, merge_input_hash,
				first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(group_key) DO UPDATE SET
				namespace = excluded.namespace,
				owner_type = excluded.owner_type,
				owner_name = excluded.owner_name,
				binary_name = excluded.binary_name,
				image = excluded.image,
				pods_json = excluded.pods_json,
				pod_count = excluded.pod_count,
				containers_json = excluded.containers_json,
				hosts_json = excluded.hosts_json,
				total_stmts = excluded.total_stmts,
				covered_stmts = excluded.covered_stmts,
				coverage_pct = excluded.coverage_pct,
				merged_coverage_text = excluded.merged_coverage_text,
				merge_input_hash = excluded.merge_input_hash,
				first_seen = excluded.first_seen,
				last_seen = excluded.last_seen
		`, og.GroupKey, og.Namespace, og.OwnerType, og.OwnerName, og.BinaryName,
			ownerImage, string(podsJSON), len(og.Pods), string(containersJSON), string(hostsJSON),
			totalStmts, coveredStmts, coveragePct,
			mergedText, mergeInputHash,
			firstSeen, lastSeen)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("upsert owner %s: %w", og.GroupKey, err)
		}

		// Get owner ID
		var ownerID int64
		err = tx.QueryRow("SELECT id FROM owners WHERE group_key = ?", og.GroupKey).Scan(&ownerID)
		if err != nil {
			tx.Rollback()
			return err
		}
		_ = res // we use the query above instead

		// Update owner_reports
		tx.Exec("DELETE FROM owner_reports WHERE owner_id = ?", ownerID)
		for _, r := range og.Reports {
			tx.Exec("INSERT INTO owner_reports (owner_id, report_id) VALUES (?, ?)", ownerID, r.ID)
		}

		// Update owner_file_stats
		tx.Exec("DELETE FROM owner_file_stats WHERE owner_id = ?", ownerID)
		if mergedText != "" {
			fileStatsList := computePerFileStats(mergedText)
			for _, fs := range fileStatsList {
				tx.Exec(`INSERT INTO owner_file_stats (owner_id, file_path, total_stmts, covered_stmts, coverage_pct)
					VALUES (?, ?, ?, ?, ?)`, ownerID, fs.FilePath, fs.TotalStmts, fs.CoveredStmts, fs.CoveragePct)
			}
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit owner %s: %w", og.GroupKey, err)
		}

		processedCount++
	}

	// Delete stale owners
	staleCount := 0
	for key := range existingOwners {
		if !currentOwnerKeys[key] {
			db.Exec("DELETE FROM owners WHERE group_key = ?", key)
			staleCount++
		}
	}

	fmt.Printf("  Processed: %d, Skipped (unchanged): %d", processedCount, skippedCount)
	if staleCount > 0 {
		fmt.Printf(", Removed stale: %d", staleCount)
	}
	fmt.Println()

	return nil
}
