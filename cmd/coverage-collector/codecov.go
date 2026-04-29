package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var (
	ccToken      string
	ccFlags      []string
	ccURL        string
	ccNamespaces []string
	ccOwners     []string
	ccDryRun     bool
	ccSlug       string
)

var codecovUploadCmd = &cobra.Command{
	Use:   "codecov-upload",
	Short: "Upload coverage data to Codecov",
	Long: `Upload merged coverage data from the SQLite database to Codecov.

Groups coverage by (source_repo, commit_id), merges all binaries from the same
repository into a single Go cover profile, and uploads via the Codecov CLI.

Each upload is tagged with --flag (default: openshift-e2e) so Codecov and
DevLake can distinguish E2E coverage from unit test coverage.

Requires the codecov CLI binary on PATH or downloads it automatically.`,
	Example: `  # Upload all coverage
  coverage-collector cluster codecov-upload --collection reports/nightly-2026-04-22

  # Upload with explicit token and self-hosted Codecov
  coverage-collector cluster codecov-upload --collection reports/nightly-2026-04-22 \
    --codecov-token $CODECOV_TOKEN --codecov-url https://codecov.internal.example.com

  # Filter to specific namespaces
  coverage-collector cluster codecov-upload --collection reports/nightly-2026-04-22 \
    --namespace 'openshift-apiserver' --namespace 'openshift-etcd'

  # Dry run — show what would be uploaded without executing
  coverage-collector cluster codecov-upload --collection reports/nightly-2026-04-22 --dry-run`,
	RunE: runCodecovUpload,
}

func init() {
	codecovUploadCmd.Flags().StringVar(&ccToken, "codecov-token", "", "Codecov upload token (or set CODECOV_TOKEN env)")
	codecovUploadCmd.Flags().StringArrayVar(&ccFlags, "flag", []string{"openshift-e2e"}, "Codecov flags (repeatable)")
	codecovUploadCmd.Flags().StringVar(&ccURL, "codecov-url", "", "Codecov instance URL (for self-hosted; sets CODECOV_URL)")
	codecovUploadCmd.Flags().StringArrayVar(&ccNamespaces, "namespace", []string{"*"}, "Namespace glob patterns (repeatable, OR logic)")
	codecovUploadCmd.Flags().StringArrayVar(&ccOwners, "owner", []string{"*"}, "Owner name glob patterns (repeatable, OR logic)")
	codecovUploadCmd.Flags().BoolVar(&ccDryRun, "dry-run", false, "Show what would be uploaded without executing")
	codecovUploadCmd.Flags().StringVar(&ccSlug, "slug", "", "Override repository slug for all uploads (e.g., owner/repo)")

	clusterCmd.AddCommand(codecovUploadCmd)
}

// repoCommitKey groups hash-groups that share the same source repository and commit.
type repoCommitKey struct {
	SourceRepo string
	CommitID   string
}

// repoCommitGroup holds all hash-groups targeting the same repo+commit.
type repoCommitGroup struct {
	Key        repoCommitKey
	HashGroups []codecovHashGroup
}

type codecovHashGroup struct {
	Hash   string
	Owners []*OwnerReport
}

func runCodecovUpload(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	token := ccToken
	if token == "" {
		token = os.Getenv("CODECOV_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("codecov token required: set --codecov-token or CODECOV_TOKEN env")
	}

	fmt.Printf("Codecov upload for collection: %s\n", collectionName)
	if ccURL != "" {
		fmt.Printf("Codecov URL: %s\n", ccURL)
	}
	fmt.Printf("Flags: %v\n", ccFlags)
	fmt.Printf("Dry run: %v\n\n", ccDryRun)

	// Open SQLite database read-only
	dbPath := filepath.Join(collectionName, "coverage.db")
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("database not found at %s — run 'compile' first", dbPath)
	}

	db, err := sql.Open("sqlite", dbPath+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	owners, err := loadOwnersForRender(db)
	if err != nil {
		return fmt.Errorf("load owners: %w", err)
	}
	fmt.Printf("Loaded %d owners from database\n", len(owners))

	imageSources, err := loadImageSources(db)
	if err != nil {
		fmt.Printf("Warning: could not load image sources: %v\n", err)
		imageSources = make(map[string]imageSource)
	}

	// Enrich with covmeta hashes
	for i := range owners {
		owners[i].CovmetaHash = computeCovmetaHash(owners[i].MergedCoverageText)
	}

	// Filter
	var filtered []OwnerReport
	for _, o := range owners {
		if matchesAnyGlob(o.Namespace, ccNamespaces) && matchesAnyGlob(o.OwnerName, ccOwners) {
			filtered = append(filtered, o)
		}
	}
	fmt.Printf("Filtered to %d owners (namespace=%v, owner=%v)\n", len(filtered), ccNamespaces, ccOwners)

	if len(filtered) == 0 {
		fmt.Println("No owners match the filter criteria")
		return nil
	}

	// Group by covmeta hash (dedup same binary across pods)
	hashGroupMap := make(map[string]*codecovHashGroup)
	for i := range filtered {
		hash := filtered[i].CovmetaHash
		if hash == "" || filtered[i].MergedCoverageText == "" {
			continue
		}
		hg, ok := hashGroupMap[hash]
		if !ok {
			hg = &codecovHashGroup{Hash: hash}
			hashGroupMap[hash] = hg
		}
		hg.Owners = append(hg.Owners, &filtered[i])
	}

	// Resolve source repo/commit per hash group, then re-group by (repo, commit)
	repoGroupMap := make(map[repoCommitKey]*repoCommitGroup)
	var skippedNoSource int

	for _, hg := range hashGroupMap {
		sourceURL, sourceCommit := resolveSourceURLForGroup(hg.Owners, imageSources)
		if sourceURL == "" || sourceCommit == "" {
			skippedNoSource++
			continue
		}

		key := repoCommitKey{SourceRepo: sourceURL, CommitID: sourceCommit}
		rg, ok := repoGroupMap[key]
		if !ok {
			rg = &repoCommitGroup{Key: key}
			repoGroupMap[key] = rg
		}
		rg.HashGroups = append(rg.HashGroups, *hg)
	}

	if skippedNoSource > 0 {
		fmt.Printf("Skipped %d hash groups with no resolved source repo/commit\n", skippedNoSource)
	}

	// Sort for deterministic ordering
	var repoGroups []*repoCommitGroup
	for _, rg := range repoGroupMap {
		repoGroups = append(repoGroups, rg)
	}
	sort.Slice(repoGroups, func(i, j int) bool {
		if repoGroups[i].Key.SourceRepo != repoGroups[j].Key.SourceRepo {
			return repoGroups[i].Key.SourceRepo < repoGroups[j].Key.SourceRepo
		}
		return repoGroups[i].Key.CommitID < repoGroups[j].Key.CommitID
	})

	fmt.Printf("Grouped into %d repo+commit targets for upload\n\n", len(repoGroups))

	// Find or download codecov CLI
	var codecovPath string
	var downloadedCLI bool
	if !ccDryRun {
		codecovPath, downloadedCLI, err = ensureCodecovCLI(ctx)
		if err != nil {
			return fmt.Errorf("codecov CLI: %w", err)
		}
		if downloadedCLI {
			defer os.Remove(codecovPath)
		}
	}

	reposDir := filepath.Join(collectionName, "repos")
	var uploaded, failed int

	for i, rg := range repoGroups {
		slug := ccSlug
		if slug == "" {
			slug = extractRepoSlug(rg.Key.SourceRepo)
		}
		gitService := extractGitService(rg.Key.SourceRepo)

		// Count total owners and binaries
		var totalOwners int
		binaryNames := make(map[string]bool)
		for _, hg := range rg.HashGroups {
			totalOwners += len(hg.Owners)
			for _, o := range hg.Owners {
				binaryNames[o.BinaryName] = true
			}
		}

		fmt.Printf("[%d/%d] %s @ %.12s (%d binaries, %d owners)\n",
			i+1, len(repoGroups), slug, rg.Key.CommitID, len(binaryNames), totalOwners)

		// Merge coverage across all hash groups in this repo+commit
		var allTexts []string
		for _, hg := range rg.HashGroups {
			for _, o := range hg.Owners {
				if o.MergedCoverageText != "" {
					allTexts = append(allTexts, o.MergedCoverageText)
				}
			}
		}
		mergedText := mergeCoverageTexts(allTexts)

		// Optionally rewrite paths if repo is cloned
		coverageText := rewriteCoverageForCodecov(mergedText, rg, reposDir, imageSources)

		if ccDryRun {
			lines := strings.Count(coverageText, "\n")
			fmt.Printf("  [dry-run] Would upload %d coverage lines to %s @ %.12s\n", lines, slug, rg.Key.CommitID)
			fmt.Printf("  [dry-run] Flags: %v, git-service: %s\n", ccFlags, gitService)
			uploaded++
			continue
		}

		// Write coverage to temp file
		tmpFile, err := os.CreateTemp("", "codecov-upload-*.out")
		if err != nil {
			fmt.Printf("  ERROR: create temp file: %v\n", err)
			failed++
			continue
		}
		if _, err := tmpFile.WriteString(coverageText); err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			fmt.Printf("  ERROR: write temp file: %v\n", err)
			failed++
			continue
		}
		tmpFile.Close()

		err = execCodecovUpload(ctx, codecovPath, codecovUploadOpts{
			Token:        token,
			CoverageFile: tmpFile.Name(),
			CommitSHA:    rg.Key.CommitID,
			Slug:         slug,
			GitService:   gitService,
			Flags:        ccFlags,
			RepoDir:      findClonedRepoDir(reposDir, rg.Key.SourceRepo, rg.Key.CommitID),
		})
		os.Remove(tmpFile.Name())

		if err != nil {
			fmt.Printf("  ERROR: upload failed: %v\n", err)
			failed++
		} else {
			fmt.Printf("  Uploaded successfully\n")
			uploaded++
		}
	}

	fmt.Printf("\nCodecov upload complete: %d uploaded, %d failed\n", uploaded, failed)
	return nil
}

// rewriteCoverageForCodecov strips the Go module prefix from coverage file
// paths so Codecov maps them to repo-relative paths.
//
// Derives the module path from the source_repo URL (e.g.,
// "https://github.com/openshift/cluster-bootstrap" -> "github.com/openshift/cluster-bootstrap").
// If cloned repos are available, also handles go.work workspaces and
// build-path anomalies (/workspace/, /go/src/).
func rewriteCoverageForCodecov(mergedText string, rg *repoCommitGroup, reposDir string, imageSources map[string]imageSource) string {
	// Derive module path from source_repo URL — no cloned repo needed
	moduleFromURL := modulePathFromSourceURL(rg.Key.SourceRepo)

	// If cloned repos exist, try workspace-aware rewriting first
	if reposDir != "" {
		var allOwners []*OwnerReport
		for i := range rg.HashGroups {
			allOwners = append(allOwners, rg.HashGroups[i].Owners...)
		}
		repoPath, moduleName, workspaceModules := resolveSourceRepo(allOwners, reposDir, imageSources, mergedText)

		if workspaceModules != nil {
			rewritten := rewriteWorkspacePaths(mergedText, workspaceModules)
			if rewritten != mergedText {
				return rewritten
			}
		}

		// Use cloned repo's actual module name if available (more accurate)
		if repoPath != "" && moduleName != "" {
			moduleFromURL = moduleName
		}
	}

	if moduleFromURL == "" {
		return mergedText
	}

	// Strip module prefix from all coverage lines
	return stripModulePrefix(mergedText, moduleFromURL)
}

// findClonedRepoDir returns the cloned repo directory if it exists.
// Mirrors the path layout used by clone_sources.go: repos/<host>/<org>/<repo>/<commit-prefix>/
func findClonedRepoDir(reposDir, sourceURL, commitID string) string {
	if reposDir == "" || sourceURL == "" {
		return ""
	}
	src := imageSource{SourceRepo: sourceURL, CommitID: commitID}
	dir := findRepoByImageSource(reposDir, src)
	if dir != "" {
		return dir
	}
	return ""
}

// modulePathFromSourceURL derives Go module path from a source repo URL.
// "https://github.com/openshift/cluster-bootstrap" -> "github.com/openshift/cluster-bootstrap"
// "git@github.com:org/repo.git" -> "github.com/org/repo"
func modulePathFromSourceURL(sourceURL string) string {
	// SSH URL: git@github.com:org/repo.git
	if strings.Contains(sourceURL, "@") && strings.Contains(sourceURL, ":") && !strings.Contains(sourceURL, "://") {
		parts := strings.SplitN(sourceURL, "@", 2)
		if len(parts) == 2 {
			hostAndPath := parts[1]
			hostAndPath = strings.Replace(hostAndPath, ":", "/", 1)
			hostAndPath = strings.TrimSuffix(hostAndPath, ".git")
			return hostAndPath
		}
	}

	u, err := url.Parse(sourceURL)
	if err != nil || u.Host == "" {
		return ""
	}
	path := strings.TrimPrefix(u.Path, "/")
	path = strings.TrimSuffix(path, ".git")
	return u.Host + "/" + path
}

// stripModulePrefix removes the Go module prefix from coverage file paths.
// "github.com/openshift/cluster-bootstrap/cmd/foo.go:1.1,2.2 1 5"
// becomes "cmd/foo.go:1.1,2.2 1 5"
func stripModulePrefix(text, modulePrefix string) string {
	prefix := modulePrefix + "/"
	var result strings.Builder
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "mode:") || line == "" {
			result.WriteString(line)
			result.WriteByte('\n')
			continue
		}
		if strings.HasPrefix(line, prefix) {
			result.WriteString(strings.TrimPrefix(line, prefix))
		} else {
			result.WriteString(line)
		}
		result.WriteByte('\n')
	}
	return strings.TrimRight(result.String(), "\n") + "\n"
}

// rewriteWorkspacePaths rewrites module-prefixed paths in coverage text
// to workspace-relative paths for go.work repos.
func rewriteWorkspacePaths(text string, workspaceModules map[string]string) string {
	if len(workspaceModules) == 0 {
		return text
	}

	// Sort modules longest-first so longer prefixes match first
	type modEntry struct {
		module string
		dir    string
	}
	var mods []modEntry
	for mod, dir := range workspaceModules {
		mods = append(mods, modEntry{mod, dir})
	}
	sort.Slice(mods, func(i, j int) bool {
		return len(mods[i].module) > len(mods[j].module)
	})

	var result strings.Builder
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "mode:") || line == "" {
			result.WriteString(line)
			result.WriteByte('\n')
			continue
		}
		rewritten := false
		for _, m := range mods {
			if strings.HasPrefix(line, m.module+"/") {
				rest := strings.TrimPrefix(line, m.module+"/")
				if m.dir == "." || m.dir == "" {
					result.WriteString(rest)
				} else {
					result.WriteString(m.dir + "/" + rest)
				}
				result.WriteByte('\n')
				rewritten = true
				break
			}
		}
		if !rewritten {
			result.WriteString(line)
			result.WriteByte('\n')
		}
	}
	return strings.TrimRight(result.String(), "\n") + "\n"
}

// extractRepoSlug parses "owner/repo" from a source repository URL.
// Handles HTTPS (https://github.com/org/repo) and SSH (git@github.com:org/repo.git).
func extractRepoSlug(sourceURL string) string {
	// Handle SSH URLs: git@github.com:org/repo.git
	if strings.Contains(sourceURL, "@") && strings.Contains(sourceURL, ":") && !strings.Contains(sourceURL, "://") {
		parts := strings.SplitN(sourceURL, ":", 2)
		if len(parts) == 2 {
			path := strings.TrimSuffix(parts[1], ".git")
			slugParts := strings.SplitN(path, "/", 3)
			if len(slugParts) >= 2 {
				return slugParts[0] + "/" + slugParts[1]
			}
			return path
		}
	}

	u, err := url.Parse(sourceURL)
	if err != nil {
		return sourceURL
	}
	path := strings.TrimPrefix(u.Path, "/")
	path = strings.TrimSuffix(path, ".git")
	parts := strings.SplitN(path, "/", 3)
	if len(parts) >= 2 {
		return parts[0] + "/" + parts[1]
	}
	return path
}

// extractGitService determines the git hosting service from a source URL.
// Handles HTTPS and SSH (git@host:...) URLs.
func extractGitService(sourceURL string) string {
	var host string

	// Handle SSH URLs: git@github.com:org/repo.git
	if strings.Contains(sourceURL, "@") && strings.Contains(sourceURL, ":") && !strings.Contains(sourceURL, "://") {
		parts := strings.SplitN(sourceURL, "@", 2)
		if len(parts) == 2 {
			hostPart := strings.SplitN(parts[1], ":", 2)
			host = strings.ToLower(hostPart[0])
		}
	} else {
		u, err := url.Parse(sourceURL)
		if err != nil {
			return ""
		}
		host = strings.ToLower(u.Hostname())
	}

	if host == "" {
		return ""
	}

	switch {
	case strings.Contains(host, "github.com"):
		return "github"
	case strings.Contains(host, "gitlab"):
		return "gitlab"
	case strings.Contains(host, "bitbucket"):
		return "bitbucket"
	default:
		return "github_enterprise"
	}
}

type codecovUploadOpts struct {
	Token        string
	CoverageFile string
	CommitSHA    string
	Slug         string
	GitService   string
	Flags        []string
	RepoDir      string // working directory for codecov CLI (cloned repo root)
}

func execCodecovUpload(ctx context.Context, codecovPath string, opts codecovUploadOpts) error {
	args := []string{
		"upload-coverage",
		"-t", opts.Token,
		"-f", opts.CoverageFile,
		"--sha", opts.CommitSHA,
		"--disable-search",
	}

	if opts.Slug != "" {
		args = append(args, "--slug", opts.Slug)
	}
	if opts.GitService != "" {
		args = append(args, "--git-service", opts.GitService)
	}
	for _, flag := range opts.Flags {
		args = append(args, "--flag", flag)
	}

	// Log the command (mask token)
	debugArgs := make([]string, len(args))
	copy(debugArgs, args)
	for i, a := range debugArgs {
		if a == "-t" && i+1 < len(debugArgs) {
			debugArgs[i+1] = "***"
		}
	}
	fmt.Printf("  exec: %s %s\n", codecovPath, strings.Join(debugArgs, " "))

	cmd := exec.CommandContext(ctx, codecovPath, args...)

	if opts.RepoDir != "" {
		cmd.Dir = opts.RepoDir
	}

	if ccURL != "" {
		cmd.Env = append(os.Environ(), "CODECOV_URL="+ccURL)
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("codecov upload-coverage failed: %w", err)
	}
	return nil
}

// ensureCodecovCLI finds codecov on PATH or downloads it.
// Returns (path, wasDownloaded, error).
func ensureCodecovCLI(ctx context.Context) (string, bool, error) {
	if p, err := exec.LookPath("codecov"); err == nil {
		return p, false, nil
	}

	fmt.Println("Downloading Codecov CLI...")

	var downloadURL string
	switch runtime.GOOS {
	case "linux":
		downloadURL = "https://cli.codecov.io/latest/linux/codecov"
	case "darwin":
		downloadURL = "https://cli.codecov.io/latest/macos/codecov"
	default:
		return "", false, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return "", false, fmt.Errorf("create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	tmpFile, err := os.CreateTemp("", "codecov-cli-*")
	if err != nil {
		return "", false, fmt.Errorf("create temp file: %w", err)
	}

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", false, fmt.Errorf("save binary: %w", err)
	}
	tmpFile.Close()

	if err := os.Chmod(tmpFile.Name(), 0755); err != nil {
		os.Remove(tmpFile.Name())
		return "", false, fmt.Errorf("chmod: %w", err)
	}

	fmt.Printf("Codecov CLI downloaded to %s\n", tmpFile.Name())
	return tmpFile.Name(), true, nil
}
