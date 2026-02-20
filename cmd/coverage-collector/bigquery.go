package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"cloud.google.com/go/bigquery"
	"github.com/spf13/cobra"
	"golang.org/x/tools/cover"
)

// BigQuery command flags
var (
	bqProject   string
	bqDataset   string
	bqCollection string
	bqNamespaces []string
	bqOwners     []string
)

// BigQuery row types

type CoverageDataRow struct {
	IngestionTime    time.Time `bigquery:"ingestion_time"`
	BinaryHash       string    `bigquery:"binary_hash"`
	CollectionID     string    `bigquery:"collection_id"`
	SourceFilename   string    `bigquery:"source_filename"`
	SourceLine       string    `bigquery:"source_line"`
	SourceLineNumber int       `bigquery:"source_line_number"`
	LineExecutions   int       `bigquery:"line_executions"`
}

type GeneratorEntry struct {
	Namespace  string `bigquery:"namespace"`
	Owner      string `bigquery:"owner"`
	Container  string `bigquery:"container"`
	BinaryName string `bigquery:"binary_name"`
}

type CoverageGeneratorsRow struct {
	IngestionTime time.Time        `bigquery:"ingestion_time"`
	SoftwareGroup string           `bigquery:"software_group"`
	BinaryHash    string           `bigquery:"binary_hash"`
	CollectionID  string           `bigquery:"collection_id"`
	SourceURL     string           `bigquery:"source_url"`
	SoftwareKey   string           `bigquery:"software_key"`
	SourceCommit  string           `bigquery:"source_commit"`
	Generators    []GeneratorEntry `bigquery:"generators"`
}

var bigqueryCmd = &cobra.Command{
	Use:   "bigquery",
	Short: "BigQuery operations",
	Long:  `Export coverage data to Google BigQuery for cross-collection analysis.`,
}

var ingestCmd = &cobra.Command{
	Use:   "ingest",
	Short: "Ingest coverage data into BigQuery",
	Long: `Ingest coverage data from a collection's SQLite database into BigQuery.

Creates two tables in the specified dataset:
  - coverage_data:       Per-line coverage data with source code
  - coverage_generators: Owner/binary metadata with source URLs

The dataset and tables are created if they don't exist.`,
	Example: `  # Ingest all coverage data
  coverage-collector bigquery --project my-project --dataset my_dataset \
    ingest --collection reports/full-exercise

  # Ingest only specific namespaces
  coverage-collector bigquery --project my-project --dataset my_dataset \
    ingest --collection reports/full-exercise \
    --namespace 'openshift-apiserver' --namespace 'openshift-etcd'

  # Ingest with glob patterns
  coverage-collector bigquery --project my-project --dataset my_dataset \
    ingest --collection reports/full-exercise \
    --namespace 'openshift-*' --owner 'kube-*'`,
	RunE: runIngest,
}

func init() {
	bigqueryCmd.PersistentFlags().StringVar(&bqProject, "project", "", "GCP project ID (required)")
	bigqueryCmd.PersistentFlags().StringVar(&bqDataset, "dataset", "", "BigQuery dataset name (required)")
	bigqueryCmd.MarkPersistentFlagRequired("project")
	bigqueryCmd.MarkPersistentFlagRequired("dataset")

	ingestCmd.Flags().StringVar(&bqCollection, "collection", "", "Collection directory (required)")
	ingestCmd.Flags().StringArrayVar(&bqNamespaces, "namespace", []string{"*"}, "Namespace glob patterns (repeatable, OR logic)")
	ingestCmd.Flags().StringArrayVar(&bqOwners, "owner", []string{"*"}, "Owner name glob patterns (repeatable, OR logic)")
	ingestCmd.MarkFlagRequired("collection")

	bigqueryCmd.AddCommand(ingestCmd)
	rootCmd.AddCommand(bigqueryCmd)
}

func runIngest(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	ingestionTime := time.Now().UTC()

	fmt.Printf("Ingesting coverage data for collection: %s\n", bqCollection)
	fmt.Printf("BigQuery target: %s.%s\n", bqProject, bqDataset)
	fmt.Printf("Ingestion time: %s\n\n", ingestionTime.Format(time.RFC3339))

	// Open SQLite database (read-only)
	dbPath := filepath.Join(bqCollection, "coverage.db")
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("database not found at %s — run 'compile' first", dbPath)
	}

	db, err := sql.Open("sqlite", dbPath+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	// Load owners and image sources
	ownerReports, err := loadOwnersForRender(db)
	if err != nil {
		return fmt.Errorf("load owners: %w", err)
	}
	fmt.Printf("Loaded %d owners from database\n", len(ownerReports))

	imageSources, err := loadImageSources(db)
	if err != nil {
		fmt.Printf("Warning: could not load image sources: %v\n", err)
		imageSources = make(map[string]imageSource)
	}

	// Enrich with covmeta hashes
	for i := range ownerReports {
		ownerReports[i].CovmetaHash = computeCovmetaHash(ownerReports[i].MergedCoverageText)
	}

	// Filter owners by namespace and owner globs
	var filtered []OwnerReport
	for _, o := range ownerReports {
		if matchesAnyGlob(o.Namespace, bqNamespaces) && matchesAnyGlob(o.OwnerName, bqOwners) {
			filtered = append(filtered, o)
		}
	}
	fmt.Printf("Filtered to %d owners (namespace=%v, owner=%v)\n", len(filtered), bqNamespaces, bqOwners)

	if len(filtered) == 0 {
		fmt.Println("No owners match the filter criteria")
		return nil
	}

	// Group by covmeta hash
	type hashGroup struct {
		hash   string
		owners []*OwnerReport
	}
	hashGroupMap := make(map[string]*hashGroup)
	for i := range filtered {
		hash := filtered[i].CovmetaHash
		if hash == "" || filtered[i].MergedCoverageText == "" {
			continue
		}
		hg, ok := hashGroupMap[hash]
		if !ok {
			hg = &hashGroup{hash: hash}
			hashGroupMap[hash] = hg
		}
		hg.owners = append(hg.owners, &filtered[i])
	}

	// Sort hash groups for deterministic ordering
	var hashGroups []*hashGroup
	for _, hg := range hashGroupMap {
		hashGroups = append(hashGroups, hg)
	}
	sort.Slice(hashGroups, func(i, j int) bool {
		return hashGroups[i].hash < hashGroups[j].hash
	})

	fmt.Printf("Grouped into %d unique binary hashes\n\n", len(hashGroups))

	// Create BigQuery client and ensure dataset/tables exist
	bqClient, err := bigquery.NewClient(ctx, bqProject)
	if err != nil {
		return fmt.Errorf("create BigQuery client: %w", err)
	}
	defer bqClient.Close()

	if err := ensureBQDatasetAndTables(ctx, bqClient); err != nil {
		return fmt.Errorf("setup BigQuery: %w", err)
	}

	dataset := bqClient.Dataset(bqDataset)
	coverageTable := dataset.Table("coverage_data")
	generatorsTable := dataset.Table("coverage_generators")

	coverageInserter := coverageTable.Inserter()
	generatorsInserter := generatorsTable.Inserter()

	reposDir := filepath.Join(bqCollection, "repos")

	var totalDataRows int
	var totalGenRows int

	for i, hg := range hashGroups {
		// Pick a representative owner for display
		rep := hg.owners[0]
		fmt.Printf("  [%d/%d] %s (%d owner(s), %d stmts)\n",
			i+1, len(hashGroups), rep.BinaryName, len(hg.owners), rep.TotalStmts)

		// Merge coverage texts from all owners in this hash group
		var texts []string
		for _, o := range hg.owners {
			if o.MergedCoverageText != "" {
				texts = append(texts, o.MergedCoverageText)
			}
		}
		mergedText := mergeCoverageTexts(texts)

		// Resolve source repo using the same 3-strategy cascade as render
		repoPath, moduleName, workspaceModules := resolveSourceRepo(hg.owners, reposDir, imageSources, mergedText)

		// Resolve source URL and commit from image sources
		sourceURL, sourceCommit := resolveSourceURLForGroup(hg.owners, imageSources)

		// Read software_group and software_key from image_sources table
		softwareGroup, softwareKey := readSoftwareInfo(hg.owners, imageSources)

		// Build generators row
		var generators []GeneratorEntry
		for _, o := range hg.owners {
			ns := o.Namespace
			owner := o.OwnerName
			container := ""
			if len(o.Containers) > 0 {
				container = strings.Join(o.Containers, ",")
			}
			// For host/pod types, leave namespace/owner/container empty per spec
			if o.OwnerType == "Host" || o.OwnerType == "Pod (No Owner)" {
				ns = ""
				owner = ""
				container = ""
			}
			generators = append(generators, GeneratorEntry{
				Namespace:  ns,
				Owner:      owner,
				Container:  container,
				BinaryName: o.BinaryName,
			})
		}

		genRow := CoverageGeneratorsRow{
			IngestionTime: ingestionTime,
			SoftwareGroup: softwareGroup,
			BinaryHash:    hg.hash,
			CollectionID:  bqCollection,
			SourceURL:     sourceURL,
			SoftwareKey:   softwareKey,
			SourceCommit:  sourceCommit,
			Generators:    generators,
		}

		if err := generatorsInserter.Put(ctx, &genRow); err != nil {
			fmt.Printf("    WARNING: failed to insert generator row: %v\n", err)
		} else {
			totalGenRows++
		}

		// Generate per-line coverage data
		dataRows, err := buildCoverageDataRows(mergedText, hg.hash, repoPath, moduleName, workspaceModules, ingestionTime)
		if err != nil {
			fmt.Printf("    WARNING: failed to build coverage data: %v\n", err)
			continue
		}

		// Batch insert coverage data rows
		const batchSize = 500
		for start := 0; start < len(dataRows); start += batchSize {
			end := start + batchSize
			if end > len(dataRows) {
				end = len(dataRows)
			}
			batch := dataRows[start:end]
			// Convert to ValueSaver slice
			var savers []*CoverageDataRow
			for j := range batch {
				savers = append(savers, &batch[j])
			}
			if err := coverageInserter.Put(ctx, savers); err != nil {
				fmt.Printf("    WARNING: batch insert failed at offset %d: %v\n", start, err)
			}
		}
		totalDataRows += len(dataRows)
	}

	fmt.Printf("\nIngestion complete:\n")
	fmt.Printf("  coverage_data rows:       %d\n", totalDataRows)
	fmt.Printf("  coverage_generators rows: %d\n", totalGenRows)

	return nil
}

// matchesAnyGlob returns true if value matches any of the glob patterns (OR logic).
func matchesAnyGlob(value string, patterns []string) bool {
	for _, p := range patterns {
		if matched, _ := filepath.Match(p, value); matched {
			return true
		}
	}
	return false
}

// ensureBQDatasetAndTables creates the dataset and tables if they don't exist.
func ensureBQDatasetAndTables(ctx context.Context, client *bigquery.Client) error {
	dataset := client.Dataset(bqDataset)

	// Create dataset if needed
	if err := dataset.Create(ctx, &bigquery.DatasetMetadata{}); err != nil {
		if !strings.Contains(err.Error(), "Already Exists") &&
			!strings.Contains(err.Error(), "alreadyExists") &&
			!strings.Contains(err.Error(), "409") {
			return fmt.Errorf("create dataset: %w", err)
		}
	} else {
		fmt.Printf("Created dataset %s.%s\n", bqProject, bqDataset)
	}

	// coverage_data table
	coverageDataSchema := bigquery.Schema{
		{Name: "ingestion_time", Type: bigquery.TimestampFieldType, Required: true},
		{Name: "binary_hash", Type: bigquery.StringFieldType, Required: true},
		{Name: "collection_id", Type: bigquery.StringFieldType, Required: true},
		{Name: "source_filename", Type: bigquery.StringFieldType, Required: true},
		{Name: "source_line", Type: bigquery.StringFieldType},
		{Name: "source_line_number", Type: bigquery.IntegerFieldType, Required: true},
		{Name: "line_executions", Type: bigquery.IntegerFieldType, Required: true},
	}

	coverageTable := dataset.Table("coverage_data")
	if err := coverageTable.Create(ctx, &bigquery.TableMetadata{
		Schema: coverageDataSchema,
		TimePartitioning: &bigquery.TimePartitioning{
			Field: "ingestion_time",
		},
		Clustering: &bigquery.Clustering{
			Fields: []string{"binary_hash", "collection_id"},
		},
	}); err != nil {
		if !strings.Contains(err.Error(), "Already Exists") &&
			!strings.Contains(err.Error(), "alreadyExists") &&
			!strings.Contains(err.Error(), "409") {
			return fmt.Errorf("create coverage_data table: %w", err)
		}
	} else {
		fmt.Println("Created table coverage_data")
	}

	// coverage_generators table
	generatorsSchema := bigquery.Schema{
		{Name: "ingestion_time", Type: bigquery.TimestampFieldType, Required: true},
		{Name: "software_group", Type: bigquery.StringFieldType},
		{Name: "binary_hash", Type: bigquery.StringFieldType, Required: true},
		{Name: "collection_id", Type: bigquery.StringFieldType, Required: true},
		{Name: "source_url", Type: bigquery.StringFieldType},
		{Name: "software_key", Type: bigquery.StringFieldType},
		{Name: "source_commit", Type: bigquery.StringFieldType},
		{Name: "generators", Type: bigquery.RecordFieldType, Repeated: true, Schema: bigquery.Schema{
			{Name: "namespace", Type: bigquery.StringFieldType},
			{Name: "owner", Type: bigquery.StringFieldType},
			{Name: "container", Type: bigquery.StringFieldType},
			{Name: "binary_name", Type: bigquery.StringFieldType},
		}},
	}

	generatorsTable := dataset.Table("coverage_generators")
	if err := generatorsTable.Create(ctx, &bigquery.TableMetadata{
		Schema: generatorsSchema,
		TimePartitioning: &bigquery.TimePartitioning{
			Field: "ingestion_time",
		},
		Clustering: &bigquery.Clustering{
			Fields: []string{"software_group", "binary_hash", "collection_id", "source_url"},
		},
	}); err != nil {
		if !strings.Contains(err.Error(), "Already Exists") &&
			!strings.Contains(err.Error(), "alreadyExists") &&
			!strings.Contains(err.Error(), "409") {
			return fmt.Errorf("create coverage_generators table: %w", err)
		}
	} else {
		fmt.Println("Created table coverage_generators")
	}

	return nil
}

// resolveSourceRepo finds the cloned source repository for a hash group using
// the same 3-strategy cascade as generateHTMLForOwner in render.go.
func resolveSourceRepo(owners []*OwnerReport, reposDir string, imageSources map[string]imageSource, mergedText string) (repoPath, moduleName string, workspaceModules map[string]string) {
	// Write merged text to temp file for package path extraction
	tmpFile, err := os.CreateTemp("", "bq-coverage-*.out")
	if err != nil {
		return "", "", nil
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)
	tmpFile.WriteString(mergedText)
	tmpFile.Close()

	packagePath := extractPackagePathFromCoverage(tmpPath)

	// Try each owner's image for Strategy 1
	for _, o := range owners {
		if o.Image == "" {
			continue
		}
		src, ok := imageSources[o.Image]
		if !ok {
			continue
		}
		candidate := findRepoByImageSource(reposDir, src)
		if candidate == "" {
			continue
		}
		// Validate module match
		if packagePath != "" {
			modName := getModuleName(candidate)
			if modName != "" && !strings.HasPrefix(packagePath, modName) {
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
					continue
				}
			}
		}
		repoPath = candidate
		break
	}

	// Strategy 2: Package path matching
	if repoPath == "" && packagePath != "" {
		repoPath = findMatchingRepository(reposDir, packagePath)
	}

	// Strategy 3: Owner name fallback
	if repoPath == "" {
		for _, o := range owners {
			repoPath = findRepoByOwnerName(reposDir, o.OwnerName)
			if repoPath != "" {
				break
			}
		}
	}

	if repoPath == "" {
		return "", "", nil
	}

	// Check for workspace modules
	workspaceModules = parseGoWorkModules(repoPath)
	if workspaceModules == nil {
		if wsRoot := findWorkspaceRoot(repoPath, reposDir); wsRoot != "" {
			workspaceModules = parseGoWorkModules(wsRoot)
			if workspaceModules != nil {
				repoPath = wsRoot
			}
		}
	}

	moduleName = getModuleName(repoPath)
	return repoPath, moduleName, workspaceModules
}

// resolveSourceURLForGroup finds the source_url and source_commit for a hash group.
func resolveSourceURLForGroup(owners []*OwnerReport, imageSources map[string]imageSource) (sourceURL, sourceCommit string) {
	for _, o := range owners {
		if o.Image == "" {
			continue
		}
		if src, ok := imageSources[o.Image]; ok {
			if src.SourceRepo != "" {
				return src.SourceRepo, src.CommitID
			}
		}
	}
	// Try host: synthetic keys
	for _, o := range owners {
		key := "host:" + o.BinaryName
		if src, ok := imageSources[key]; ok {
			if src.SourceRepo != "" {
				return src.SourceRepo, src.CommitID
			}
		}
	}
	return "", ""
}

// readSoftwareInfo reads software_group and software_key from the image_sources
// table for any of the owners in a hash group.
func readSoftwareInfo(owners []*OwnerReport, imageSources map[string]imageSource) (softwareGroup, softwareKey string) {
	for _, o := range owners {
		// Try container image key
		if o.Image != "" {
			if src, ok := imageSources[o.Image]; ok {
				if src.SoftwareGroup != "" && softwareGroup == "" {
					softwareGroup = src.SoftwareGroup
				}
				if src.SoftwareKey != "" && softwareKey == "" {
					softwareKey = src.SoftwareKey
				}
				if softwareGroup != "" && softwareKey != "" {
					return
				}
			}
		}
		// Try host: synthetic key
		key := "host:" + o.BinaryName
		if src, ok := imageSources[key]; ok {
			if src.SoftwareGroup != "" && softwareGroup == "" {
				softwareGroup = src.SoftwareGroup
			}
			if src.SoftwareKey != "" && softwareKey == "" {
				softwareKey = src.SoftwareKey
			}
			if softwareGroup != "" && softwareKey != "" {
				return
			}
		}
	}
	return
}

// buildCoverageDataRows parses merged coverage text and builds per-line
// CoverageDataRow entries. If repoPath is set, includes source line text.
func buildCoverageDataRows(mergedText, binaryHash, repoPath, moduleName string, workspaceModules map[string]string, ingestionTime time.Time) ([]CoverageDataRow, error) {
	// Write merged text to temp file for parsing
	tmpFile, err := os.CreateTemp("", "bq-merged-*.out")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	// Handle path rewriting for the coverage file (same as render)
	if err := os.WriteFile(tmpPath, []byte(mergedText), 0644); err != nil {
		return nil, fmt.Errorf("write temp file: %w", err)
	}

	covFileToUse := tmpPath
	if repoPath != "" {
		packagePath := extractPackagePathFromCoverage(tmpPath)
		if workspaceModules == nil {
			// Non-workspace: check if path rewriting is needed
			needsRewrite := false
			rewriteOldPath := packagePath

			if moduleName != "" && packagePath != "" && !strings.HasPrefix(packagePath, moduleName) {
				needsRewrite = true
			}

			if !needsRewrite && strings.Contains(mergedText, "/workspace/") && moduleName != "" {
				needsRewrite = true
				rewriteOldPath = "/workspace/"
			}

			if !needsRewrite && strings.Contains(mergedText, "/go/src/") {
				needsRewrite = true
				if moduleName != "" {
					rewriteOldPath = "/go/src/" + moduleName
				}
			}

			if needsRewrite {
				rewrittenFile, err := rewriteCoveragePaths(covFileToUse, rewriteOldPath, moduleName)
				if err == nil {
					covFileToUse = rewrittenFile
					defer os.Remove(rewrittenFile)
				}
			}
		}
	}

	profiles, err := cover.ParseProfiles(covFileToUse)
	if err != nil {
		return nil, fmt.Errorf("parse profiles: %w", err)
	}

	var rows []CoverageDataRow

	for _, profile := range profiles {
		// Resolve file path within the repo
		relPath := profile.FileName
		if workspaceModules != nil {
			if resolved := resolveWorkspacePath(relPath, workspaceModules); resolved != "" {
				relPath = resolved
			}
		} else if moduleName != "" && strings.HasPrefix(relPath, moduleName) {
			relPath = strings.TrimPrefix(relPath, moduleName)
			relPath = strings.TrimPrefix(relPath, "/")
		}

		// Try to read source file
		var sourceLines []string
		if repoPath != "" {
			absPath := filepath.Join(repoPath, relPath)
			if data, err := os.ReadFile(absPath); err == nil {
				sourceLines = strings.Split(string(data), "\n")
			}
		}

		// Compute per-line execution counts from profile blocks
		// Determine total lines from source or profile
		totalLines := len(sourceLines)
		if totalLines == 0 {
			// Estimate from profile blocks
			for _, block := range profile.Blocks {
				if block.EndLine > totalLines {
					totalLines = block.EndLine
				}
			}
		}

		if totalLines == 0 {
			continue
		}

		// Build per-line execution counts (1-indexed)
		lineCounts := make([]int, totalLines+1)
		for i := range lineCounts {
			lineCounts[i] = -1 // -1 = not tracked
		}
		for _, block := range profile.Blocks {
			for line := block.StartLine; line <= block.EndLine && line <= totalLines; line++ {
				if block.Count > lineCounts[line] {
					lineCounts[line] = block.Count
				}
			}
		}

		// Emit one row per line
		for lineNum := 1; lineNum <= totalLines; lineNum++ {
			sourceLine := ""
			if lineNum <= len(sourceLines) {
				sourceLine = sourceLines[lineNum-1]
			}

			rows = append(rows, CoverageDataRow{
				IngestionTime:    ingestionTime,
				BinaryHash:       binaryHash,
				CollectionID:     bqCollection,
				SourceFilename:   profile.FileName,
				SourceLine:       sourceLine,
				SourceLineNumber: lineNum,
				LineExecutions:   lineCounts[lineNum],
			})
		}
	}

	return rows, nil
}
