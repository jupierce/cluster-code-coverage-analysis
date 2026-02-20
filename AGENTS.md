# Cluster Code Coverage Analysis

Go CLI tool that downloads, compiles, and renders Go code coverage data
collected from instrumented binaries running on a live OpenShift cluster.
Unlike traditional test coverage, this measures which code paths are exercised
during cluster operation (integration/E2E testing, steady-state runtime, etc.).

## Workflow

```
coverage-collector cluster download      # Download coverage data from S3
coverage-collector cluster compile       # Process into SQLite database
coverage-collector cluster clone-sources # Clone source repos for HTML annotation
coverage-collector cluster render        # Generate HTML reports from database
```

Each step is incremental: hash-based change detection skips unchanged data.

## Project Structure

```
cmd/coverage-collector/
  main.go              # Root cobra command
  cluster.go           # Cluster command group, shared flags, logger
  download.go          # S3 download subcommand (aws cli)
  compile.go           # SQLite compilation (textfmt, merge, stats, image/info.json inspection)
  clone_sources.go     # Git clone subcommand (reads image_sources from DB)
  render.go            # HTML report generation (hash-group based), index.html template
  render_custom_html.go # Per-file source annotation HTML renderer + template
pkg/
  log/                 # Logger package
reports/               # Collection data directories (gitignored)
```

## Build & Run

```bash
go build ./cmd/coverage-collector/

# Full pipeline
./coverage-collector cluster download --collection <name> \
  --bucket <s3-bucket> --prefix <s3-prefix> --profile <aws-profile> --region <region>
./coverage-collector cluster compile --collection <name> [--update '*']
./coverage-collector cluster clone-sources --collection <name>
./coverage-collector cluster render --collection <name>
```

## Dependencies

- `go tool covdata` (Go toolchain, for textfmt conversion)
- `oc` (OpenShift CLI, for image label inspection -- optional)
- `git` (for clone-sources)
- `aws` CLI (for S3 download)
- `golang.org/x/tools/cover` (coverage profile parsing)
- `github.com/spf13/cobra` (CLI framework)
- `modernc.org/sqlite` (pure Go SQLite driver, no CGo)

## Database Schema (v4)

| Table | Purpose |
|-------|---------|
| `report_sources` | One row per coverage directory (raw reports) |
| `owners` | One row per owner/binary/covmetaHash group (merged results) |
| `owner_reports` | Many-to-many join (owner <-> reports) |
| `owner_file_stats` | Per-file coverage stats for each owner |
| `image_sources` | Image ref (or `host:<binary>`) -> source repo URL + commit ID |
| `schema_version` | Tracks schema version for migrations |

The database (`coverage.db`) stores all coverage text, merged results, per-file
stats, and image source mappings. Typically ~7GB for a full cluster.

## Data Directory Layout

```
reports/<collection>/
  coverage/           # Raw coverage data (covmeta + covcounters per report)
    <ns>-<pod>-<container>/
      metadata.json   # Pod/container/binary info
      info.json       # Source URL/commit from S3 (if available)
      covmeta.<hash>  # Binary coverage metadata
      covcounters.*   # Binary coverage counters
  coverage.db         # SQLite database (compiled results)
  repos/              # Cloned source repositories
    github.com/<org>/<repo>/<commit-prefix>/
  html/               # Generated HTML reports
    index.html        # Interactive dashboard
    <hash>.html       # Per-binary coverage reports (named by covmeta hash)
  logs/               # Log files
```

---

## Step 1: Download (`download.go`)

Downloads coverage data from S3. The coverage producer (running in the kubelet
or as a sidecar) uploads coverage data in a structured S3 path layout. This
command downloads it and generates `metadata.json` files from S3 path components.

Flags: `--bucket`, `--prefix`, `--profile`, `--region`, `--skip-existing`

## Step 2: Compile (`compile.go`)

Processes raw coverage data into the SQLite database.

### Processing Pipeline

1. **Scan** `coverage/` for report directories containing `covmeta.*` files
2. **Hash-based change detection**: MD5 of binary coverage files (`input_hash`).
   Only changed reports are reprocessed. Use `--update '*'` to force all.
3. **Text conversion**: `go tool covdata textfmt` converts binary to text format
4. **Filter**: Remove `coverage_server.go` lines (injected infrastructure code)
5. **Parse**: Extract total/covered statements from text format
6. **Insert** into `report_sources` table

### Owner Grouping

Reports are grouped into owners by:
- **Group key**: `namespace/ownerType/ownerName/binaryName/covmetaHash`
- **Owner type detection** (`extractOwnerInfoCompile`):
  - `name-<number>` -> StatefulSet
  - `name-<8-10char>-<5char>` -> Deployment (ReplicaSet pattern)
  - `installer-*` / `pruner-*` patterns -> Job
  - `name-<5char>` -> DaemonSet
  - Fallthrough -> `Pod (No Owner)` with empty owner name
- **Host binaries**: `namespace="host"`, `ownerType="Host"`, `ownerName=binaryName`
- **Covmeta hash**: MD5 of statement definitions (ignoring execution counts).
  Identifies the same compiled binary regardless of which image/container runs it.
  Used in the group key so that the same binary from different images merges
  into a single owner.

### Coverage Merging

`mergeCoverageTexts()` merges multiple coverage texts by taking the max
execution count per coverage block. This combines coverage data from multiple
pods running the same binary.

### Image Source Resolution

Two mechanisms populate the `image_sources` table:

1. **info.json** (`populateImageSourcesFromInfoJSON`): Scans report directories
   for `info.json` files containing `source_url` and `source_commit` fields.
   Works for both container and host reports. Host reports use synthetic keys
   `host:<binary_name>` since they have no container image.

2. **Image label inspection** (`inspectImages`): Uses `oc image info -o json`
   to read `io.openshift.build.source-location` and
   `io.openshift.build.commit.id` labels from container images. Includes
   fallbacks for manifest lists (`--filter-by-os=linux/amd64`) and release
   payloads (`oc adm release info --image-for`).

### Compile Flags

- `--update '*'`: Force full recompilation
- `--update 'namespace=openshift-*'`: Force specific namespace (glob)
- `--update 'container=machine-config*'`: Force specific container
- Multiple `--update` flags use AND logic

## Step 3: Clone Sources (`clone_sources.go`)

Clones source repositories identified during compile.

- Reads `(source_repo, commit_id)` pairs from `image_sources` table
- Clones to `repos/<host>/<org>/<repo>/<commit-prefix>/`
- `--skip-existing` (default true) avoids re-cloning
- Concurrent cloning with `--max-concurrency`

## Step 4: Render (`render.go`, `render_custom_html.go`)

Generates HTML reports from the SQLite database.

### Hash-Group Based HTML Generation

One HTML file is generated per unique covmeta hash, not per owner. This means
multiple index rows can link to the same `<hash>.html` file.

**Flow:**

1. **Load owners** from DB via `loadOwnersForRender()`
2. **Enrich** with commit IDs and compute `CovmetaHash` for each owner
3. **Group by covmeta hash** into `hashGroup` structs
4. **Merge coverage stats** for multi-owner groups: `mergeCoverageTexts()` on
   all owners' coverage, then update all owners' `TotalStmts`/`CoveredStmts`/
   `Coverage` to show the combined numbers in the index
5. **Cache check**: Combined cache key from sorted `MergeInputHash` values.
   Checks for embedded `<!-- coverage-hash: ... -->` comment in existing HTML.
6. **Parallel generation** of uncached groups (controlled by `--max-concurrency`):
   - Build synthetic `OwnerReport` via `buildSyntheticOwner()`:
     - Union of all pods, containers, hosts across owners in the group
     - Pick best image for source resolution (prefer one with resolved source repo)
     - Populate `HashGroupOwners` for the collapsible details in HTML
   - Pre-set `HTMLFile = "<hash>.html"` on synthetic owner
   - Write merged coverage text to temp file
   - Call `generateHTMLForOwner()` -> `renderCustomCoverageHTML()`
   - Set `HTMLFile` and `HasHTML` on ALL owners in the group

### Source Repository Resolution (3-strategy cascade)

`generateHTMLForOwner()` finds the source repo for annotated HTML:

1. **Strategy 1: Image labels** (fast, O(1)): Look up `image_sources` table.
   **With validation**: After finding a repo, check that its Go module name
   matches the coverage package path. Images can contain multiple binaries from
   different repos (e.g., multus image contains bridge, egress-router,
   whereabouts from containernetworking/plugins). If the module doesn't match,
   fall through to Strategy 2. Also checks `go.work` workspace modules.

2. **Strategy 2: Package path matching** (slower, walks `repos/`):
   `findMatchingRepository()` scores repos by module prefix match (100),
   repo name match (50), partial containment (25), special cases like
   prometheus-operator migration (90).

3. **Strategy 3: Owner name fallback** (slowest, walks `repos/`):
   `findRepoByOwnerName()` matches owner name to repo directory names.

### Path Rewriting

Coverage files reference source paths as compiled. These often don't match
the repo structure:

- `/workspace/pkg/file.go` -> container build paths
- `/go/src/github.com/org/repo/pkg/file.go` -> GOPATH mode builds
- Module path migrations (e.g., `coreos/prometheus-operator` ->
  `prometheus-operator/prometheus-operator`)

`rewriteCoveragePaths()` handles these. For monorepos with `go.work`,
`parseGoWorkModules()` and `resolveWorkspacePath()` map module paths to
workspace subdirectories.

### Custom HTML Renderer (`render_custom_html.go`)

`renderCustomCoverageHTML()` generates self-contained HTML with:

- **Header**: For hash-group reports, shows binary name with collapsible
  `<details>` section listing all owner groups (namespace, type, owner,
  binary, containers, pod count, hosts). For single-owner reports, shows
  the owner's namespace/type/name.
- **Stat cards**: Source files, overall coverage %, total statements,
  covered statements, distribution badges
- **File table**: Searchable, filterable, sortable columns
- **Source viewer**: Line numbers, coverage highlighting (`cov-hit` green,
  `cov-none` red), per-line execution counts
- **Split view**: File list alongside source code
- **URL hash deep linking**: `#file0`, `#file1`, etc.
- **256KB buffered writer**: Handles large files (some reports 10MB+)

**Unresolved source files**: Files that can't be resolved to source code on
disk are included in the report with a `<div class="no-source">No source code
resolved for this file</div>` placeholder. Coverage stats for these files are
still computed from the coverage profile data.

**Stats fallback**: When no source files could be resolved at all (repo not
cloned), the template falls back to the owner's DB-level stats
(`owner.TotalStmts` / `owner.CoveredStmts`) so the HTML report still shows
correct coverage numbers.

### Index HTML (`ownerIndexTemplate`)

Interactive dashboard with:

- **Stat cards**: Total owners, pods, overall coverage %, statements
- **Coverage distribution badges**: Excellent (>=70%), Good (>=50%),
  Moderate (>=30%), Poor (>=15%), Critical (<15%)
- **Filters**:
  - Text search (namespace, owner, container, binary)
  - Namespace dropdown
  - Owner type dropdown (Deployment, DaemonSet, StatefulSet, Job, Host,
    Pod (No Owner))
  - Coverage level dropdown
  - Checkbox: "Hide e2e-* namespace entries" (default checked)
  - Checkbox: "Hide openshift-must-gather-* namespace entries" (default checked)
- **Sortable columns**: Namespace, Owner, Container/Binary, Coverage,
  Statements
- **Expandable rows**: Click to see pods, hosts, images details
- **Stats deduplication**: Both Go `calculateOwnerStats()` and JavaScript
  `updateStats()` deduplicate by covmeta hash so the same binary isn't
  counted multiple times in overall totals

**Owner type display**:
- "Pod (No Owner)" uses CSS class `pod-no-owner` (parens/spaces break CSS
  selectors) and suppresses owner name display (like Host)
- Each row stores `data-covmeta-hash`, `data-statements`, `data-covered-stmts`
  for JS-side stats deduplication

### Stale HTML Cleanup

After generating the index, render removes any `.html` files in the output
directory that are not referenced by current owners (`index.html` is always
kept). This cleans up files from previous runs that are no longer needed.

---

## Key Design Decisions

- **SQLite via modernc.org/sqlite**: Pure Go driver (no CGo). Single-file
  database for portability.
- **Incremental processing**: Both compile and render use hash-based change
  detection. Compile tracks `input_hash` (MD5 of binary files) and
  `merge_input_hash`. Render checks HTML files for embedded
  `<!-- coverage-hash: ... -->` comment.
- **Covmeta hash grouping**: One HTML per unique binary hash solves the problem
  of static pods with per-node names (e.g., `kube-apiserver-ip-10-0-29-251...`)
  creating separate owner groups for the same binary. Without this, total_stmts
  were inflated by ~50% and overall coverage was artificially low (~9% vs ~15%).
- **info.json source resolution**: The S3 coverage producer includes an
  `info.json` alongside coverage files with `source_url` and `source_commit`.
  This provides source info for host binaries (which have no container image
  labels) and serves as an alternative to `oc image info` inspection.
- **Strategy 1 validation**: Image labels can point to the wrong repo when an
  image contains multiple binaries from different source repos. The module
  match check prevents using the wrong repo for source annotation.

## Known Issues and Edge Cases

1. **Third-party binaries without cloned repos**: CNI plugins like bridge,
   egress-router, whereabouts come from `containernetworking/plugins` which
   may not be cloned. Reports show correct stats but files display "No source
   code resolved for this file".
2. **Coverage server lines**: The injected `coverage_server.go` is filtered
   out by `filterCoverageServerLines()` since it's infrastructure code.
3. **Binary name from os.Executable()**: Returns the actual binary name on
   disk, which may differ from the container name or repository name.
4. **Host report deduplication**: Host-level coverage reports for processes
   also visible as pod containers are deduplicated during compile.
5. **Multiple coverage servers per pod**: Sequential port scanning
   (53700-53799) handles pods with multiple instrumented binaries.

## Module Path

`github.com/jupierce/cluster-code-coverage-analysis`
