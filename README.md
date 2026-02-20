# coverage-collector CLI

A command-line tool for processing Go code coverage collected from running
applications across an entire OpenShift/Kubernetes cluster. It downloads
coverage data from S3, compiles it into a SQLite database, clones source
repositories, and generates interactive HTML reports with annotated source code.

A "collection" can span multiple cluster lifecycles and is not tied to a single
cluster instance.

## Installation

### Build from source

```bash
go build -o coverage-collector ./cmd/coverage-collector
```

Or install directly:

```bash
go install github.com/jupierce/cluster-code-coverage-analysis/cmd/coverage-collector@latest
```

## How It Works

Go binaries built with `-cover` can be linked with a small HTTP coverage server
that serves binary coverage data on a well-known port (default 53700+). A
coverage producer running on the cluster collects this data and uploads it to
S3. This tool downloads that data and processes it into interactive HTML reports.

Coverage data is **cumulative**: Go's in-process counters record every code path
executed since the process started. Multiple collections accumulate additional
`covcounters.*` files, so no data is lost. When the data is compiled and
rendered, all counter files are merged to produce combined reports.

Lines originating from `coverage_server.go` (the embedded HTTP server) are
automatically filtered out of all reports.

## Workflow

The primary workflow uses the `cluster` command group. Run these subcommands in
order:

```
coverage-collector cluster download      --collection <name>  # Download from S3
coverage-collector cluster compile       --collection <name>  # Build SQLite DB
coverage-collector cluster clone-sources --collection <name>  # Clone source repos
coverage-collector cluster render        --collection <name>  # Generate HTML
```

### 1. `cluster download`

Download coverage data (covmeta and covcounters files) from an S3 bucket.
Generates `metadata.json` for each coverage entry from S3 path components.

```bash
coverage-collector cluster download --collection my-collection \
  --bucket art-ocp-code-coverage \
  --prefix openshift-ci/coverage \
  --profile saml \
  --region us-east-1

# Skip already-downloaded entries
coverage-collector cluster download --collection my-collection \
  --bucket art-ocp-code-coverage \
  --prefix openshift-ci/coverage \
  --skip-existing
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--bucket` | *(required)* | S3 bucket name |
| `--prefix` | *(required)* | S3 path prefix |
| `--profile` | | AWS CLI profile |
| `--region` | | AWS region |
| `--skip-existing` | false | Skip entries that already have local data |

### 2. `cluster compile`

Process raw coverage data into an SQLite database. This step:

- Converts binary coverage to text format via `go tool covdata textfmt`
- Filters out `coverage_server.go` lines
- Groups reports by owner (Deployment, DaemonSet, StatefulSet, Job, Host, Pod)
- Merges coverage from multiple pods of the same owner/binary
- Resolves source repository URLs from `info.json` files and image labels
- Computes per-file coverage statistics

Change detection uses MD5 hashes; only changed reports are reprocessed.

```bash
# Incremental compile
coverage-collector cluster compile --collection my-collection

# Force full recompilation
coverage-collector cluster compile --collection my-collection --update '*'

# Force recompilation for a specific namespace
coverage-collector cluster compile --collection my-collection \
  --update 'namespace=openshift-apiserver'
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--update` | | Force recomputation (repeatable, AND logic). Use `'*'` for all, or `field=glob` for `namespace`, `node`, `container`, `image` |

### 3. `cluster clone-sources`

Clone source repositories identified during compile. Uses `source_url` and
`source_commit` from the `image_sources` table to clone at the exact commit.

```bash
coverage-collector cluster clone-sources --collection my-collection
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--skip-existing` | true | Skip already-cloned repositories |

### 4. `cluster render`

Generate HTML reports from the compiled database. Produces one HTML report per
unique binary (identified by covmeta hash), plus an interactive `index.html`.

Multiple owners running the same binary share a single HTML report. The index
shows all owners with their individual metadata, linking to the shared report.

```bash
# Render to the default location (<collection>/html/)
coverage-collector cluster render --collection my-collection

# Render to a custom directory
coverage-collector cluster render --collection my-collection \
  --output-dir my-collection/html-post-e2e

# Only generate the index (skip per-binary HTML)
coverage-collector cluster render --collection my-collection \
  --skip-component-html
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--output-dir` | `<collection>/html` | Output directory for HTML reports |
| `--skip-component-html` | false | Only generate the index |

### Shared cluster flags

These flags apply to all `cluster` subcommands:

| Flag | Default | Description |
|------|---------|-------------|
| `--collection` | *(required)* | Collection name; also used as the working directory |
| `--verbosity` | info | Log verbosity: `error`, `info`, `debug`, `trace` |
| `--max-concurrency` | 8 | Maximum concurrent operations |

## Directory Structure

After a full run, the collection directory looks like:

```
<collection>/
  coverage/                 # Raw coverage data from S3
    <ns>-<pod>-<container>/
      metadata.json         # Pod/container/binary info
      info.json             # Source URL/commit (from S3 producer)
      covmeta.<hash>        # Coverage metadata (deterministic per binary)
      covcounters.<hash>    # Coverage counters (unique per collection)
  coverage.db               # SQLite database (~7GB for a full cluster)
  repos/                    # Cloned source repositories
    github.com/<org>/<repo>/<commit-prefix>/
  html/                     # Generated HTML reports
    index.html              # Interactive dashboard
    <hash>.html             # Per-binary coverage reports (named by covmeta hash)
  logs/                     # Timestamped log files
```

## Interactive Index

The generated `index.html` provides:

- **Search** by namespace, owner name, container, or binary
- **Filter** by namespace, owner type, or coverage level
- **Sort** by any column (namespace, owner, container/binary, coverage %,
  statements)
- **Color-coded** coverage: Excellent (>=70%), Good (>=50%), Moderate (>=30%),
  Poor (>=15%), Critical (<15%)
- **Click-through** to per-binary HTML reports with annotated source code
- **Expandable rows** showing pods, hosts, and image details
- **Checkbox filters** to hide e2e-* and openshift-must-gather-* namespaces
  (checked by default)
- **Deduplicated stats**: Overall coverage percentages are computed by unique
  binary hash, so the same binary running in multiple owners is only counted
  once

## Per-Binary HTML Reports

Each `<hash>.html` report includes:

- **Collapsible header** listing all owner groups that run this binary
  (namespace, type, owner, containers, pod count, hosts)
- **Stat cards** with source file count, overall coverage %, total and covered
  statements
- **File table** with search, coverage level filter, and sortable columns
- **Source code viewer** with line numbers, green/red coverage highlighting,
  and per-line execution counts
- **Split view** mode for viewing the file list alongside source code
- **Deep linking** via URL hash (`#file0`, `#file1`, etc.)
- **Unresolved files**: Files without cloned source show "No source code
  resolved for this file" with their coverage stats still computed

## Owner Grouping

Reports are grouped by owner type, inferred from pod name patterns:

| Pattern | Owner Type |
|---------|------------|
| `name-<hash>-<5char>` | Deployment |
| `name-<number>` | StatefulSet |
| `name-<5char>` | DaemonSet |
| `installer-*`, `pruner-*` | Job |
| Host-level processes | Host |
| Unrecognized pods | Pod (No Owner) |

Owners with the same binary (same covmeta hash) share a single HTML report.
This prevents inflated statement counts when the same binary runs in multiple
pods with different names (e.g., static pods with per-node names).

## Source Repository Resolution

The tool uses a 3-strategy cascade to find source code for annotated reports:

1. **Image labels** (fast): Looks up `io.openshift.build.source-location` /
   `io.openshift.build.commit.id` from container image labels or `info.json`.
   Validates that the repo's Go module matches the coverage package path.
2. **Package path matching**: Walks cloned repos and scores by Go module prefix
   match.
3. **Owner name fallback**: Matches owner name to repository directory names.

For host binaries (no container image), source info comes from `info.json` files
using synthetic `host:<binary_name>` keys.

## Prerequisites

1. **Coverage data in S3**: The coverage producer must have uploaded covmeta and
   covcounters files to the configured S3 bucket.

2. **Go toolchain**: Required for `go tool covdata textfmt` (converting binary
   coverage to text format).

3. **AWS CLI**: Required by `download` to fetch data from S3.

4. **Git**: Required by `clone-sources` to clone repositories.

5. **`oc` CLI** *(optional)*: Used during `compile` to inspect container image
   labels for source repository info. Falls back to `info.json` if unavailable.

## Acknowledgments

The coverage HTTP client was derived from
[psturc/go-coverage-http](https://github.com/psturc/go-coverage-http).
