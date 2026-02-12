# coverage-collector CLI

A command-line tool for collecting Go code coverage from running applications
across an entire Kubernetes cluster. It discovers coverage-enabled pods, clones
source repositories, retrieves coverage data via HTTP port-forwarding, and
generates interactive HTML reports -- all without requiring `GOCOVERDIR` or
volume mounts.

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
that serves binary coverage data on a well-known port (default 53700+). When
such a binary runs inside a Kubernetes pod, `coverage-collector` uses the
Kubernetes port-forward API to reach that endpoint and download `covmeta.*` /
`covcounters.*` files without any special volume configuration.

Coverage data is **cumulative**: Go's in-process counters record every code path
executed since the process started. Running `collect` multiple times (e.g. before
and after an integration test suite) accumulates additional `covcounters.*` files
with unique names, so no data is lost.  When `render` runs, it merges all counter
files for each pod and produces a combined report.

Lines originating from `coverage_server.go` (the embedded HTTP server) are
automatically filtered out of all reports. Vendor code is excluded at the build
level by Go's coverage instrumentation and does not appear in reports.

## Workflow

The primary workflow uses the `cluster` command group.  Run these subcommands in
order:

```
coverage-collector cluster discover      --cluster <name>
coverage-collector cluster clone-sources --cluster <name>
coverage-collector cluster collect       --cluster <name>
coverage-collector cluster render        --cluster <name>
```

### 1. `cluster discover`

Scan the cluster for all pods, inspect their container images, and identify which
ones were built with coverage enabled.  Produces a **discovery plan**
(`<cluster>/discovery-plan.json`) that drives subsequent steps.

```bash
# Discover all coverage-enabled pods
coverage-collector cluster discover --cluster my-cluster

# Restrict to specific namespaces
coverage-collector cluster discover --cluster my-cluster \
  --namespaces openshift-monitoring,openshift-operators

# Skip image inspection (faster, but fewer details in the plan)
coverage-collector cluster discover --cluster my-cluster --skip-inspection
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--namespaces` | *(all)* | Comma-separated namespaces to scan |
| `--max-concurrency` | 10 | Concurrent image inspections |
| `--skip-inspection` | false | Skip image inspection |
| `--registry-config` | *(auto)* | Path to registry credentials JSON |

### 2. `cluster clone-sources`

Clone the Git repositories identified by discovery at the exact commits used to
build each image.  Sources are stored under `<cluster>/repos/` and are used by
`render` to produce HTML reports with annotated source code.

```bash
coverage-collector cluster clone-sources --cluster my-cluster

# Increase parallelism
coverage-collector cluster clone-sources --cluster my-cluster --max-concurrency 10
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--max-concurrency` | 5 | Concurrent git clones |
| `--skip-existing` | true | Skip already-cloned repositories |

### 3. `cluster collect`

Connect to every coverage-enabled container discovered in step 1 and download
its binary coverage data via port-forward.

```bash
coverage-collector cluster collect --cluster my-cluster
```

Coverage files are saved under `<cluster>/coverage/<namespace>/<pod>/<container>/`.
Each collection writes new `covcounters.*` files with unique names, so running
`collect` again after exercising additional code paths adds to the existing data
rather than replacing it.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--max-concurrency` | 5 | Concurrent coverage collections |
| `--process-reports` | false | Generate per-pod HTML reports during collection |
| `--use-sources` | true | Use cloned sources for path remapping |

### 4. `cluster render`

Merge per-pod coverage by owner (Deployment, DaemonSet, StatefulSet, Job),
generate an HTML report for each owner with annotated source code, and build an
interactive `index.html`.

```bash
# Render to the default location (<cluster>/html/)
coverage-collector cluster render --cluster my-cluster

# Render to a custom directory (useful for before/after comparisons)
coverage-collector cluster render --cluster my-cluster \
  --output-dir my-cluster/html-post-e2e
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--output-dir` | `<cluster>/html` | Output directory for HTML reports |
| `--skip-html` | false | Only generate the index (skip per-owner HTML) |

### Shared cluster flags

These flags apply to all `cluster` subcommands:

| Flag | Default | Description |
|------|---------|-------------|
| `--cluster` | *(required)* | Cluster name; also used as the working directory |
| `--verbosity` | info | Log verbosity: `error`, `info`, `debug`, `trace` |
| `--kubeconfig` | *(auto)* | Path to kubeconfig (`$KUBECONFIG` or `~/.kube/config`) |

## Lifecycle Coverage (Before/After Comparisons)

Because counter files accumulate, you can capture coverage at different points
in a cluster's lifecycle:

```bash
# 1. After fresh install
coverage-collector cluster collect --cluster my-cluster
coverage-collector cluster render  --cluster my-cluster --output-dir my-cluster/html-baseline

# 2. Run your integration / e2e tests against the cluster

# 3. Collect again -- new counters are added alongside the existing ones
coverage-collector cluster collect --cluster my-cluster
coverage-collector cluster render  --cluster my-cluster --output-dir my-cluster/html-post-e2e
```

The post-e2e report will reflect all code executed since each pod started,
including both the baseline behavior and the additional paths exercised by the
test suite.  Coverage percentages will only stay the same or increase.

## Single-Pod Collection

A standalone `collect` command is available for collecting coverage from an
individual pod outside the cluster workflow:

```bash
# By pod name
coverage-collector collect --pod my-pod-12345 --test-name my-test

# By label selector
coverage-collector collect --label app=my-app --test-name my-test --namespace prod
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `-p, --pod` | | Pod name (mutually exclusive with `--label`) |
| `-l, --label` | | Label selector (mutually exclusive with `--pod`) |
| `-c, --container` | *(auto)* | Container name |
| `-t, --test-name` | *(required)* | Subdirectory name for output |
| `--port` | 53700 | Coverage server starting port |
| `--source-dir` | *(cwd)* | Source directory for path remapping |
| `--no-path-remap` | false | Disable path remapping |
| `--timeout` | 60 | Timeout in seconds |
| `-n, --namespace` | default | Kubernetes namespace |
| `-o, --output-dir` | ./coverage-output | Output directory |

One of `--pod` or `--label` must be provided.

## Directory Structure

After a full run, the cluster directory looks like:

```
<cluster>/
  discovery-plan.json       # Output of discover
  clone-summary.json        # Output of clone-sources
  logs/                     # Timestamped log files
  repos/                    # Cloned source repositories
  coverage/                 # Per-pod binary coverage data
    <namespace>/
      <pod>/
        <container>/
          covmeta.*          # Coverage metadata (deterministic per binary)
          covcounters.*      # Coverage counters (unique per collection)
          coverage.out       # Generated text format
          coverage_filtered.out
  html/                     # Rendered HTML reports (default output-dir)
    index.html              # Interactive index with filtering & sorting
    <owner>.html            # Per-owner coverage report with source code
```

## Interactive Index

The generated `index.html` provides:

- **Search** by namespace, owner name, or container
- **Filter** by namespace dropdown
- **Sort** by any column (namespace, owner, type, container, coverage %, statements)
- **Color-coded** coverage percentages (red < 25%, orange < 50%, yellow < 75%, green >= 75%)
- **Click-through** to individual HTML reports showing annotated source code

## Prerequisites

1. **Coverage-enabled binaries**: Applications must be built with Go's `-cover`
   flag and linked with an HTTP coverage server listening on port 53700+.

2. **Kubernetes access**: A valid kubeconfig or in-cluster RBAC permissions with
   access to list pods and create port-forwards.

3. **Go toolchain**: The `go` command is required for `go tool covdata textfmt`
   (converting binary coverage to text) and for HTML report generation.

4. **Git**: Required by `clone-sources` to clone repositories.

## Environment Variables

- `KUBECONFIG` -- Path to kubeconfig file (overridden by `--kubeconfig` flag)

## Exit Codes

- `0` -- Success
- `1` -- Error

## Acknowledgments

The coverage HTTP client was derived from
[psturc/go-coverage-http](https://github.com/psturc/go-coverage-http).
