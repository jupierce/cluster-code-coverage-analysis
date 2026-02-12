# AGENTS.md - Project Knowledge Base

This document captures institutional knowledge about the cluster code coverage analysis tool for future AI agents working on this codebase.

## Project Purpose

This tool collects Go code coverage data from **running binaries** on an OpenShift cluster. Unlike traditional test coverage, this measures which code paths are exercised during normal cluster operation (integration/E2E testing, steady-state runtime, etc.). The coverage data is collected live from instrumented binaries via an embedded HTTP coverage server, then rendered into interactive HTML reports.

## Architecture Overview

### CLI Commands (`cmd/coverage-collector/`)

The tool is a Cobra-based CLI with these subcommands:

| Command | File | Purpose |
|---------|------|---------|
| `discover` | `cluster.go` | Scan cluster for coverage-enabled pods |
| `collect` | `cluster.go` | Collect coverage data from discovered pods |
| `clone` | `cluster.go` | Clone source repositories for HTML generation |
| `render` | `render.go` | Generate HTML coverage reports |

### Key Packages

| Package | Purpose |
|---------|---------|
| `pkg/cluster/discover.go` | Kubernetes API discovery of pods/images |
| `pkg/cluster/collect.go` | Coverage collection orchestration (concurrent workers) |
| `pkg/cluster/clone.go` | Git clone of source repos based on image labels |
| `pkg/cluster/image.go` | Image inspection and coverage detection |
| `pkg/cluster/auth.go` | Registry authentication |
| `client/client.go` | Low-level coverage client (port forwarding, HTTP) |

## Coverage Server Protocol

Instrumented OpenShift binaries embed a coverage HTTP server. Key details:

- **Port**: 53700 (primary), with sequential scanning up to 53799
- **Identity Headers**: The server responds with:
  - `X-Art-Coverage-Server: true` - confirms it's a coverage server
  - `X-Art-Coverage-Binary: <binary-name>` - the Go binary name (from `os.Executable()`)
  - `X-Art-Coverage-Pid: <pid>` - process ID
- **Endpoints**:
  - `GET /` - returns identity headers (used for health check / scanning)
  - `GET /coverage` - returns binary coverage data (covmeta + covcounters format)
- **Multiple servers per pod**: A single pod can have multiple containers, each running different binaries, each with its own coverage server on a different port. The client scans ports sequentially to find all servers.

## Coverage Detection (Image Inspection)

Coverage-enabled images are detected in `pkg/cluster/image.go` via two methods:

1. **Environment variable**: `GO_COMPLIANCE_COVER=1` (legacy method, no longer present in newer builds)
2. **OpenShift build labels** (current method): If an image has both:
   - `io.openshift.build.commit.id`
   - `io.openshift.build.source-location`

   These labels indicate the image was built by the same CI system that injects the coverage server.

## Coverage Data Pipeline

```
Pod (binary coverage server on port 53700+)
  ↓ collect (port-forward + HTTP GET /coverage)
Binary coverage data (covmeta.* + covcounters.* files)
  ↓ go tool covdata textfmt
Text coverage format (coverage.out)
  ↓ filter coverage_server.go lines
Filtered coverage (coverage_filtered.out)
  ↓ merge by owner+binary
Merged coverage file (*-merged.out)
  ↓ custom HTML renderer
Interactive HTML report (*.html)
```

### Data Formats

- **Binary format**: `covmeta.<hash>` and `covcounters.<hash>` files - raw Go coverage data
- **Text format** (`coverage.out`): Standard Go coverage profile format:
  ```
  mode: set
  github.com/org/repo/pkg/file.go:10.20,15.30 3 1
  ```
  Format: `filepath:startline.startcol,endline.endcol numstatements count`
- **Filtered format** (`coverage_filtered.out`): Same as text but with `coverage_server.go` lines removed (the injected server code itself shouldn't count toward coverage)

### Collection Directory Structure

```
<cluster-name>/
  coverage/
    <namespace>-<pod>-<container>/
      metadata.json        # Pod/container/binary info
      covmeta.<hash>       # Binary coverage metadata
      covcounters.<hash>   # Binary coverage counters
      coverage.out         # Generated text format
      coverage_filtered.out # Filtered text format
  repos/
    github.com/<org>/<repo>/<commit>/  # Cloned source
  html/
    index.html             # Interactive index
    *.html                 # Per-owner+binary reports
    *-merged.out           # Merged coverage files
```

## Report Grouping

Reports are grouped by **owner + binary name**:
- Key format: `namespace/ownerType/ownerName/binaryName`
- Owner type is inferred from pod name patterns:
  - `name-<hash>-<hash>` → Deployment
  - `name-<ordinal>` → StatefulSet
  - `name-<5char>` → DaemonSet
- **Binary name != container name**: A container named `openshift-apiserver-check-endpoints` might run a binary called `cluster-kube-apiserver-operator`. The binary name comes from the coverage server's `X-Art-Coverage-Binary` header.
- Different binaries in the same owner get separate rows in reports.

## Custom HTML Renderer (`render_custom_html.go`)

Replaced `go tool cover -html` with a custom renderer that:

1. Uses `golang.org/x/tools/cover.ParseProfiles()` to parse merged coverage files
2. Uses `Profile.Boundaries(src)` to get byte-offset coverage span markers
3. Generates annotated source HTML with `<span class="cov-hit">` (green) and `<span class="cov-none">` (red)
4. Produces self-contained HTML with:
   - File table view with search, coverage level filter, sortable columns
   - Source code viewer with line numbers and coverage highlighting
   - Split view mode (file list alongside source)
   - URL hash deep linking (`#file0`, `#file1`, etc.)
   - Same visual design as index.html (stat cards, coverage bars, badges)

### Why Not `go tool cover -html`?

The old approach had problems:
- Required Go module resolution from the repo directory (slow, error-prone)
- Needed `GOFLAGS=-mod=mod`, `GOWORK=off`, `GOTOOLCHAIN=auto` environment vars
- Produced ugly default UI (black background, basic dropdown)
- Failed for ~8% of reports due to module resolution issues
- The custom renderer achieves ~99% success rate (880/890 vs 822/890)

## Path Rewriting Gotchas

Coverage files reference source paths as they were during compilation. These often don't match the actual repository structure:

1. **Container build paths**: `/workspace/pkg/file.go` or `/go/src/github.com/org/repo/pkg/file.go` - need rewriting to module path
2. **Module path migrations**: `github.com/coreos/prometheus-operator` → `github.com/prometheus-operator/prometheus-operator` - org renamed
3. **`/go/src/` prefix**: Container builds using GOPATH mode prepend `/go/src/` to module paths

The `rewriteCoveragePaths()` function handles these cases. The `filterMissingSourceFiles()` function removes coverage lines for files that don't exist in the repo (generated files like `bindata.go`).

## Repository Matching

`findMatchingRepository()` in `render.go` matches coverage file package paths to cloned repos:
- Exact module prefix match (score 100)
- Repository name match across org changes (score 50)
- Partial name containment (score 25)
- Special cases for known migrations like prometheus-operator (score 90)
- Fallback: `findRepoByOwnerName()` matches by owner name to repo directory name

## Performance Characteristics

### Collection
- Default concurrency: 20 workers
- Port forward timeout: 10 seconds
- Stabilization delay: 200ms between port scans
- Fail-fast: if first port (53700) fails, skip the pod entirely (pod unreachable)
- Port scanning: quiet mode (no logging) during sequential port scan
- Typical cluster: ~274 pods, ~86 coverage-enabled images, ~3000+ successful collections

### Rendering
- Scanning phase: converts binary coverage data to text format using `go tool covdata textfmt` (can be slow for many reports)
- HTML generation: uses 256KB buffered writer for large files (some reports are 10MB+)
- Typical run: ~890 owner+binary groups from ~2200 coverage reports
- Full render: takes significant time for a large cluster (scanning + merging + HTML generation)

## Kubeconfig

The tool uses standard kubeconfig for cluster access. The kubeconfig is specified via the `--kubeconfig` flag. Do NOT assume `~/.kube/config` is correct - OpenShift CI clusters use different kubeconfig paths. Always ask the user for the kubeconfig location.

## Source Repository Cloning

The `clone` command uses image labels to determine source repos:
- `io.openshift.build.source-location` → Git repository URL
- `io.openshift.build.commit.id` → Git commit hash
- Repos are cloned to `<cluster>/repos/github.com/<org>/<repo>/<commit>/`
- The cloned repo is used to read source files for HTML annotation

## Known Issues and Edge Cases

1. **Some binaries have no matching repo**: ~10/890 groups can't find a source repository. These produce warnings but don't block other reports.
2. **Generated files**: Files like `bindata.go`, `zz_generated_*` exist in coverage data but not in the source repo. These are filtered out by `filterMissingSourceFiles()`.
3. **Coverage server lines**: The injected `coverage_server.go` is filtered out by `createFilteredCoverage()` since it's infrastructure code, not application code.
4. **Binary name from os.Executable()**: This returns the actual binary name on disk, which may differ from the container name or the repository name.
5. **Multiple coverage servers per pod**: Sequential port scanning (53700-53799) handles pods with multiple instrumented binaries.
6. **Output buffering with pipes**: When redirecting render output through pipes like `tee file | tail`, output may buffer. Use the log file directly instead.

## Module Path

The `go.mod` module path is `github.com/jupierce/cluster-code-coverage-analysis`.

## Dependencies

Key dependencies:
- `golang.org/x/tools/cover` - Coverage profile parsing and boundary computation
- `github.com/spf13/cobra` - CLI framework
- `k8s.io/client-go` - Kubernetes API client (port forwarding, pod listing)
- `github.com/google/go-containerregistry` - Container image inspection
- `oras.land/oras-go/v2` - OCI registry operations
