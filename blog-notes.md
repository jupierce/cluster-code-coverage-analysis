# Blog Post Notes: Cluster-Wide Go Code Coverage for OpenShift

Raw technical notes and lessons learned from building an end-to-end system for
measuring Go code coverage across a live OpenShift cluster. This document
captures everything needed to write a blog post later.

---

## The Problem

OpenShift is composed of hundreds of Go binaries running across multiple nodes.
There was no way to answer "how much of this code actually runs in production?"
or "what new code paths did our e2e tests exercise?" Traditional Go coverage
requires running `go test` -- it doesn't work for long-running daemons deployed
in a Kubernetes cluster.

Go 1.20 introduced support for building binaries with `-cover`, which
instruments the binary to record coverage counters at runtime. But there's
a gap: the standard approach writes coverage data to a `GOCOVERDIR` directory
on exit, which doesn't help for daemons that run indefinitely inside
containers.

---

## The Instrumentation Side (doozer / ART build system)

Coverage instrumentation is injected at build time by the OpenShift ART
(Automated Release Tooling) build system via `doozer`. When
`build_profiles.enable_go_cover: true` is set in the group config, two
things happen:

### 1. Compiler flag injection

Go compliance shims (`golang_builder_FIPS_wrapper.sh` for container images,
`rpm_builder_go_wrapper.sh` for RPMs) intercept every `go build` and
`go install` invocation and inject `-cover -covermode=atomic`. The shim
replaces the `go` binary on `$PATH`, renaming the real one to `go.real`, and
rebuilds argument lists on the fly.

### 2. Coverage server injection

A file called `coverage_server.go` is copied into every `package main`
directory in the source tree. This file contains an `init()` function that
starts a lightweight HTTP server, serving live coverage data collected by
Go's `runtime/coverage` package.

### coverage_server.go technical details

**Port selection**: Default starting port is 53700 (overridable via
`COVERAGE_PORT` env var). Multiple coverage-instrumented binaries in the same
network namespace (e.g. multiple containers in a hostNetwork pod) try up to
50 consecutive ports (53700-53749) to find an available one. If all are
exhausted, the server silently doesn't start and the binary runs normally.

**Identity headers**: Every response includes:
- `X-Art-Coverage-Server: 1` -- confirms this is a coverage server
- `X-Art-Coverage-Pid: <pid>` -- PID of the instrumented process
- `X-Art-Coverage-Binary: <name>` -- base name of the running binary

**Endpoints**:
- `GET /coverage` -- returns JSON with base64-encoded `covmeta.*` and
  `covcounters.*` binary data
- `GET /health` -- returns `200 OK`
- `HEAD /` -- returns identity headers only (used for port scanning)

**Import aliasing**: Because the file is injected into arbitrary `package main`
directories, every import and top-level identifier uses a `_cov` prefix to
avoid name collisions with the host package. This was discovered the hard way
when `cluster-ingress-operator` declared `var log = logf.Logger.WithName("main")`
at package level, conflicting with `import "log"`.

### Source injection safety rules

The `find_go_main_packages()` function in doozer applies several safety rules:

1. **Build-constraint awareness**: Files with `//go:build ignore` or
   `// +build ignore` are skipped when determining a directory's package name.
   Without this, code generators that declare `package main` but are never
   compiled would cause false positives.

2. **Package consistency check**: A directory is only treated as `package main`
   if ALL compilable `.go` files agree. Mixed-package directories are excluded.
   Example: prometheus has a `plugins/` directory where `generate.go` says
   `package main` (with a build tag) but `minimum.go` says `package plugins`.

3. **Sub-module exclusion**: Directories with their own `go.mod` (that aren't
   the project root) are skipped. Injecting into sub-modules would cause
   `go mod vendor` to copy `coverage_server.go` into the `vendor/` tree,
   breaking strict vendoring checks. Example: `operator-framework-olm` has
   separate Go modules under `staging/`.

4. **Standard exclusions**: `.git`, `vendor`, `node_modules` are always skipped.

### Failure modes encountered during instrumentation

| Problem | Symptom | Root cause | Fix |
|---------|---------|------------|-----|
| Mixed-package injection | `found packages main and plugins` | Build-tagged `package main` in non-main directory | Package consistency check |
| Import collision | `log already declared` | Host package shadows `import "log"` | `_cov` prefix on all identifiers |
| Vendor pollution | `vendor directory changed after vendoring` | Injected into sub-module consumed via `replace` | Sub-module exclusion |
| RPM missing coverage | Kubelet binary not instrumented | `go install` not handled (only `go build`) | Added `install` to shim condition |

---

## The Scanner / Collector Tool

### Architecture overview

A Go CLI (`coverage-collector`) built with Cobra, with a `cluster` command
group containing four subcommands run in sequence:

```
coverage-collector cluster download   --cluster <name> --bucket <s3> --prefix <path>
coverage-collector cluster compile    --cluster <name>
coverage-collector cluster clone-sources --cluster <name>
coverage-collector cluster render     --cluster <name>
```

Coverage data is collected separately (by an external collector running in the
cluster or uploaded to S3) and this tool focuses on downloading, compiling,
and rendering it. The tool was derived in part from
[psturc/go-coverage-http](https://github.com/psturc/go-coverage-http).

### Step 1: Download

The `download` command retrieves coverage data from an S3 bucket. The coverage
producer (running in the kubelet) uploads binary coverage data (covmeta/
covcounters files) to S3 in a structured path layout:

```
{prefix}/{hostname}/{namespace}/{podName}/{containerName}/{discoveryTime}/{sanitizedImage}/{sanitizedBinary}/
```

**Metadata extraction**: Each S3 path is parsed to extract namespace, pod name,
container name, hostname, image reference, binary name, and collection
timestamp. These are stored in a `metadata.json` alongside the downloaded
coverage data.

**Concurrency**: Up to 10 concurrent downloads (configurable via
`--max-concurrency`).

**Output**: Binary coverage files saved under
`<cluster>/coverage/<dirName>/` along with `metadata.json` for each entry.

### Step 2: Compile

The `compile` command processes raw coverage data into a SQLite database
(`coverage.db`), performing all expensive computation upfront. This is the
core data pipeline.

**Phase 1 -- Report ingestion**: For each coverage directory:
1. Runs `go tool covdata textfmt` to convert binary data to text format.
2. Filters out lines from `coverage_server.go` (the injected HTTP server).
3. Parses per-file coverage statistics (total stmts, covered stmts, pct).
4. Stores the coverage text and metadata in the `report_sources` table.
5. Tracks an MD5 `input_hash` of the binary coverage files for incremental
   change detection -- unchanged reports are skipped on re-run.

**Phase 1.5 -- Image inspection**: For each unique container image referenced
in the reports:
1. Runs `oc image info <ref> -o json` to inspect image labels.
2. Extracts `io.openshift.build.source-location` (source repo URL) and
   `io.openshift.build.commit.id` (git commit hash).
3. Stores the mapping in the `image_sources` table.
4. Results are cached -- only new or previously-failed images are re-inspected.
5. Non-fatal: if `oc` is not available, the phase is skipped entirely.

**Phase 2 -- Owner computation**: Groups reports by pod owner and merges
coverage:
1. Infers owner type from pod naming conventions via regex (Deployment,
   DaemonSet, StatefulSet, Job, Host).
2. Groups by `{namespace}|{ownerType}|{ownerName}|{binaryName}`.
3. Merges coverage across pod replicas using max-count semantics.
4. Computes per-file coverage statistics for the merged result.
5. Stores everything in the `owners`, `owner_reports`, and
   `owner_file_stats` tables.

**Incremental updates**: The `--update` flag supports glob patterns for
selective recomputation:
```
--update '*'                          # Force full recomputation
--update 'namespace=openshift-*'      # Recompute matching namespaces
--update 'container=kube-apiserver'   # Recompute matching containers
```
Multiple `--update` flags combine with AND logic.

**Database schema** (v2):
- `report_sources` -- one row per coverage directory (2214 in our test cluster)
- `owners` -- one row per owner/binary group (891 in our test cluster)
- `owner_reports` -- many-to-many join between owners and reports
- `owner_file_stats` -- per-file coverage stats for each owner
- `image_sources` -- image-to-source-repo mapping (52 images inspected)
- `schema_version` -- tracks schema version for migrations

### Step 3: Clone Sources

The `clone-sources` command reads the `image_sources` table from the database
and `git clone`s each identified source repository at the build commit.

**Directory layout**: Sources are stored under
`<cluster>/repos/<host>/<org>/<repo>/<commit-prefix>/` where `<commit-prefix>`
is the first 8 characters of the commit hash.

**Checkout fallback**: If `git fetch origin <commit>` fails after a
`--depth 1` clone, the tool falls back to using the default branch HEAD.
This handles cases where the server doesn't support fetching arbitrary commits.

**Concurrency**: Up to 5 concurrent clones (configurable via
`--max-concurrency`).

**Skip existing**: `--skip-existing` (default true) skips repos that already
have a `go.mod` in the target directory.

### Step 4: Render

The `render` command reads from the SQLite database and generates HTML reports.
All expensive computation (textfmt conversion, merging, statistics) was already
done during compile -- render focuses purely on HTML generation.

**Source repository resolution** uses a 3-strategy lookup:
1. **Image source labels** (fast, O(1)): Uses the `image_sources` table to
   map the owner's container image directly to a cloned repo directory.
2. **Package path matching** (slower, walks repos/): Extracts the Go package
   path from coverage data and searches for a matching `go.mod` in the repos
   tree.
3. **Owner name matching** (slowest, walks repos/): Tries to find a repo
   whose directory name matches the owner name.

**Path rewriting**: Coverage data records file paths as they appeared during
the container build. These are rewritten to match the local cloned repo paths.
Handles `/workspace/...`, `/go/src/<module>/...`, and module name changes.

**HTML caching**: Uses `merge_input_hash` from the database to detect whether
the underlying coverage data has changed. If not, the existing HTML file is
reused (checked via an embedded `<!-- coverage-hash: ... -->` comment).

**Output**: Per-owner HTML reports with line-by-line annotated source code
(green = covered, red = not covered), plus an interactive `index.html`
dashboard.

**Source annotation algorithm**: Uses `golang.org/x/tools/cover` to get
coverage boundaries (byte offsets marking where covered/uncovered spans begin
and end). Iterates source byte-by-byte, opening `<span class="cov-hit">` or
`<span class="cov-none">` at boundaries. HTML spans can't cross `<tr>`
boundaries, so at each newline, the current span is closed and re-opened in
the next row.

**The interactive index.html** is a complete single-page application with:
- Real-time search/filter by namespace, owner name, container
- Dropdown filters for namespace, owner type, coverage tier
- Sortable columns (string and numeric sorting)
- Color-coded coverage bars (red < 25%, orange < 50%, yellow < 75%, green >= 75%)
- Click-through to individual source reports

**Per-owner HTML reports** feature:
- Stats dashboard (files, coverage %, statements)
- Filterable/sortable file list
- Source viewer with line-by-line coverage highlighting
- Three view modes: list, source, split
- URL hash navigation for deep-linking to specific files

---

## Key Technical Insights

### Coverage data is cumulative

Go's in-process coverage counters record every code path executed since the
process started. Each `collect` run downloads a snapshot of the counters at
that moment. The `covcounters.*` files have unique names (incorporating PID
and a nonce), so running `collect` multiple times creates additional files
alongside existing ones rather than replacing them.

When `render` runs, `go tool covdata textfmt` merges all counter files in
each directory, producing a combined view. This means coverage percentages
can only stay the same or increase across successive collections.

### Lifecycle coverage comparisons

This cumulative property enables before/after comparisons:
1. Fresh install -> `collect` -> `render --output-dir html-baseline`
2. Run e2e test suite
3. `collect` again -> `render --output-dir html-post-e2e`

The post-e2e report reflects all code executed since each pod started,
including both the baseline behavior and paths exercised by tests. We
verified this empirically: across 890 pod owner/container combinations,
zero decreased after e2e tests, while 494 (55.5%) increased.

Largest gains after e2e:
- openshift-image-registry / dockerregistry: 14.96% -> 48.16% (+33.20 pp)
- openshift-apiserver / openshift-apiserver: 25.51% -> 56.52% (+31.01 pp)
- cluster-policy-controller: 41.03% -> 70.27% (+29.24 pp)

### Vendor code is excluded at the build level

Go's `-cover` flag only instruments the main module's packages, not vendored
dependencies. We confirmed this empirically: zero `coverage.out` or
`coverage_filtered.out` files contain `/vendor/` paths. This is inherent to
Go's coverage instrumentation, not something the tool explicitly filters.

### hostNetwork pods and port conflicts

Coverage servers in pods bind to ports starting at 53700. Each pod normally
gets its own network namespace, so multiple pods can all bind 53700
independently. However, hostNetwork pods share the host's network namespace,
so their coverage servers must use different ports (53700, 53701, etc.
incrementally).

When kubelet was updated to also embed a coverage server, it grabbed port
53700 on the host network namespace (since it starts before any pods). This
pushed all hostNetwork pod coverage servers to 53701+. Non-hostNetwork pods
are unaffected since they have their own network namespace.

The collector handles this gracefully -- when it port-forwards to a
hostNetwork pod and probes 53700, it hits kubelet, gets a 500 error
("not built with -cover"), skips it, and continues to 53701+ where the
actual pod coverage servers are.

### Port-forward works for hostNetwork pods

We initially hypothesized that hostNetwork pods might not be reachable via
Kubernetes port-forward, which would require SSH-based collection via a
bastion host. Testing showed that port-forward works fine for hostNetwork
pods -- it just reaches the host's network namespace (which is the pod's
namespace in this case). All 3046 successful collections used port-forward;
the 89 failures were all due to stale/completed pods or pods without coverage
servers, not port-forward limitations.

### The stale data bug

The original render pipeline cached intermediate text files
(`coverage_filtered.out`, `coverage.out`). On a second render after
collecting new data, it would find the cached text files and skip
regeneration from the binary data, missing the newly collected
`covcounters.*` files entirely.

Fix: always regenerate from binary data when `covmeta.*` files exist.
Only fall back to cached text files when no binary data is present
(pre-existing text-format coverage).

### Source path rewriting challenges

Coverage data records file paths as they appeared during the build
(inside the container). These don't match the local filesystem where
sources are cloned. The render pipeline handles three path formats:

1. **`/workspace/...`** -- Typical container build path. Rewritten to
   the Go module name.
2. **`/go/src/<module>/...`** -- Standard GOPATH-style paths. The
   `/go/src/` prefix is stripped.
3. **Module name changes** -- Some projects have been transferred between
   GitHub organizations (e.g., `coreos/prometheus-operator` ->
   `prometheus-operator/prometheus-operator`). The tool detects this
   by comparing the module path in coverage data against `go.mod` in
   cloned repos and rewrites accordingly.

### Pod owner inference

The tool groups coverage by pod owner (Deployment, DaemonSet, StatefulSet,
etc.) but the Kubernetes API doesn't directly expose this in the pod's
coverage data path. Instead, owner type is inferred from pod naming patterns:

- **Deployment**: Two hash suffixes -- `<name>-<replicaset-hash>-<pod-hash>`
  (e.g., `api-server-abc1234567-xyz12`)
- **DaemonSet**: Single 5-char hash suffix -- `<name>-<hash>`
- **StatefulSet**: Numeric ordinal -- `<name>-<N>`
- **Job**: Special-cased for `installer-*` and `pruner-*` patterns

This heuristic works well in practice for OpenShift components but is
inherently fragile for unusual naming patterns.

### Coverage merge semantics

When merging coverage from multiple pods of the same owner (e.g., 3 replicas
of a Deployment), the tool uses **max-count** semantics: for each coverage
block (a contiguous region of source code), the highest execution count from
any replica is preserved. This produces a "union" view -- if a code path was
exercised in any replica, it shows as covered in the merged report.

---

## Scale

On a 6-node OpenShift GCP cluster (3 masters, 3 workers):

- **274 pods** scanned
- **86 unique container images** inspected
- **77 source repositories** cloned
- **3046 successful** coverage collections (multiple containers per pod)
- **89 failures** (stale pods, pods without coverage, unreachable pods)
- **890 unique owner/container combinations** rendered
- **880 HTML reports** generated (10 skipped due to missing source repos)
- **~54 GB** total data (cloned repos + coverage data + HTML reports)
- **11 GB** backup tarball of coverage data alone

---

## Error handling philosophy

The tool follows a **resilient, non-fatal** approach throughout:

- Namespace listing failures: warned and skipped
- Image inspection failures: logged, error stored in plan, not fatal
- Repository parsing failures: debug-logged and skipped
- Clone failures: recorded in summary, don't block other clones
- Collection failures: recorded per-pod, don't block other collections
- HTML generation failures: warned, owner skipped, index still generated
- Missing source files in coverage: lines filtered out, report generated
  from remaining files

Only infrastructure failures (can't create directories, can't save JSON)
are fatal. This is important at scale -- you don't want 1 flaky image
registry response to abort a 274-pod discovery.

---

## Bastion / SSH exploration

We explored whether SSH access to nodes (via an `ssh-bastion` deployment)
could provide additional coverage data beyond what Kubernetes port-forward
collects. Findings:

- All coverage servers on ports 537xx were containerized (CRI-O) processes,
  not host-level daemons.
- Port-forward worked for all pod types including hostNetwork pods.
- After kubelet was updated with a coverage server, it appeared on 53700 on
  all 6 nodes, but returned 500 ("binary not built with -cover") because
  the kubelet RPM wasn't compiled with `-cover` at that point.
- SSH-based collection would be needed for host-level binaries (kubelet,
  crio) once they are rebuilt with `-cover`, since these run as systemd
  services and are not reachable via Kubernetes port-forward.

---

## Technology stack

- **Go** (Cobra CLI framework)
- **modernc.org/sqlite** (pure Go SQLite driver, no CGo)
- **golang.org/x/tools/cover** (parsing coverage profiles)
- **go tool covdata textfmt** (binary-to-text coverage conversion)
- **oc image info** (container image label inspection for source repo mapping)
- **AWS CLI** (S3 download via `aws s3 ls` / `aws s3 cp`)
- Vanilla HTML/CSS/JavaScript for reports (no framework dependencies,
  works offline)

---

## Acknowledgments

The coverage HTTP client was derived from
[psturc/go-coverage-http](https://github.com/psturc/go-coverage-http).
