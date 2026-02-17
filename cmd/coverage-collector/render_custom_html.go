package main

import (
	"bufio"
	"fmt"
	"html"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/cover"
)

// FileCoverageReport holds per-file coverage data for the custom HTML report
type FileCoverageReport struct {
	Path         string        // relative path (e.g., "pkg/operator/starter.go")
	FullPath     string        // full module path
	Coverage     float64       // percentage
	TotalStmts   int
	CoveredStmts int
	BodyHTML     template.HTML // source with coverage spans + line numbers
}

// buildFileCoverageReports parses a merged coverage file and builds per-file reports
// with annotated source code HTML
func buildFileCoverageReports(coverageFile, repoPath, moduleName string, workspaceModules map[string]string) ([]FileCoverageReport, error) {
	profiles, err := cover.ParseProfiles(coverageFile)
	if err != nil {
		return nil, fmt.Errorf("parse profiles: %w", err)
	}

	var reports []FileCoverageReport

	for _, profile := range profiles {
		// Resolve relative path within the repo
		relPath := profile.FileName
		if workspaceModules != nil {
			if resolved := resolveWorkspacePath(relPath, workspaceModules); resolved != "" {
				relPath = resolved
			}
		} else if moduleName != "" && strings.HasPrefix(relPath, moduleName) {
			relPath = strings.TrimPrefix(relPath, moduleName)
			relPath = strings.TrimPrefix(relPath, "/")
		}

		absPath := filepath.Join(repoPath, relPath)
		src, err := os.ReadFile(absPath)
		if err != nil {
			// Skip files that can't be found (generated files, vendored, etc.)
			continue
		}

		// Compute per-file stats
		totalStmts := 0
		coveredStmts := 0
		for _, block := range profile.Blocks {
			totalStmts += block.NumStmt
			if block.Count > 0 {
				coveredStmts += block.NumStmt
			}
		}

		var coverage float64
		if totalStmts > 0 {
			coverage = float64(coveredStmts) / float64(totalStmts) * 100
		}

		bodyHTML := annotateSource(src, profile)

		reports = append(reports, FileCoverageReport{
			Path:         relPath,
			FullPath:     profile.FileName,
			Coverage:     coverage,
			TotalStmts:   totalStmts,
			CoveredStmts: coveredStmts,
			BodyHTML:     bodyHTML,
		})
	}

	// Sort by path
	sort.Slice(reports, func(i, j int) bool {
		return reports[i].Path < reports[j].Path
	})

	return reports, nil
}

// annotateSource produces HTML with line numbers and coverage highlighting spans
func annotateSource(src []byte, profile *cover.Profile) template.HTML {
	boundaries := profile.Boundaries(src)

	var buf strings.Builder
	buf.WriteString(`<table class="source-code"><tbody>`)

	// We'll process the source byte by byte, inserting boundaries
	// Build a map of offset -> list of boundaries at that offset
	type boundaryEntry struct {
		b     cover.Boundary
		index int
	}
	boundaryMap := make(map[int][]boundaryEntry)
	for i, b := range boundaries {
		boundaryMap[b.Offset] = append(boundaryMap[b.Offset], boundaryEntry{b, i})
	}

	lineNum := 1
	buf.WriteString(fmt.Sprintf(`<tr><td class="line-num" id="L%d">%d</td><td class="line-content">`, lineNum, lineNum))

	inSpan := false

	for i := 0; i < len(src); i++ {
		// Check for boundaries at this offset
		if entries, ok := boundaryMap[i]; ok {
			for _, entry := range entries {
				b := entry.b
				if b.Start {
					if inSpan {
						buf.WriteString("</span>")
					}
					if b.Count > 0 {
						buf.WriteString(`<span class="cov-hit">`)
					} else {
						buf.WriteString(`<span class="cov-none">`)
					}
					inSpan = true
				} else {
					if inSpan {
						buf.WriteString("</span>")
						inSpan = false
					}
				}
			}
		}

		c := src[i]
		if c == '\n' {
			if inSpan {
				buf.WriteString("</span>")
			}
			buf.WriteString("</td></tr>\n")
			lineNum++
			buf.WriteString(fmt.Sprintf(`<tr><td class="line-num" id="L%d">%d</td><td class="line-content">`, lineNum, lineNum))
			if inSpan {
				// Re-open the span on the next line
				// We need to remember what kind of span we were in
				// Look backwards in the boundaries to find the last opened span
				buf.WriteString(lastOpenSpan(boundaries, i))
			}
		} else if c == '<' {
			buf.WriteString("&lt;")
		} else if c == '>' {
			buf.WriteString("&gt;")
		} else if c == '&' {
			buf.WriteString("&amp;")
		} else if c == '\t' {
			buf.WriteString("    ")
		} else {
			buf.WriteByte(c)
		}
	}

	if inSpan {
		buf.WriteString("</span>")
	}
	buf.WriteString("</td></tr>\n")
	buf.WriteString("</tbody></table>")

	return template.HTML(buf.String())
}

// lastOpenSpan finds the last opened span tag class at the given source offset
func lastOpenSpan(boundaries []cover.Boundary, offset int) string {
	// Walk boundaries up to this offset and track the open span state
	var lastClass string
	for _, b := range boundaries {
		if b.Offset > offset {
			break
		}
		if b.Start {
			if b.Count > 0 {
				lastClass = `<span class="cov-hit">`
			} else {
				lastClass = `<span class="cov-none">`
			}
		} else {
			lastClass = ""
		}
	}
	return lastClass
}

// renderCustomCoverageHTML generates a self-contained HTML file with the custom coverage report
func renderCustomCoverageHTML(outputPath string, owner *OwnerReport, fileReports []FileCoverageReport) error {
	funcMap := template.FuncMap{
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
		"escapeHTML": func(s string) string {
			return html.EscapeString(s)
		},
	}

	tmpl, err := template.New("coverage").Funcs(funcMap).Parse(customCoverageTemplate)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriterSize(f, 256*1024) // 256KB buffer for large files

	// Calculate aggregate stats
	totalFiles := len(fileReports)
	totalStmts := 0
	coveredStmts := 0
	excellent, good, moderate, poor, critical := 0, 0, 0, 0, 0

	for _, fr := range fileReports {
		totalStmts += fr.TotalStmts
		coveredStmts += fr.CoveredStmts
		switch {
		case fr.Coverage >= 70:
			excellent++
		case fr.Coverage >= 50:
			good++
		case fr.Coverage >= 30:
			moderate++
		case fr.Coverage >= 15:
			poor++
		default:
			critical++
		}
	}

	var overallCoverage float64
	if totalStmts > 0 {
		overallCoverage = float64(coveredStmts) / float64(totalStmts) * 100
	}

	binaryName := ""
	if len(owner.Containers) > 0 {
		binaryName = owner.Containers[0]
	}

	data := struct {
		Owner           *OwnerReport
		BinaryName      string
		Files           []FileCoverageReport
		TotalFiles      int
		OverallCoverage float64
		TotalStmts      int
		CoveredStmts    int
		Excellent       int
		Good            int
		Moderate        int
		Poor            int
		Critical        int
	}{
		Owner:           owner,
		BinaryName:      binaryName,
		Files:           fileReports,
		TotalFiles:      totalFiles,
		OverallCoverage: overallCoverage,
		TotalStmts:      totalStmts,
		CoveredStmts:    coveredStmts,
		Excellent:       excellent,
		Good:            good,
		Moderate:        moderate,
		Poor:            poor,
		Critical:        critical,
	}

	if err := tmpl.Execute(w, data); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}

	return w.Flush()
}

const customCoverageTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Coverage: {{.Owner.Namespace}} / {{.Owner.OwnerName}}{{if .BinaryName}} ({{.BinaryName}}){{end}}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #f5f5f5;
            line-height: 1.6;
        }

        .container {
            max-width: 1800px;
            margin: 0 auto;
            padding: 20px;
        }

        /* Header */
        .header {
            background: white;
            padding: 20px 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }

        .header h1 {
            color: #333;
            font-size: 22px;
            margin-bottom: 4px;
        }

        .header .subtitle {
            color: #666;
            font-size: 13px;
        }

        .back-link {
            display: inline-block;
            margin-bottom: 12px;
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
            font-size: 13px;
        }

        .back-link:hover {
            text-decoration: underline;
        }

        /* Stat cards */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 12px;
            margin-bottom: 20px;
        }

        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 16px;
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
            font-size: 10px;
            opacity: 0.9;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 6px;
        }

        .stat-value {
            font-size: 26px;
            font-weight: bold;
        }

        /* Coverage distribution badges */
        .coverage-distribution {
            display: flex;
            gap: 8px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }

        .coverage-badge {
            padding: 6px 12px;
            border-radius: 16px;
            font-size: 11px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .coverage-badge .count {
            background: rgba(255,255,255,0.3);
            padding: 1px 6px;
            border-radius: 8px;
        }

        .badge-excellent { background: #28a745; color: white; }
        .badge-good { background: #5cb85c; color: white; }
        .badge-moderate { background: #ffc107; color: #333; }
        .badge-poor { background: #fd7e14; color: white; }
        .badge-critical { background: #dc3545; color: white; }

        /* Controls */
        .controls {
            display: flex;
            gap: 12px;
            margin-bottom: 15px;
            flex-wrap: wrap;
            align-items: center;
        }

        .search-box {
            flex: 1;
            min-width: 250px;
        }

        input[type="text"] {
            width: 100%;
            padding: 9px 14px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 13px;
        }

        input[type="text"]:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        select {
            padding: 9px 14px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 13px;
            background: white;
            cursor: pointer;
        }

        /* File list panel */
        .file-list-panel {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            padding: 20px;
            margin-bottom: 20px;
        }

        .filter-info {
            padding: 10px 14px;
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            border-radius: 4px;
            font-size: 13px;
            margin-bottom: 12px;
            display: none;
        }

        .filter-info.active {
            display: block;
        }

        /* File table */
        table.file-table {
            width: 100%;
            border-collapse: collapse;
        }

        table.file-table th {
            background: #f8f9fa;
            padding: 12px 10px;
            text-align: left;
            font-weight: 600;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #666;
            border-bottom: 2px solid #dee2e6;
            position: sticky;
            top: 0;
            cursor: pointer;
            user-select: none;
            z-index: 10;
        }

        table.file-table th:hover {
            background: #e9ecef;
        }

        table.file-table th.sortable::after {
            content: " \21C5";
            opacity: 0.3;
        }

        table.file-table th.sorted-asc::after {
            content: " \25B2";
            opacity: 1;
        }

        table.file-table th.sorted-desc::after {
            content: " \25BC";
            opacity: 1;
        }

        table.file-table td {
            padding: 10px 10px;
            border-bottom: 1px solid #f0f0f0;
            font-size: 13px;
        }

        table.file-table tr:hover {
            background: #f8f9fa;
        }

        table.file-table tr.clickable {
            cursor: pointer;
        }

        table.file-table tr.clickable:hover {
            background: #e7f3ff;
        }

        .file-path {
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            font-size: 12px;
            word-break: break-all;
        }

        .coverage-bar {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .bar-container {
            flex: 1;
            background: #e9ecef;
            height: 20px;
            border-radius: 10px;
            overflow: hidden;
            min-width: 80px;
        }

        .bar-fill {
            height: 100%;
            transition: width 0.3s;
            display: flex;
            align-items: center;
            justify-content: flex-end;
            padding-right: 8px;
            font-size: 10px;
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
            min-width: 50px;
            text-align: right;
            font-size: 13px;
        }

        .coverage-text.excellent { color: #28a745; }
        .coverage-text.good { color: #5cb85c; }
        .coverage-text.moderate { color: #f39c12; }
        .coverage-text.poor { color: #fd7e14; }
        .coverage-text.critical { color: #dc3545; }

        .statements {
            color: #666;
            font-size: 12px;
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
        }

        /* Source viewer */
        .source-viewer {
            display: none;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }

        .source-header {
            position: sticky;
            top: 0;
            z-index: 20;
            background: white;
            padding: 14px 20px;
            border-bottom: 1px solid #dee2e6;
            display: flex;
            align-items: center;
            gap: 14px;
            flex-wrap: wrap;
            border-radius: 8px 8px 0 0;
        }

        .source-header .btn {
            padding: 6px 14px;
            border: 1px solid #ddd;
            border-radius: 4px;
            background: white;
            cursor: pointer;
            font-size: 12px;
            font-weight: 600;
            color: #333;
        }

        .source-header .btn:hover {
            background: #f0f0f0;
        }

        .source-header .btn-primary {
            background: #667eea;
            color: white;
            border-color: #667eea;
        }

        .source-header .btn-primary:hover {
            background: #5a6fd6;
        }

        .source-file-name {
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            font-size: 13px;
            font-weight: 600;
            color: #333;
            flex: 1;
            min-width: 200px;
        }

        .source-coverage {
            font-weight: 600;
            font-size: 14px;
        }

        .legend {
            display: flex;
            gap: 14px;
            font-size: 11px;
            color: #666;
        }

        .legend-item {
            display: flex;
            align-items: center;
            gap: 4px;
        }

        .legend-swatch {
            width: 14px;
            height: 14px;
            border-radius: 3px;
        }

        .legend-swatch.hit { background: rgba(40, 167, 69, 0.15); border: 1px solid rgba(40, 167, 69, 0.3); }
        .legend-swatch.miss { background: rgba(220, 53, 69, 0.15); border: 1px solid rgba(220, 53, 69, 0.3); }
        .legend-swatch.none { background: white; border: 1px solid #ddd; }

        .source-body {
            overflow-x: auto;
            max-height: calc(100vh - 200px);
            overflow-y: auto;
        }

        /* Source code table */
        table.source-code {
            width: 100%;
            border-collapse: collapse;
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            font-size: 12px;
            line-height: 1.5;
        }

        table.source-code td {
            padding: 0;
            vertical-align: top;
            border: none;
        }

        table.source-code td.line-num {
            width: 1px;
            min-width: 50px;
            padding: 0 10px 0 12px;
            text-align: right;
            color: #999;
            user-select: none;
            background: #fafafa;
            border-right: 1px solid #eee;
            white-space: nowrap;
        }

        table.source-code td.line-content {
            padding: 0 12px;
            white-space: pre;
        }

        table.source-code tr:hover td {
            background: rgba(102, 126, 234, 0.05);
        }

        table.source-code tr:hover td.line-num {
            color: #667eea;
        }

        /* Coverage highlighting */
        .cov-hit {
            background-color: rgba(40, 167, 69, 0.15);
        }

        .cov-none {
            background-color: rgba(220, 53, 69, 0.15);
        }

        /* Layout modes */
        .split-view {
            display: flex;
            gap: 20px;
        }

        .split-view .file-list-panel {
            width: 400px;
            min-width: 300px;
            max-height: calc(100vh - 40px);
            overflow-y: auto;
            position: sticky;
            top: 20px;
            flex-shrink: 0;
        }

        .split-view .source-viewer {
            flex: 1;
            min-width: 0;
        }

        .split-view table.file-table th:nth-child(3),
        .split-view table.file-table td:nth-child(3) {
            display: none;
        }

        @media (max-width: 1200px) {
            .split-view {
                flex-direction: column;
            }

            .split-view .file-list-panel {
                width: 100%;
                max-height: 400px;
                position: static;
            }
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

            .source-header {
                flex-direction: column;
                align-items: flex-start;
            }
        }
    </style>
</head>
<body>
    <div class="container" id="app">
        <div class="header">
            <a class="back-link" href="index.html">&larr; Back to Index</a>
            <h1>{{.Owner.Namespace}} / {{.Owner.OwnerType}} / {{.Owner.OwnerName}}</h1>
            <div class="subtitle">{{if .BinaryName}}Binary: {{.BinaryName}} &middot; {{end}}{{.Owner.PodCount}} pod{{if ne .Owner.PodCount 1}}s{{end}} &middot; {{.TotalFiles}} source files</div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Source Files</div>
                <div class="stat-value">{{formatInt .TotalFiles}}</div>
            </div>
            <div class="stat-card secondary">
                <div class="stat-label">Overall Coverage</div>
                <div class="stat-value">{{formatPct .OverallCoverage}}</div>
            </div>
            <div class="stat-card tertiary">
                <div class="stat-label">Total Statements</div>
                <div class="stat-value">{{formatInt .TotalStmts}}</div>
            </div>
            <div class="stat-card quaternary">
                <div class="stat-label">Covered Statements</div>
                <div class="stat-value">{{formatInt .CoveredStmts}}</div>
            </div>
        </div>

        <div class="coverage-distribution">
            {{if .Excellent}}<div class="coverage-badge badge-excellent"><span>Excellent (&ge;70%)</span><span class="count">{{.Excellent}}</span></div>{{end}}
            {{if .Good}}<div class="coverage-badge badge-good"><span>Good (50-69%)</span><span class="count">{{.Good}}</span></div>{{end}}
            {{if .Moderate}}<div class="coverage-badge badge-moderate"><span>Moderate (30-49%)</span><span class="count">{{.Moderate}}</span></div>{{end}}
            {{if .Poor}}<div class="coverage-badge badge-poor"><span>Poor (15-29%)</span><span class="count">{{.Poor}}</span></div>{{end}}
            {{if .Critical}}<div class="coverage-badge badge-critical"><span>Critical (&lt;15%)</span><span class="count">{{.Critical}}</span></div>{{end}}
        </div>

        <div id="mainLayout">
            <div class="file-list-panel" id="fileListPanel">
                <div class="controls">
                    <div class="search-box">
                        <input type="text" id="searchBox" placeholder="Search file paths...">
                    </div>
                    <select id="coverageFilter">
                        <option value="">All Levels</option>
                        <option value="excellent">Excellent (&ge;70%)</option>
                        <option value="good">Good (50-69%)</option>
                        <option value="moderate">Moderate (30-49%)</option>
                        <option value="poor">Poor (15-29%)</option>
                        <option value="critical">Critical (&lt;15%)</option>
                    </select>
                </div>

                <div id="filterInfo" class="filter-info"></div>

                <table class="file-table" id="fileTable">
                    <thead>
                        <tr>
                            <th class="sortable" data-sort="path">File Path</th>
                            <th class="sortable" data-sort="coverage">Coverage</th>
                            <th class="sortable" data-sort="statements">Statements</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range $i, $f := .Files}}
                        <tr class="clickable" data-file-index="{{$i}}"
                            data-path="{{$f.Path}}"
                            data-coverage="{{$f.Coverage}}"
                            data-statements="{{$f.TotalStmts}}"
                            data-coverage-class="{{colorClass $f.Coverage}}">
                            <td><span class="file-path">{{$f.Path}}</span></td>
                            <td>
                                <div class="coverage-bar">
                                    <div class="bar-container">
                                        <div class="bar-fill {{colorClass $f.Coverage}}" style="width: {{$f.Coverage}}%">
                                            {{if showPctInBar $f.Coverage}}{{formatPct $f.Coverage}}{{end}}
                                        </div>
                                    </div>
                                    <span class="coverage-text {{colorClass $f.Coverage}}">{{formatPct $f.Coverage}}</span>
                                </div>
                            </td>
                            <td class="statements">{{$f.CoveredStmts}}/{{$f.TotalStmts}}</td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
            </div>

            <div class="source-viewer" id="sourceViewer">
                <div class="source-header">
                    <button class="btn btn-primary" id="backToListBtn">Back to File List</button>
                    <button class="btn" id="toggleFileListBtn">Show File List</button>
                    <span class="source-file-name" id="sourceFileName"></span>
                    <span class="source-coverage" id="sourceCoverage"></span>
                    <div class="legend">
                        <span class="legend-item"><span class="legend-swatch hit"></span> Covered</span>
                        <span class="legend-item"><span class="legend-swatch miss"></span> Not Covered</span>
                        <span class="legend-item"><span class="legend-swatch none"></span> Not Tracked</span>
                    </div>
                </div>
                <div class="source-body" id="sourceBody"></div>
            </div>
        </div>
    </div>

    {{range $i, $f := .Files}}
    <template id="file-source-{{$i}}">{{$f.BodyHTML}}</template>
    {{end}}

    <script>
        const fileTable = document.getElementById('fileTable');
        const fileListPanel = document.getElementById('fileListPanel');
        const sourceViewer = document.getElementById('sourceViewer');
        const sourceBody = document.getElementById('sourceBody');
        const sourceFileName = document.getElementById('sourceFileName');
        const sourceCoverage = document.getElementById('sourceCoverage');
        const backToListBtn = document.getElementById('backToListBtn');
        const toggleFileListBtn = document.getElementById('toggleFileListBtn');
        const mainLayout = document.getElementById('mainLayout');
        const searchBox = document.getElementById('searchBox');
        const coverageFilter = document.getElementById('coverageFilter');
        const filterInfo = document.getElementById('filterInfo');
        const rows = fileTable.querySelectorAll('tbody tr');

        let currentView = 'list'; // 'list', 'source', 'split'
        let currentFileIndex = -1;

        // File click handler
        fileTable.addEventListener('click', function(e) {
            const row = e.target.closest('tr[data-file-index]');
            if (!row) return;
            const idx = parseInt(row.dataset.fileIndex);
            showSource(idx);
        });

        function showSource(idx) {
            currentFileIndex = idx;
            const row = fileTable.querySelector('tr[data-file-index="' + idx + '"]');
            if (!row) return;

            const path = row.dataset.path;
            const coverage = parseFloat(row.dataset.coverage);
            const covClass = row.dataset.coverageClass;

            sourceFileName.textContent = path;
            sourceCoverage.textContent = coverage.toFixed(1) + '%';
            sourceCoverage.className = 'source-coverage ' + covClass;

            // Load source from template
            const tmpl = document.getElementById('file-source-' + idx);
            if (tmpl) {
                sourceBody.innerHTML = tmpl.innerHTML;
            }

            // Highlight selected row
            rows.forEach(r => r.style.background = '');
            row.style.background = '#e7f3ff';

            if (currentView === 'list') {
                // Switch to source-only view
                fileListPanel.style.display = 'none';
                sourceViewer.style.display = 'block';
                mainLayout.classList.remove('split-view');
                currentView = 'source';
                toggleFileListBtn.textContent = 'Show File List';
            } else if (currentView === 'split') {
                sourceViewer.style.display = 'block';
            }

            // Update URL hash
            history.replaceState(null, '', '#file' + idx);
        }

        backToListBtn.addEventListener('click', function() {
            sourceViewer.style.display = 'none';
            fileListPanel.style.display = 'block';
            mainLayout.classList.remove('split-view');
            currentView = 'list';
            rows.forEach(r => r.style.background = '');
            history.replaceState(null, '', window.location.pathname);
        });

        toggleFileListBtn.addEventListener('click', function() {
            if (currentView === 'source') {
                // Enter split view
                fileListPanel.style.display = 'block';
                mainLayout.classList.add('split-view');
                currentView = 'split';
                toggleFileListBtn.textContent = 'Hide File List';
            } else if (currentView === 'split') {
                // Back to source-only
                fileListPanel.style.display = 'none';
                mainLayout.classList.remove('split-view');
                currentView = 'source';
                toggleFileListBtn.textContent = 'Show File List';
            }
        });

        // Filter functionality
        function applyFilters() {
            const searchTerm = searchBox.value.toLowerCase();
            const selectedCoverage = coverageFilter.value;
            let visibleCount = 0;

            rows.forEach(row => {
                const path = row.dataset.path.toLowerCase();
                const coverageClass = row.dataset.coverageClass;

                const matchesSearch = !searchTerm || path.includes(searchTerm);
                const matchesCoverage = !selectedCoverage || coverageClass === selectedCoverage;

                if (matchesSearch && matchesCoverage) {
                    row.style.display = '';
                    visibleCount++;
                } else {
                    row.style.display = 'none';
                }
            });

            if (searchTerm || selectedCoverage) {
                filterInfo.classList.add('active');
                filterInfo.textContent = 'Showing ' + visibleCount + ' of ' + rows.length + ' files';
            } else {
                filterInfo.classList.remove('active');
            }
        }

        searchBox.addEventListener('input', applyFilters);
        coverageFilter.addEventListener('change', applyFilters);

        // Sorting functionality
        let currentSort = { column: null, direction: 'asc' };

        fileTable.querySelectorAll('th.sortable').forEach(th => {
            th.addEventListener('click', () => {
                const sortBy = th.dataset.sort;

                if (currentSort.column === sortBy) {
                    currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
                } else {
                    currentSort.column = sortBy;
                    currentSort.direction = 'asc';
                }

                fileTable.querySelectorAll('th.sortable').forEach(header => {
                    header.classList.remove('sorted-asc', 'sorted-desc');
                });
                th.classList.add('sorted-' + currentSort.direction);

                const tbody = fileTable.querySelector('tbody');
                const rowsArray = Array.from(rows);

                rowsArray.sort((a, b) => {
                    let aVal, bVal;

                    if (sortBy === 'coverage') {
                        aVal = parseFloat(a.dataset.coverage);
                        bVal = parseFloat(b.dataset.coverage);
                    } else if (sortBy === 'statements') {
                        aVal = parseInt(a.dataset.statements);
                        bVal = parseInt(b.dataset.statements);
                    } else {
                        aVal = a.dataset.path.toLowerCase();
                        bVal = b.dataset.path.toLowerCase();
                    }

                    if (aVal < bVal) return currentSort.direction === 'asc' ? -1 : 1;
                    if (aVal > bVal) return currentSort.direction === 'asc' ? 1 : -1;
                    return 0;
                });

                rowsArray.forEach(row => tbody.appendChild(row));
            });
        });

        // Handle URL hash on load
        if (window.location.hash) {
            const match = window.location.hash.match(/^#file(\d+)$/);
            if (match) {
                const idx = parseInt(match[1]);
                if (idx >= 0 && idx < rows.length) {
                    showSource(idx);
                }
            }
        }
    </script>
</body>
</html>
`
