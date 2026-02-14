package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

const (
	nodeDiscoveryNamespace = "coverage-node-discovery"
	nodeDiscoveryDaemonSet = "coverage-node-proxy"
	nodeDiscoveryLabel     = "app=coverage-node-proxy"
	coverageStartPort      = 53700
	coverageMaxPorts       = 50
	maxConsecutiveMisses   = 5
)

var (
	kubeletCommit string

	scanNodesCmd = &cobra.Command{
		Use:   "scan-nodes",
		Short: "Scan cluster nodes for host-level coverage servers",
		Long: `Scan cluster nodes for host-level coverage servers (e.g., kubelet) that are
running directly on the host rather than in pods.

This command uses a hostNetwork DaemonSet deployed in the
coverage-node-discovery namespace to port-forward into each node's network
namespace and probe for coverage servers on ports 53700-53749.

Coverage servers belonging to pods are automatically filtered out so that
only true host-level processes (e.g., kubelet) are collected.

Use --kubelet-commit to clone the kubelet source from
https://github.com/openshift/kubernetes at the specified commit, enabling
the render pipeline to generate source-annotated HTML reports.

Prerequisites:
  - The node-discovery DaemonSet must be deployed:
      oc apply -f node-discovery/daemonset.yaml`,
		Example: `  # Scan nodes for host-level coverage
  coverage-collector cluster scan-nodes --cluster prod --kubelet-commit 0df3535

  # Scan with higher concurrency
  coverage-collector cluster scan-nodes --cluster prod --kubelet-commit 0df3535 --max-concurrency 3`,
		RunE: runScanNodes,
	}
)

func init() {
	scanNodesCmd.Flags().IntVar(&maxConcurrency, "max-concurrency", 5, "Maximum concurrent node scans")
	scanNodesCmd.Flags().StringVar(&kubeletCommit, "kubelet-commit", "", "Commit hash for openshift/kubernetes source (required)")
	scanNodesCmd.MarkFlagRequired("kubelet-commit")
	clusterCmd.AddCommand(scanNodesCmd)
}

// hostCoverageServer represents a coverage server found on a node's host network.
type hostCoverageServer struct {
	Port       int
	PID        string
	BinaryName string
}

// nodePortForward sets up a SPDY port-forward to a pod in the node-discovery namespace.
// Returns the assigned local port, a stop channel, and any error.
func nodePortForward(restConfig *rest.Config, podName string, targetPort int) (int, chan struct{}, error) {
	path := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/portforward", nodeDiscoveryNamespace, podName)
	hostIP := strings.TrimPrefix(restConfig.Host, "https://")
	serverURL, err := url.Parse(fmt.Sprintf("https://%s%s", hostIP, path))
	if err != nil {
		return 0, nil, fmt.Errorf("parse server URL: %w", err)
	}

	transport, upgrader, err := spdy.RoundTripperFor(restConfig)
	if err != nil {
		return 0, nil, fmt.Errorf("create round tripper: %w", err)
	}

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, "POST", serverURL)

	stopChan := make(chan struct{}, 1)
	readyChan := make(chan struct{})
	ports := []string{fmt.Sprintf("0:%d", targetPort)}

	forwarder, err := portforward.New(dialer, ports, stopChan, readyChan, io.Discard, io.Discard)
	if err != nil {
		return 0, nil, fmt.Errorf("create port forwarder: %w", err)
	}

	errChan := make(chan error, 1)
	go func() {
		if err := forwarder.ForwardPorts(); err != nil {
			errChan <- err
		}
	}()

	select {
	case <-readyChan:
		forwardedPorts, err := forwarder.GetPorts()
		if err != nil || len(forwardedPorts) == 0 {
			close(stopChan)
			return 0, nil, fmt.Errorf("get forwarded ports: %w", err)
		}
		return int(forwardedPorts[0].Local), stopChan, nil
	case err := <-errChan:
		close(stopChan)
		return 0, nil, fmt.Errorf("port forward failed: %w", err)
	case <-time.After(10 * time.Second):
		close(stopChan)
		return 0, nil, fmt.Errorf("timeout waiting for port forward")
	}
}

// probeCoveragePort sends a HEAD request and checks for coverage identity headers.
func probeCoveragePort(localPort int) (binaryName, pid string, ok bool) {
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest("HEAD", fmt.Sprintf("http://localhost:%d/coverage", localPort), nil)
	if err != nil {
		return "", "", false
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", "", false
	}
	defer resp.Body.Close()

	if resp.Header.Get("X-Art-Coverage-Server") != "1" {
		return "", "", false
	}

	return resp.Header.Get("X-Art-Coverage-Binary"), resp.Header.Get("X-Art-Coverage-Pid"), true
}

// normalizeBinaryName converts underscores to dashes for consistent matching.
func normalizeBinaryName(name string) string {
	return strings.ReplaceAll(name, "_", "-")
}

// buildPodBinarySet queries all pods in the cluster and returns a set of
// normalized binary names that belong to pod processes. Uses a global scope
// (not per-node) so that DaemonSet pods whose container name differs from
// their binary name can still be matched against deployment pods elsewhere
// that share the same binary name.
func buildPodBinarySet(ctx context.Context, clientset kubernetes.Interface) map[string]bool {
	podBinaries := map[string]bool{}

	podList, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return podBinaries
	}

	for _, pod := range podList.Items {
		if pod.Namespace == nodeDiscoveryNamespace {
			continue
		}
		for _, container := range pod.Spec.Containers {
			podBinaries[normalizeBinaryName(container.Name)] = true

			// Extract binary name from image path:
			// e.g. "registry.redhat.io/openshift4/ose-kube-rbac-proxy:v4.17" → "kube-rbac-proxy"
			imageParts := strings.Split(container.Image, "/")
			imageBase := imageParts[len(imageParts)-1]
			if colonIdx := strings.Index(imageBase, ":"); colonIdx >= 0 {
				imageBase = imageBase[:colonIdx]
			}
			imageBase = strings.TrimPrefix(imageBase, "ose-")
			podBinaries[normalizeBinaryName(imageBase)] = true
		}
		for _, container := range pod.Spec.InitContainers {
			podBinaries[normalizeBinaryName(container.Name)] = true
		}
	}

	return podBinaries
}

// isPodBinary checks whether a binary name matches a known pod process.
// Uses exact normalized match plus token-based overlap to catch cases like
// "multus-daemon" matching "kube-multus" (shared "multus" token).
func isPodBinary(binaryName string, podBinaries map[string]bool) bool {
	normalized := normalizeBinaryName(binaryName)
	if podBinaries[normalized] {
		return true
	}

	// Token overlap: split on dashes and check if any significant token
	// (4+ chars) appears in both the binary name and a pod container name.
	binaryTokens := make(map[string]bool)
	for _, t := range strings.Split(normalized, "-") {
		if len(t) >= 4 {
			binaryTokens[t] = true
		}
	}

	for name := range podBinaries {
		for _, t := range strings.Split(name, "-") {
			if len(t) >= 4 && binaryTokens[t] {
				return true
			}
		}
	}

	return false
}

// scanNodeViaProxy scans a node's host network for coverage servers by
// port-forwarding through the DaemonSet proxy pod. Servers whose binary name
// matches a known pod process on the node are filtered out.
func scanNodeViaProxy(restConfig *rest.Config, proxyPod string, podBinaries map[string]bool) ([]hostCoverageServer, int, error) {
	var servers []hostCoverageServer
	consecutiveMisses := 0
	skipped := 0

	for i := 0; i < coverageMaxPorts && consecutiveMisses < maxConsecutiveMisses; i++ {
		targetPort := coverageStartPort + i

		localPort, stopChan, err := nodePortForward(restConfig, proxyPod, targetPort)
		if err != nil {
			consecutiveMisses++
			continue
		}

		binaryName, pid, ok := probeCoveragePort(localPort)
		close(stopChan)

		if !ok {
			consecutiveMisses++
			continue
		}

		consecutiveMisses = 0

		// Filter: skip servers whose binary name matches a known pod process.
		// PID 1 is always a container init process. For hostPID pods, the
		// process has a real PID but its binary name still matches a pod container.
		if pid == "1" || isPodBinary(binaryName, podBinaries) {
			skipped++
			continue
		}

		servers = append(servers, hostCoverageServer{
			Port:       targetPort,
			PID:        pid,
			BinaryName: binaryName,
		})
	}

	return servers, skipped, nil
}

// collectCoverageViaProxy retrieves coverage data through a port-forward
// to the DaemonSet proxy pod and saves it in the standard coverage format.
func collectCoverageViaProxy(restConfig *rest.Config, proxyPod, nodeName string, server hostCoverageServer, coverageDir string) error {
	testName := fmt.Sprintf("%s-%s", nodeName, server.BinaryName)
	testDir := filepath.Join(coverageDir, testName)

	if err := os.MkdirAll(testDir, 0755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	localPort, stopChan, err := nodePortForward(restConfig, proxyPod, server.Port)
	if err != nil {
		return fmt.Errorf("port forward to %d: %w", server.Port, err)
	}
	defer close(stopChan)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://localhost:%d/coverage", localPort))
	if err != nil {
		return fmt.Errorf("GET /coverage: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("coverage endpoint returned %d: %s", resp.StatusCode, body)
	}

	var covResp struct {
		MetaFilename     string `json:"meta_filename"`
		MetaData         string `json:"meta_data"`
		CountersFilename string `json:"counters_filename"`
		CountersData     string `json:"counters_data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&covResp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	metaData, err := base64.StdEncoding.DecodeString(covResp.MetaData)
	if err != nil {
		return fmt.Errorf("decode meta data: %w", err)
	}

	counterData, err := base64.StdEncoding.DecodeString(covResp.CountersData)
	if err != nil {
		return fmt.Errorf("decode counter data: %w", err)
	}

	if err := os.WriteFile(filepath.Join(testDir, covResp.MetaFilename), metaData, 0644); err != nil {
		return fmt.Errorf("write meta: %w", err)
	}

	if err := os.WriteFile(filepath.Join(testDir, covResp.CountersFilename), counterData, 0644); err != nil {
		return fmt.Errorf("write counters: %w", err)
	}

	// Save metadata.json compatible with the render pipeline
	metadata := map[string]interface{}{
		"pod_name":      nodeName,
		"namespace":     "",
		"container":     map[string]string{"name": "", "image": ""},
		"binary_name":   server.BinaryName,
		"pid":           server.PID,
		"coverage_port": server.Port,
		"collected_at":  time.Now().Format(time.RFC3339),
		"test_name":     testName,
		"node_name":     nodeName,
		"host_process":  true,
	}

	metadataJSON, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	return os.WriteFile(filepath.Join(testDir, "metadata.json"), metadataJSON, 0644)
}

// cloneKubeletSource clones the openshift/kubernetes repo at the given commit
// into the standard repos directory structure.
func cloneKubeletSource(clusterDir, commit string) error {
	commitPrefix := commit
	if len(commitPrefix) > 8 {
		commitPrefix = commitPrefix[:8]
	}
	repoDir := filepath.Join(clusterDir, "repos", "github.com", "openshift", "kubernetes", commitPrefix)

	// Skip if already cloned at this commit
	if _, err := os.Stat(filepath.Join(repoDir, "go.mod")); err == nil {
		fmt.Printf("Kubelet source already cloned at %s\n", repoDir)
		return nil
	}

	fmt.Printf("Cloning openshift/kubernetes at commit %s...\n", commit)

	if err := os.MkdirAll(filepath.Dir(repoDir), 0755); err != nil {
		return fmt.Errorf("create repo directory: %w", err)
	}

	// Clone
	cmd := exec.Command("git", "clone", "--no-checkout",
		"https://github.com/openshift/kubernetes.git", repoDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git clone: %w", err)
	}

	// Checkout the specific commit
	checkout := exec.Command("git", "-C", repoDir, "checkout", commit)
	checkout.Stdout = os.Stdout
	checkout.Stderr = os.Stderr
	if err := checkout.Run(); err != nil {
		// Try fetching the commit if not in default clone
		fetch := exec.Command("git", "-C", repoDir, "fetch", "origin", commit)
		fetch.Stdout = os.Stdout
		fetch.Stderr = os.Stderr
		if fetchErr := fetch.Run(); fetchErr != nil {
			return fmt.Errorf("git fetch commit %s: %w", commit, fetchErr)
		}
		retry := exec.Command("git", "-C", repoDir, "checkout", commit)
		retry.Stdout = os.Stdout
		retry.Stderr = os.Stderr
		if err := retry.Run(); err != nil {
			return fmt.Errorf("git checkout %s: %w", commit, err)
		}
	}

	fmt.Printf("Kubelet source cloned to %s\n", repoDir)
	return nil
}

func runScanNodes(cmd *cobra.Command, args []string) error {
	clusterDir := clusterName

	logger, err := createLogger(clusterDir)
	if err != nil {
		return err
	}
	defer logger.Close()

	logger.Info("Starting node coverage scan for cluster: %s", clusterName)

	// Clone kubelet source
	if err := cloneKubeletSource(clusterDir, kubeletCommit); err != nil {
		return fmt.Errorf("clone kubelet source: %w", err)
	}
	fmt.Println()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	clientset, restConfig, err := createKubeClient()
	if err != nil {
		return fmt.Errorf("create kubernetes client: %w", err)
	}

	// Check for DaemonSet proxy pods
	pods, err := clientset.CoreV1().Pods(nodeDiscoveryNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: nodeDiscoveryLabel,
	})
	if err != nil || len(pods.Items) == 0 {
		fmt.Println("Node discovery DaemonSet not found.")
		fmt.Println()
		fmt.Println("To collect host-level coverage (e.g., kubelet), deploy the")
		fmt.Println("node-discovery proxy first:")
		fmt.Println()
		fmt.Println("  oc apply -f node-discovery/daemonset.yaml")
		fmt.Println()
		return fmt.Errorf("namespace %q or DaemonSet %q not found", nodeDiscoveryNamespace, nodeDiscoveryDaemonSet)
	}

	// Build pod -> node mapping
	type proxyPod struct {
		name     string
		nodeName string
	}
	var proxyPods []proxyPod
	for _, p := range pods.Items {
		if p.Status.Phase != "Running" {
			continue
		}
		proxyPods = append(proxyPods, proxyPod{name: p.Name, nodeName: p.Spec.NodeName})
	}

	if len(proxyPods) == 0 {
		return fmt.Errorf("no running proxy pods found in namespace %q", nodeDiscoveryNamespace)
	}

	fmt.Printf("Found %d node-discovery proxy pods\n", len(proxyPods))

	// Build global set of pod binary names for filtering
	podBinaries := buildPodBinarySet(ctx, clientset)
	fmt.Printf("Built pod binary filter (%d known names)\n\n", len(podBinaries))

	coverageDir := filepath.Join(clusterDir, "coverage")
	if err := os.MkdirAll(coverageDir, 0755); err != nil {
		return fmt.Errorf("create coverage directory: %w", err)
	}

	// Scan nodes concurrently
	type nodeResult struct {
		NodeName  string
		Servers   int
		Collected int
		Skipped   int
		Errors    []string
	}

	var (
		results []nodeResult
		mu      sync.Mutex
		wg      sync.WaitGroup
	)

	sem := make(chan struct{}, maxConcurrency)

	for _, pp := range proxyPods {
		wg.Add(1)
		go func(pp proxyPod) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fmt.Printf("Scanning node: %s\n", pp.nodeName)
			result := nodeResult{NodeName: pp.nodeName}

			servers, skipped, err := scanNodeViaProxy(restConfig, pp.name, podBinaries)
			if err != nil {
				errMsg := fmt.Sprintf("scan failed: %v", err)
				result.Errors = append(result.Errors, errMsg)
				logger.Warning("Node %s: %s", pp.nodeName, errMsg)
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
				return
			}

			result.Servers = len(servers)
			result.Skipped = skipped
			if len(servers) == 0 {
				fmt.Printf("  No host-level coverage servers on %s (skipped %d pod servers)\n", pp.nodeName, skipped)
			}

			for _, server := range servers {
				fmt.Printf("  Collecting %s (port %d, pid %s)...\n", server.BinaryName, server.Port, server.PID)
				if err := collectCoverageViaProxy(restConfig, pp.name, pp.nodeName, server, coverageDir); err != nil {
					errMsg := fmt.Sprintf("collect %s:%d: %v", pp.nodeName, server.Port, err)
					result.Errors = append(result.Errors, errMsg)
					logger.Warning("  %s", errMsg)
				} else {
					result.Collected++
					fmt.Printf("  Collected: %s-%s\n", pp.nodeName, server.BinaryName)
				}
			}

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(pp)
	}

	wg.Wait()

	// Summary
	totalServers := 0
	totalCollected := 0
	totalSkipped := 0
	totalErrors := 0
	for _, r := range results {
		totalServers += r.Servers
		totalCollected += r.Collected
		totalSkipped += r.Skipped
		totalErrors += len(r.Errors)
	}

	fmt.Println()
	fmt.Println("Node Scan Summary")
	fmt.Println("=================")
	fmt.Printf("Nodes scanned: %d\n", len(proxyPods))
	fmt.Printf("Host coverage servers found: %d\n", totalServers)
	fmt.Printf("Pod servers skipped: %d\n", totalSkipped)
	fmt.Printf("Successful collections: %d\n", totalCollected)
	if totalErrors > 0 {
		fmt.Printf("Errors: %d\n", totalErrors)
	}
	fmt.Println()

	return nil
}
