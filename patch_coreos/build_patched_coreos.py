#!/usr/bin/env python3
"""
Build and push a patched CoreOS image with coverage-instrumented OpenShift RPMs.

Usage (interactive — walks you through each step):
    python3 build_patched_coreos.py

Usage (non-interactive — all arguments provided):
    python3 build_patched_coreos.py \
        --payload quay.io/openshift-release-dev/ocp-release-nightly:4.21.0-0.nightly-multi-2026-02-11-145241-x86_64 \
        --brew-base https://download-01.beak-001.prod.iad2.dc.redhat.com/brewroot/vol/rhel-9/packages/openshift/4.21.0/202602131911.p2.g0df3535.assembly.coverage.el9/ \
        --build-dir /tmp/patched-coreos
"""

import argparse
import os
import subprocess
import sys
from urllib.parse import urlparse

RPM_NAMES = [
    "openshift-kube-scheduler",
    "openshift-kube-controller-manager",
    "openshift-kube-apiserver",
    "openshift-hyperkube",
    "openshift-kubelet",
]

QUAY_REPO = "quay.io/openshift-release-dev/ocp-v4.0-art-dev"

DEFAULT_BUILD_DIR = "/tmp/patched-coreos"


def run_cmd(cmd, capture=True, check=True):
    """Run a command, print it, and return the result."""
    print(f"+ {' '.join(cmd)}", flush=True)
    result = subprocess.run(
        cmd,
        capture_output=capture,
        text=True,
        check=check,
    )
    if capture and result.stdout:
        print(result.stdout.strip(), flush=True)
    return result


def normalize_brew_base(url):
    """Normalize a brew URL to a base URL (without arch dir or RPM filename).

    Accepts any of:
      - Full RPM download URL: .../x86_64/openshift-kubelet-....rpm
      - URL with arch dir:     .../x86_64/
      - Base URL:              .../202602142128.p2.g0df3535.assembly.coverage.el9/

    Returns the base URL without the arch directory (the script adds /x86_64/ when
    constructing RPM download URLs).
    """
    url = url.strip()

    # Strip RPM filename if present
    if url.endswith(".rpm"):
        url = url.rsplit("/", 1)[0]

    # Strip arch directory if present
    url = url.rstrip("/")
    known_arches = ("x86_64", "aarch64", "s390x", "ppc64le", "noarch")
    if url.rsplit("/", 1)[-1] in known_arches:
        url = url.rsplit("/", 1)[0]

    return url.rstrip("/") + "/"


def parse_brew_base(brew_base_url):
    """Parse the brew base URL to extract version and release.

    Expected URL pattern:
      https://.../brewroot/vol/rhel-9/packages/openshift/{version}/{release}/
    """
    parsed = urlparse(brew_base_url)
    path = parsed.path.rstrip("/")
    parts = path.split("/")

    try:
        pkg_idx = parts.index("packages")
        # packages/openshift/{version}/{release}
        package_name = parts[pkg_idx + 1]
        version = parts[pkg_idx + 2]
        release = parts[pkg_idx + 3]
    except (ValueError, IndexError):
        print(
            f"Error: Cannot parse version/release from brew-base URL: {brew_base_url}\n"
            "Expected URL pattern: .../packages/<name>/{version}/{release}/",
            file=sys.stderr,
        )
        sys.exit(1)

    return version, release


def prompt_payload():
    """Interactively prompt for the release payload."""
    print()
    print("=" * 70)
    print("STEP 1: RELEASE PAYLOAD")
    print("=" * 70)
    print("""
Provide the OpenShift release payload image. This is the nightly or CI
payload that your cluster is running.

Example:
  quay.io/openshift-release-dev/ocp-release-nightly:4.21.0-0.nightly-multi-2026-02-11-145241-x86_64
""")
    payload = input("Paste the release payload image: ").strip()
    if not payload:
        print("Error: No payload provided", file=sys.stderr)
        sys.exit(1)
    return payload


def prompt_brew_base():
    """Interactively guide the user to provide the brew base URL."""
    print()
    print("=" * 70)
    print("STEP 2: BREW BASE URL")
    print("=" * 70)
    print("""
To find the brew base URL for coverage-instrumented RPMs:

  1. Find the brew task for the openshift coverage build.
     Example task page:
       https://brewweb.engineering.redhat.com/brew/taskinfo?taskID=70077466

  2. On the task page, click the build link to open the build info page.
     Example build page:
       https://brewweb.engineering.redhat.com/brew/buildinfo?buildID=3952600

  3. On the build page, right-click any x86_64 RPM and copy its download link.
     Example RPM link:
       https://download-01.beak-001.prod.iad2.dc.redhat.com/brewroot/vol/
       rhel-9/packages/openshift/4.21.0/202602142128.p2.g0df3535.assembly
       .coverage.el9/x86_64/openshift-kubelet-4.21.0-202602142128.p2
       .g0df3535.assembly.coverage.el9.x86_64.rpm

You can paste any of:
  - A full RPM download URL (the filename will be stripped automatically)
  - A URL ending in /x86_64/ (the arch dir will be stripped automatically)
  - The brew base URL directly
""")
    url = input("Paste the RPM download URL (or brew base URL): ").strip()
    if not url:
        print("Error: No URL provided", file=sys.stderr)
        sys.exit(1)

    brew_base = normalize_brew_base(url)
    print(f"\nBrew base URL: {brew_base}")
    return brew_base


def prompt_build_dir():
    """Interactively prompt for the build directory."""
    print()
    print("=" * 70)
    print("STEP 3: BUILD DIRECTORY")
    print("=" * 70)
    print(f"""
Where should the Dockerfile and machineconfigs.yaml be written?
Press Enter to use the default: {DEFAULT_BUILD_DIR}
""")
    build_dir = input(f"Build directory [{DEFAULT_BUILD_DIR}]: ").strip()
    if not build_dir:
        build_dir = DEFAULT_BUILD_DIR
    return build_dir


def get_rhel_coreos_pullspec(payload):
    """Get the rhel-coreos image pullspec from the release payload."""
    result = run_cmd(
        ["oc", "adm", "release", "info", "--image-for", "rhel-coreos", payload]
    )
    pullspec = result.stdout.strip()
    if not pullspec:
        print("Error: Failed to get rhel-coreos pullspec from payload", file=sys.stderr)
        sys.exit(1)
    return pullspec


def generate_dockerfile(base_image, brew_base_url, version, release):
    """Generate Dockerfile content matching the existing format."""
    brew_base = brew_base_url.rstrip("/")

    curl_lines = []
    for rpm_name in RPM_NAMES:
        rpm_filename = f"{rpm_name}-{version}-{release}.x86_64.rpm"
        rpm_url = f"{brew_base}/x86_64/{rpm_filename}"
        curl_lines.append(
            f"    curl -k -L -o /tmp/rpms/{rpm_name}.rpm \\\n"
            f"      {rpm_url};"
        )

    curls = " \\\n".join(curl_lines)

    return (
        f"FROM {base_image}\n"
        f"\n"
        f"# Download and install all RPMs in a single dnf transaction\n"
        f"RUN set -eux; \\\n"
        f"    mkdir -p /tmp/rpms; \\\n"
        f"{curls} \\\n"
        f"    \\\n"
        f"    dnf -y install /tmp/rpms/*.rpm; \\\n"
        f"    rm -rf /tmp/rpms; \\\n"
        f"    dnf clean all\n"
    )


def generate_machineconfigs(image_ref):
    """Generate machineconfigs.yaml content."""
    return (
        "---\n"
        "apiVersion: machineconfiguration.openshift.io/v1\n"
        "kind: MachineConfig\n"
        "metadata:\n"
        "  name: 99-master-osimage-override\n"
        "  labels:\n"
        "    machineconfiguration.openshift.io/role: master\n"
        "spec:\n"
        f"  osImageURL: {image_ref}\n"
        "---\n"
        "apiVersion: machineconfiguration.openshift.io/v1\n"
        "kind: MachineConfig\n"
        "metadata:\n"
        "  name: 99-worker-osimage-override\n"
        "  labels:\n"
        "    machineconfiguration.openshift.io/role: worker\n"
        "spec:\n"
        f"  osImageURL: {image_ref}\n"
    )


def check_remote_image_exists(tag):
    """Check if an image already exists on the remote registry."""
    result = run_cmd(["skopeo", "inspect", f"docker://{tag}"], capture=True, check=False)
    return result.returncode == 0


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Build and push a patched CoreOS image with coverage-instrumented "
            "OpenShift RPMs. Run without arguments for interactive mode."
        ),
    )
    parser.add_argument(
        "--payload",
        help=(
            "OpenShift release payload image "
            "(e.g. quay.io/openshift-release-dev/ocp-release-nightly:4.21.0-0.nightly-multi-2026-02-11-145241-x86_64). "
            "If omitted, you will be prompted interactively."
        ),
    )
    parser.add_argument(
        "--brew-base",
        help=(
            "Brew base URL for RPM downloads. Can be a base URL, a URL ending "
            "in /x86_64/, or a full RPM download URL (filename is stripped "
            "automatically). If omitted, you will be walked through finding it."
        ),
    )
    parser.add_argument(
        "--build-dir",
        help=f"Directory to write the Dockerfile and machineconfigs.yaml (default: {DEFAULT_BUILD_DIR})",
    )
    parser.add_argument(
        "--dest",
        help=(
            "Destination image name (e.g. quay.io/myrepo/myimage:mytag). "
            "Overrides the default destination of "
            f"{QUAY_REPO}:{{version}}-{{release}}."
        ),
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite the image if it already exists on the remote registry",
    )

    args = parser.parse_args()

    # Interactive prompts for missing arguments
    payload = args.payload or prompt_payload()
    brew_base = normalize_brew_base(args.brew_base) if args.brew_base else prompt_brew_base()
    build_dir = args.build_dir or prompt_build_dir()

    # Parse brew base URL
    version, release = parse_brew_base(brew_base)

    # Determine image tag
    image_tag = args.dest or f"{QUAY_REPO}:{version}-{release}"

    # Show plan
    rpm_list = "\n".join(f"      - {name}-{version}-{release}.x86_64.rpm" for name in RPM_NAMES)
    print()
    print("=" * 70)
    print("BUILD PLAN")
    print("=" * 70)
    print(f"""
This script will perform the following steps:

  1. RESOLVE BASE IMAGE
     Use 'oc adm release info' to extract the rhel-coreos image pullspec
     from the release payload. This is the base CoreOS image that all
     cluster nodes run.

     Payload: {payload}

  2. GENERATE DOCKERFILE
     Create a Dockerfile that starts FROM the rhel-coreos base image and
     installs coverage-instrumented RPMs on top of it. The RPMs are
     downloaded from brew during the container build.

     RPMs to install:
{rpm_list}

     Brew base: {brew_base}
     Version:   {version}
     Release:   {release}

  3. BUILD IMAGE
     Run 'podman build' to produce the patched CoreOS image locally.

  4. PUSH IMAGE
     Push the image to the ART dev registry:

       {image_tag}

     The push captures the image digest (sha256:...).

  5. GENERATE MACHINECONFIGS
     Write machineconfigs.yaml that tells the Machine Config Operator to
     rebase all master and worker nodes onto the patched CoreOS image
     (referenced by digest for immutability).

     Apply with: oc apply -f {build_dir}/machineconfigs.yaml

  Build artifacts will be written to: {build_dir}
""")

    if not args.payload and not args.brew_base:
        # Interactive mode — confirm before proceeding
        confirm = input("Proceed? [Y/n]: ").strip().lower()
        if confirm and confirm != "y":
            print("Aborted.")
            sys.exit(0)

    # Step 1: Resolve base image
    print()
    print("-" * 70)
    print("Step 1: Resolving rhel-coreos base image...")
    print("-" * 70)
    base_image = get_rhel_coreos_pullspec(payload)
    print(f"Base image: {base_image}")

    # Check if image already exists remotely
    print(f"\nChecking if {image_tag} already exists...")
    if check_remote_image_exists(image_tag):
        if not args.overwrite:
            print(
                f"Error: Image {image_tag} already exists on the remote registry.\n"
                f"Use --overwrite to push anyway.",
                file=sys.stderr,
            )
            sys.exit(1)
        else:
            print(f"WARNING: Image {image_tag} already exists; --overwrite specified, will overwrite.")
    else:
        print("Image does not exist remotely, proceeding.")

    # Step 2: Generate Dockerfile
    print()
    print("-" * 70)
    print("Step 2: Generating Dockerfile...")
    print("-" * 70)
    os.makedirs(build_dir, exist_ok=True)
    dockerfile_path = os.path.join(build_dir, "Dockerfile")
    dockerfile_content = generate_dockerfile(base_image, brew_base, version, release)
    with open(dockerfile_path, "w") as f:
        f.write(dockerfile_content)
    print(f"Wrote {dockerfile_path}")

    # Step 3: Build image
    print()
    print("-" * 70)
    print("Step 3: Building image with podman...")
    print("-" * 70)
    run_cmd(["podman", "build", "-t", image_tag, build_dir], capture=False)

    # Step 4: Push image
    print()
    print("-" * 70)
    print(f"Step 4: Pushing image to {QUAY_REPO}...")
    print("-" * 70)
    digest_file = os.path.join(build_dir, ".digest")
    run_cmd(
        ["podman", "push", "--digestfile", digest_file, image_tag],
        capture=False,
    )

    with open(digest_file) as f:
        digest = f.read().strip()
    os.remove(digest_file)
    print(f"\nPushed with digest: {digest}")

    # Step 5: Generate machineconfigs
    print()
    print("-" * 70)
    print("Step 5: Generating machineconfigs.yaml...")
    print("-" * 70)
    # Use the repo portion of image_tag (strip tag) for the digest reference
    image_repo = image_tag.rsplit(":", 1)[0] if ":" in image_tag else image_tag
    image_ref = f"{image_repo}@{digest}"
    mc_path = os.path.join(build_dir, "machineconfigs.yaml")
    mc_content = generate_machineconfigs(image_ref)
    with open(mc_path, "w") as f:
        f.write(mc_content)
    print(f"Wrote {mc_path}")

    # Done
    print()
    print("=" * 70)
    print("DONE")
    print("=" * 70)
    print(f"""
  Image pushed:  {image_tag}
  Image digest:  {image_ref}
  Dockerfile:    {dockerfile_path}
  MachineConfig: {mc_path}

To apply the patched CoreOS image to your cluster:

  oc apply -f {mc_path}

This will cause the Machine Config Operator to drain and reboot each node,
replacing the OS image with the patched version containing coverage-
instrumented kubelet, kube-apiserver, kube-controller-manager, and
kube-scheduler binaries.
""")


if __name__ == "__main__":
    main()
