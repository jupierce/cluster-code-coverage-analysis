#!/usr/bin/env python3
"""
Build and push a patched CoreOS image with coverage-instrumented OpenShift RPMs.

Usage:
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
        description="Build and push a patched CoreOS image with coverage-instrumented OpenShift RPMs."
    )
    parser.add_argument(
        "--payload",
        required=True,
        help=(
            "OpenShift release payload image "
            "(e.g. quay.io/openshift-release-dev/ocp-release-nightly:4.21.0-0.nightly-multi-2026-02-11-145241-x86_64)"
        ),
    )
    parser.add_argument(
        "--brew-base",
        required=True,
        help=(
            "Brew base URL for RPM downloads "
            "(e.g. https://download-01.beak-001.prod.iad2.dc.redhat.com/brewroot/vol/rhel-9/packages/openshift/4.21.0/202602131911.p2.g0df3535.assembly.coverage.el9/)"
        ),
    )
    parser.add_argument(
        "--build-dir",
        required=True,
        help="Directory to write the Dockerfile and machineconfigs.yaml",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite the image if it already exists on the remote registry",
    )

    args = parser.parse_args()

    # Parse brew base URL
    version, release = parse_brew_base(args.brew_base)
    print(f"Parsed version: {version}")
    print(f"Parsed release: {release}")

    # Get rhel-coreos pullspec
    print(f"\nLooking up rhel-coreos image for payload: {args.payload}")
    base_image = get_rhel_coreos_pullspec(args.payload)
    print(f"Base image: {base_image}")

    # Determine image tag
    image_tag = f"{QUAY_REPO}:{version}-{release}"
    print(f"\nTarget image tag: {image_tag}")

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

    # Create build directory
    os.makedirs(args.build_dir, exist_ok=True)

    # Generate and write Dockerfile
    dockerfile_path = os.path.join(args.build_dir, "Dockerfile")
    dockerfile_content = generate_dockerfile(base_image, args.brew_base, version, release)
    with open(dockerfile_path, "w") as f:
        f.write(dockerfile_content)
    print(f"\nWrote Dockerfile to {dockerfile_path}")

    # Build image
    print("\nBuilding image...")
    run_cmd(["podman", "build", "-t", image_tag, args.build_dir], capture=False)

    # Push image and capture digest
    digest_file = os.path.join(args.build_dir, ".digest")
    print(f"\nPushing image to {image_tag}...")
    run_cmd(
        ["podman", "push", "--digestfile", digest_file, image_tag],
        capture=False,
    )

    # Read digest
    with open(digest_file) as f:
        digest = f.read().strip()
    print(f"\nPushed with digest: {digest}")

    # Generate machineconfigs.yaml with the pushed image digest
    image_ref = f"{QUAY_REPO}@{digest}"
    mc_path = os.path.join(args.build_dir, "machineconfigs.yaml")
    mc_content = generate_machineconfigs(image_ref)
    with open(mc_path, "w") as f:
        f.write(mc_content)
    print(f"Wrote machineconfigs.yaml to {mc_path}")
    print(f"OS image URL: {image_ref}")

    # Clean up digest temp file
    os.remove(digest_file)

    print("\nDone!")


if __name__ == "__main__":
    main()
