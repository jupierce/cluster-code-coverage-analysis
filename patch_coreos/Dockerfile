FROM quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:a2d7f1d2bc2344a8e08eb1e206add71a2f164ccf1bd1c7bd0d7831bbae255837

# Download and install all RPMs in a single dnf transaction
RUN set -eux; \
    mkdir -p /tmp/rpms; \
    curl -k -L -o /tmp/rpms/openshift-kube-scheduler.rpm \
      https://download-01.beak-001.prod.iad2.dc.redhat.com/brewroot/vol/rhel-9/packages/openshift/4.21.0/202602131911.p2.g0df3535.assembly.coverage.el9/x86_64/openshift-kube-scheduler-4.21.0-202602131911.p2.g0df3535.assembly.coverage.el9.x86_64.rpm; \
    curl -k -L -o /tmp/rpms/openshift-kube-controller-manager.rpm \
      https://download-01.beak-001.prod.iad2.dc.redhat.com/brewroot/vol/rhel-9/packages/openshift/4.21.0/202602131911.p2.g0df3535.assembly.coverage.el9/x86_64/openshift-kube-controller-manager-4.21.0-202602131911.p2.g0df3535.assembly.coverage.el9.x86_64.rpm; \
    curl -k -L -o /tmp/rpms/openshift-kube-apiserver.rpm \
      https://download-01.beak-001.prod.iad2.dc.redhat.com/brewroot/vol/rhel-9/packages/openshift/4.21.0/202602131911.p2.g0df3535.assembly.coverage.el9/x86_64/openshift-kube-apiserver-4.21.0-202602131911.p2.g0df3535.assembly.coverage.el9.x86_64.rpm; \
    curl -k -L -o /tmp/rpms/openshift-hyperkube.rpm \
      https://download-01.beak-001.prod.iad2.dc.redhat.com/brewroot/vol/rhel-9/packages/openshift/4.21.0/202602131911.p2.g0df3535.assembly.coverage.el9/x86_64/openshift-hyperkube-4.21.0-202602131911.p2.g0df3535.assembly.coverage.el9.x86_64.rpm; \
    curl -k -L -o /tmp/rpms/openshift-kubelet.rpm \
      https://download-01.beak-001.prod.iad2.dc.redhat.com/brewroot/vol/rhel-9/packages/openshift/4.21.0/202602131911.p2.g0df3535.assembly.coverage.el9/x86_64/openshift-kubelet-4.21.0-202602131911.p2.g0df3535.assembly.coverage.el9.x86_64.rpm; \
    \
    dnf -y install /tmp/rpms/*.rpm; \
    rm -rf /tmp/rpms; \
    dnf clean all

