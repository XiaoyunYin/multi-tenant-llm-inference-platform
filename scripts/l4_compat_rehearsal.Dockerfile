FROM ubuntu:24.04@sha256:a853f94d226358a79c740cfc7bce0c289748f3fe3488d921d038ccd752c61b60
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 cloud-init curl openssl ca-certificates iptables libatomic1 && rm -rf /var/lib/apt/lists/*
COPY docker.tgz /tmp/docker.tgz
RUN tar -xzf /tmp/docker.tgz -C /usr/bin --strip-components=1 && mv /usr/bin/docker /usr/bin/docker-real
COPY l4_compat_rehearsal_host.py /rehearsal/host.py
RUN ln -sf /rehearsal/host.py /usr/bin/docker && ln -sf /rehearsal/host.py /usr/bin/systemctl && ln -sf /rehearsal/host.py /usr/bin/nvidia-smi && chmod +x /rehearsal/host.py
ENTRYPOINT ["python3", "/rehearsal/host.py", "init"]
