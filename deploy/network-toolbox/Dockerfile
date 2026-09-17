FROM projectdiscovery/nuclei:v3.11.1 AS nuclei

FROM debian:bookworm-slim AS nmap-builder

ARG NMAP_VERSION=7.991
ARG NMAP_SHA256=a5d507f29437bef3bedd4771ff9aaa8fc1c2a109ddba1f5b1cf12027456929be
# Bootstrap Debian HTTPS from the certificate bundle in the pinned Nuclei
# stage; apt still verifies repository signatures and package hashes.
COPY --from=nuclei /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Retries=3 update \
    && apt-get install -y --no-install-recommends \
        build-essential bzip2 ca-certificates curl libpcap-dev libssl-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
RUN curl --fail --location --silent --show-error --retry 3 \
        "https://nmap.org/dist/nmap-${NMAP_VERSION}.tar.bz2" -o /tmp/nmap.tar.bz2 \
    && echo "${NMAP_SHA256}  /tmp/nmap.tar.bz2" | sha256sum --check - \
    && tar --extract --bzip2 --file /tmp/nmap.tar.bz2 --directory /tmp \
    && cd "/tmp/nmap-${NMAP_VERSION}" \
    && ./configure --prefix=/opt/nmap --without-zenmap \
    && make -j2 \
    && make install

FROM debian:bookworm-slim

ARG NUCLEI_TEMPLATES_VERSION=v10.4.6
ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/opt/nmap/bin:${PATH}"

COPY --from=nuclei /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN sed -i 's/^Components: main$/Components: main non-free/' /etc/apt/sources.list.d/debian.sources \
    && sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Retries=3 update \
    && apt-get install -y --no-install-recommends \
        arp-scan avahi-daemon avahi-utils bind9-host ca-certificates curl dbus dnsrecon \
        dnsutils fping iproute2 libnss-mdns libpcap0.8 libssl3 libstdc++6 netdiscover nikto openssl python3-pkg-resources smbclient snmp sslscan \
        tar tcpdump traceroute tshark whatweb \
    && rm -rf /var/lib/apt/lists/*

COPY --from=nmap-builder /opt/nmap /opt/nmap
RUN nmap --version && test -s /opt/nmap/share/nmap/nmap-service-probes

# Nuclei confines signed-template helper files to its default template root.
# This release resolves that root to /nuclei-templates in the read-only image.
RUN mkdir -p /nuclei-templates \
    && curl --fail --location --silent --show-error \
        "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/${NUCLEI_TEMPLATES_VERSION}.tar.gz" \
      | tar --extract --gzip --directory /nuclei-templates --strip-components=1 \
    && test -d /nuclei-templates/http/exposures \
    && test -d /nuclei-templates/http/misconfiguration \
    && test -d /nuclei-templates/ssl

COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY avahi-daemon.conf /etc/avahi/avahi-daemon.conf
COPY entrypoint.sh /usr/local/bin/aegis-toolbox-entrypoint
RUN dbus-uuidgen --ensure=/etc/machine-id \
    && chmod 0755 /usr/local/bin/aegis-toolbox-entrypoint

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 CMD avahi-daemon --check || exit 1

CMD ["/usr/local/bin/aegis-toolbox-entrypoint"]
