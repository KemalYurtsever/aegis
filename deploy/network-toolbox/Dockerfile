FROM projectdiscovery/nuclei:v3.11.1 AS nuclei

FROM debian:bookworm-slim

ARG NUCLEI_TEMPLATES_VERSION=v10.4.6
ENV DEBIAN_FRONTEND=noninteractive

RUN sed -i 's/^Components: main$/Components: main non-free/' /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        arp-scan avahi-daemon avahi-utils bind9-host ca-certificates curl dbus dnsrecon \
        dnsutils fping iproute2 libnss-mdns netdiscover nikto nmap openssl python3-pkg-resources smbclient snmp sslscan \
        tar tcpdump traceroute tshark whatweb \
    && rm -rf /var/lib/apt/lists/*

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
