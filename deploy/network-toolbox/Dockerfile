FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends arp-scan ca-certificates curl dnsutils iproute2 nmap traceroute \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
