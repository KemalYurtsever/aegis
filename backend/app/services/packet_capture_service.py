from datetime import datetime, timezone
from ipaddress import ip_address
import re

from sqlalchemy.orm import Session

from app.models import PacketCapture, PacketMetadata, utc_now


_NON_PHYSICAL = re.compile(r"virtual|loopback|miniport|tunnel|vpn|hyper-v|wi-fi direct|wsl|mullvad", re.I)


def available_interfaces() -> list[dict]:
    from scapy.all import conf

    interfaces = []
    for item in conf.ifaces.values():
        value = str(item.network_name)
        address = str(item.ip or "").strip()
        usable_address = False
        if address:
            try:
                parsed = ip_address(address)
                usable_address = not parsed.is_link_local and not parsed.is_loopback
            except ValueError:
                pass
        identity = f"{item.name} {item.description}"
        recommended = usable_address and not _NON_PHYSICAL.search(identity)
        details = [str(item.name)]
        if item.description and item.description != item.name:
            details.append(str(item.description))
        if address:
            details.append(address)
        interfaces.append({
            "value": value,
            "label": " — ".join(details),
            "ip_address": address or None,
            "recommended": bool(recommended),
        })
    return sorted(interfaces, key=lambda item: (not item["recommended"], item["label"].lower()))


def capture_metadata(interface_name: str | None, duration_seconds: int, max_packets: int) -> list[dict]:
    from scapy.all import IP, IPv6, TCP, UDP, sniff
    if interface_name is not None and interface_name not in {item["value"] for item in available_interfaces()}:
        raise ValueError("Unknown packet-capture interface")
    records = []
    def observe(packet):
        network = packet.getlayer(IP) or packet.getlayer(IPv6)
        transport = packet.getlayer(TCP) or packet.getlayer(UDP)
        records.append({
            "timestamp": datetime.fromtimestamp(float(packet.time), timezone.utc),
            "source_ip": getattr(network, "src", None), "destination_ip": getattr(network, "dst", None),
            "protocol": "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "IP" if network else packet.name[:20],
            "source_port": getattr(transport, "sport", None), "destination_port": getattr(transport, "dport", None),
            "length_bytes": len(packet),
        })
    sniff(iface=interface_name or None, timeout=duration_seconds, count=max_packets, prn=observe, store=False, promisc=False)
    return records


def run_capture(interface_name: str | None, duration_seconds: int, max_packets: int, db: Session) -> PacketCapture:
    capture = PacketCapture(interface_name=interface_name, duration_seconds=duration_seconds, max_packets=max_packets)
    db.add(capture); db.flush()
    try:
        for record in capture_metadata(interface_name, duration_seconds, max_packets):
            db.add(PacketMetadata(capture_id=capture.id, **record))
        capture.status = "COMPLETED"
    except Exception as exc:
        capture.status = "FAILED"; capture.error = str(exc)[:500]
    capture.completed_at = utc_now(); db.commit(); db.refresh(capture)
    return capture
