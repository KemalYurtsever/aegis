import csv
import re
from functools import lru_cache
from pathlib import Path


_DATA_DIR = Path(__file__).resolve().parents[2] / "data"
_REGISTRIES = (("oui36.csv", 9), ("mam.csv", 7), ("oui.csv", 6))


@lru_cache(maxsize=1)
def load_assignments() -> dict[str, str]:
    assignments: dict[str, str] = {}
    for filename, prefix_length in _REGISTRIES:
        path = _DATA_DIR / filename
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                prefix = re.sub(r"[^0-9A-F]", "", row.get("Assignment", "").upper())
                organization = row.get("Organization Name", "").strip()
                if len(prefix) == prefix_length and organization:
                    assignments[prefix] = organization[:255]
    return assignments


def lookup_mac_vendor(mac_address: str | None) -> str | None:
    if not mac_address:
        return None
    normalized = re.sub(r"[^0-9A-F]", "", mac_address.upper())
    if len(normalized) != 12:
        return None
    if int(normalized[:2], 16) & 0x02:
        return "Locally administered / randomized"
    assignments = load_assignments()
    for prefix_length in (9, 7, 6):
        if normalized[:prefix_length] in assignments:
            return assignments[normalized[:prefix_length]]
    return None
