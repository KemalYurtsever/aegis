"""Synchronize the local NVD mirror from official JSON 2.0 feeds."""

import argparse
import sys
import time
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.database import Base, SessionLocal, engine  # noqa: E402
from app.models import CveMirrorState  # noqa: E402
from app.services.cve_mirror_service import CveMirrorRunner  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode", choices=("modified", "recent", "year", "full"),
        default="modified",
    )
    parser.add_argument("--year", type=int)
    arguments = parser.parse_args()
    Base.metadata.create_all(bind=engine)
    runner = CveMirrorRunner(SessionLocal)
    runner.start()
    if not runner.sync(arguments.mode.upper(), arguments.year):
        print("A CVE mirror synchronization is already running.", file=sys.stderr)
        runner.shutdown()
        return 2
    previous = None
    try:
        while True:
            with SessionLocal() as db:
                state = db.get(CveMirrorState, 1)
                if state is None:
                    raise RuntimeError("CVE mirror state disappeared")
                snapshot = (
                    state.status, state.current_feed, state.feeds_completed,
                    state.feeds_total, state.progress_percent,
                )
                if snapshot != previous:
                    print(
                        f"{state.status} feed={state.current_feed or '-'} "
                        f"feeds={state.feeds_completed}/{state.feeds_total} "
                        f"progress={state.progress_percent}%",
                        flush=True,
                    )
                    previous = snapshot
                if state.status != "SYNCING":
                    if state.error:
                        print(state.error, file=sys.stderr)
                    print(
                        f"records={state.record_count} cpe_matches={state.cpe_match_count} "
                        f"baseline_complete={state.baseline_complete}",
                        flush=True,
                    )
                    return 0 if state.status == "READY" else 1
            time.sleep(1)
    except KeyboardInterrupt:
        runner.cancel()
        print("Cancellation requested; waiting for the current bounded operation.", flush=True)
        return 130
    finally:
        runner.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
