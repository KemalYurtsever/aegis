"""Opt-in real-tool check against synthetic HTTP version evidence; no NVD calls."""
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.services.nse_verification_service import NseVerificationResult
from app.services.port_scan_service import DetectedService, OpenPort
from app.services.service_enrichment_service import enrich_open_services


@pytest.mark.skipif(not os.getenv("AEGIS_LIVE_ENRICHMENT_TEST_IP"), reason="Real-tool fixture is opt-in")
def test_real_whatweb_on_controlled_http_fixture():
    address = os.environ["AEGIS_LIVE_ENRICHMENT_TEST_IP"]

    class Handler(BaseHTTPRequestHandler):
        server_version = "nginx/1.24.0"
        sys_version = ""

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Powered-By", "PHP/8.2.1")
            self.end_headers()
            self.wfile.write(b'<html><head><meta name="generator" content="WordPress 6.5.2"></head><body>Controlled Aegis test fixture</body></html>')

        def log_message(self, *_args):
            pass

    # Bind only an explicitly supplied address assigned to this host.
    server = ThreadingHTTPServer((address, 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        result = enrich_open_services(address, [OpenPort(port, "http", None)],
                                       [DetectedService(port, "http", None, None, None, ())], NseVerificationResult((), (), 0))
        run = result.tool_runs[0]
        assert run.status == "COMPLETED", run.details
        assert {(item.product, item.version) for item in result.services} >= {
            ("nginx", "1.24.0"), ("PHP", "8.2.1"), ("WordPress", "6.5.2"),
        }
        print({"tool": run.tool, "status": run.status, "duration_ms": run.duration_ms,
               "fixture_identities": [(item.product, item.version) for item in result.services]})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
