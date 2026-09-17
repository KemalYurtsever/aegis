import threading
import time

from app.models import NmapPortCache, utc_now
from app.schemas import LabCommandRead


def _device(client, headers, address="198.18.5.60"):
    response = client.post(
        "/api/devices",
        headers=headers,
        json={
            "name": "Nmap job target",
            "ip_address": address,
            "device_type": "Server",
            "is_active": True,
        },
    )
    assert response.status_code == 201
    return response.json()


def _wait_for_job(client, headers, job_id, statuses=("COMPLETED", "PARTIAL", "FAILED", "CANCELLED")):
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        response = client.get(f"/api/security/toolbox/nmap/jobs/{job_id}", headers=headers)
        assert response.status_code == 200
        job = response.json()
        if job["status"] in statuses:
            return job
        time.sleep(0.02)
    raise AssertionError(f"Nmap job {job_id} did not reach {statuses}")


def test_nmap_job_is_adaptive_audited_and_reuses_closed_cache(client, admin_headers, monkeypatch):
    device = _device(client, admin_headers)
    calls = []

    def fake_scan(address, ports, service_detection, **kwargs):
        calls.append((address, list(ports), service_detection, kwargs))
        if kwargs["profile"] == "FAST" and set(ports) == {80, 81}:
            output = "80/tcp open http\n81/tcp closed hosts2-ns"
        else:
            output = "80/tcp open http Apache"
        return LabCommandRead(
            tool="nmap", target=address, exit_code=0, output=output,
            duration_ms=2.0, scanned_port_count=len(ports),
        )

    monkeypatch.setattr("app.services.nmap_scan_job_service.nmap_tcp_scan", fake_scan)
    created = client.post(
        "/api/security/toolbox/nmap/jobs",
        headers=admin_headers,
        json={
            "device_id": device["id"], "ports": [80, 81],
            "scan_mode": "CUSTOM", "profile": "DETAILED",
            "traffic_policy": "IDS_FRIENDLY", "show_reason": True,
        },
    )
    assert created.status_code == 202
    first = _wait_for_job(client, admin_headers, created.json()["id"])

    assert first["status"] == "COMPLETED"
    assert first["progress_percent"] == 100
    assert first["open_ports"] == [80]
    assert first["requested_by"] == "test-admin"
    assert first["client_ip"] == "testclient"
    assert first["traffic_policy"] == "IDS_FRIENDLY"
    assert calls[0][3]["profile"] == "FAST"
    assert calls[0][3]["discovery_profile"] == "DETAILED"
    assert calls[0][3]["show_reason"] is True
    assert calls[1][1] == [80]
    assert calls[1][3]["profile"] == "DETAILED"

    second_response = client.post(
        "/api/security/toolbox/nmap/jobs",
        headers=admin_headers,
        json={
            "device_id": device["id"], "ports": [80, 81],
            "scan_mode": "CUSTOM", "profile": "FAST",
        },
    )
    assert second_response.status_code == 202
    second = _wait_for_job(client, admin_headers, second_response.json()["id"])

    assert second["status"] == "COMPLETED"
    assert second["cache_hit"] is True
    assert second["cached_closed_count"] == 1
    assert second["scanned_port_count"] == 1
    assert calls[-1][1] == [80]
    history = client.get(
        f"/api/security/toolbox/nmap/jobs?device_id={device['id']}&limit=5",
        headers=admin_headers,
    )
    assert history.status_code == 200
    assert [item["id"] for item in history.json()] == [second["id"], first["id"]]


def test_nmap_job_detects_possible_filtering_after_known_open_port(client, admin_headers, monkeypatch):
    device = _device(client, admin_headers, "198.18.5.61")
    with client.app.state.session_factory() as db:
        db.add(NmapPortCache(
            device_id=device["id"], target_ip=device["ip_address"],
            port=443, state="OPEN", observed_at=utc_now(),
        ))
        db.commit()

    monkeypatch.setattr(
        "app.services.nmap_scan_job_service.nmap_tcp_scan",
        lambda address, ports, service_detection, **kwargs: LabCommandRead(
            tool="nmap", target=address, exit_code=0,
            output="Not shown: 1 filtered tcp port (no-response)",
            duration_ms=2.0, scanned_port_count=1,
        ),
    )
    response = client.post(
        "/api/security/toolbox/nmap/jobs",
        headers=admin_headers,
        json={"device_id": device["id"], "ports": [443], "scan_mode": "CUSTOM"},
    )
    assert response.status_code == 202
    job = _wait_for_job(client, admin_headers, response.json()["id"])

    assert job["status"] == "PARTIAL"
    assert job["ban_signal"] is True
    assert "IDS/firewall block is possible" in job["ban_reason"]
    assert "Possible block signal" in job["output"]


def test_running_nmap_job_can_be_cancelled_between_bounded_phases(client, admin_headers, monkeypatch):
    device = _device(client, admin_headers, "198.18.5.62")
    release = threading.Event()

    def slow_discovery(address, ports, service_detection, **kwargs):
        release.wait(timeout=2)
        return LabCommandRead(
            tool="nmap", target=address, exit_code=0,
            output="80/tcp open http", duration_ms=2.0, scanned_port_count=1,
        )

    monkeypatch.setattr("app.services.nmap_scan_job_service.nmap_tcp_scan", slow_discovery)
    response = client.post(
        "/api/security/toolbox/nmap/jobs",
        headers=admin_headers,
        json={
            "device_id": device["id"], "ports": [80],
            "scan_mode": "CUSTOM", "profile": "AGGRESSIVE",
        },
    )
    assert response.status_code == 202
    job_id = response.json()["id"]
    running = _wait_for_job(client, admin_headers, job_id, statuses=("RUNNING",))
    assert running["phase"] == "DISCOVERY"

    cancelled = client.post(
        f"/api/security/toolbox/nmap/jobs/{job_id}/cancel", headers=admin_headers
    )
    assert cancelled.status_code == 200
    assert cancelled.json()["cancel_requested"] is True
    release.set()
    finished = _wait_for_job(client, admin_headers, job_id)
    assert finished["status"] == "CANCELLED"
    assert finished["phase"] == "CANCELLED"
