from app.agent_main import app as agent_app


def test_agent_ingress_exposes_only_agent_protocol_routes():
    paths = {route.path for route in agent_app.routes}
    assert paths == {
        "/api/agent/health",
        "/api/agent/metrics",
        "/api/agent/jobs/next",
        "/api/agent/jobs/{job_id}/result",
    }
