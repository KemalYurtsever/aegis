from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

from app.models import AgentEnrollment, utc_now

AgentHealthStatus = Literal["WAITING", "REPORTING", "DELAYED", "OFFLINE"]


@dataclass(frozen=True)
class AgentHealth:
    status: AgentHealthStatus
    seconds_since_last_report: int | None


def calculate_agent_health(enrollment: AgentEnrollment, now: datetime | None = None) -> AgentHealth:
    current = now or utc_now()
    last_seen = enrollment.last_seen_at
    if last_seen is None:
        return AgentHealth("WAITING", None)
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    age = max(0, int((current - last_seen).total_seconds()))
    interval = max(10, enrollment.report_interval_seconds or 60)
    if age <= max(interval * 2, 90):
        status = "REPORTING"
    elif age <= max(interval * 5, 300):
        status = "DELAYED"
    else:
        status = "OFFLINE"
    return AgentHealth(status, age)
