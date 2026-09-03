# LIIMS automation center

The **Automation center** is an administrator-only control surface. It reuses
the normal LIIMS monitoring, alert, discovery, diagnostic, notification,
reporting, vulnerability, and agent records; it does not run a second hidden
monitoring system.

## Automations

- Related active alerts on the same device group or IP network are correlated
  into one incident and resolve when the related alerts recover.
- One-time, daily, and weekly maintenance windows can target all devices or one
  device group. Monitoring results continue, while new alerts are suppressed.
- Optional incident diagnostics queue only the existing allowlisted agent jobs:
  network connections, top processes, and security log summary.
- Availability reports are generated locally on schedule and recorded in the
  database. Enabled notification channels receive a short generation notice.
- Inventory and agent fingerprints form a configuration baseline. Later
  changes create visible drift events without altering the device.
- The desired agent version is compared with reporting agents; updates are not
  installed automatically.
- Optional discovery runs when the connected network changes or its interval is
  due. Optional service discovery creates checks for one unconfigured device
  per cycle. Optional defensive assessment scans one device per interval.
- The health summary uses Foundry Local only when a loopback endpoint and model
  are configured. Otherwise, LIIMS produces a deterministic built-in summary.

Network-generating automations are disabled by default. Turn them on from the
Automation center only for networks you administer.

## Foundry Local

Set both variables in `backend/.env`, then restart the hybrid backend:

```text
LIIMS_FOUNDRY_LOCAL_URL=http://127.0.0.1:5272
LIIMS_FOUNDRY_LOCAL_MODEL=your-local-model-id
```

LIIMS rejects non-loopback model endpoints. It sends only an aggregate health
sentence, not credentials, packet contents, diagnostic results, or device
records. The model is advisory and cannot execute jobs or change settings.

## Reports

Scheduled reports are stored under `backend/reports` by default. Change the
directory with `LIIMS_REPORT_DIRECTORY`. Downloads validate the filename and
never accept arbitrary paths.

## Safety boundaries

- All settings and actions require the `ADMIN` role.
- Existing request-size and rate limits apply.
- Diagnostic job types and result sizes remain allowlisted and bounded.
- Maintenance suppresses alerts but never deletes monitoring history.
- Discovery and defensive scans follow the existing connected-lab policy.
- Agent updates are reported as needed, not silently installed.
