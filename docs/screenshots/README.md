# Screenshot provenance checklist

No screenshot file is currently committed. The Docker application is healthy and seeded, but the
automated browser runtime is blocked by the Windows workspace ACL failure. No designed or mocked
replacement image may be added.

Capture only from the real application after running:

~~~powershell
docker compose up --build -d
docker compose exec -T api python -m scripts.demo
~~~

| Recommended file | Route/state | Recommended use |
| --- | --- | --- |
| soc-overview.png | / at desktop width | GitHub README hero and LinkedIn project overview |
| incident-detail.png | /incidents/inc-52fe50efc453c4 | Incident response, evidence timeline, correlation, and CTI pivot |
| threat-intelligence.png | /threat-intelligence after a local synthetic lookup | Connector safeguards, reputation context, and audit history |
| soc-analytics.png | /analytics | Data analysis, detection yield, and entity risk |
| attack-coverage.png | /attack-coverage | ATT&CK v19.1 coverage, explicit gaps, and Navigator export |
| responsive-incident-queue.png | /incidents at narrow width | Responsive full-stack dashboard proof |

Before committing a capture:

1. Confirm the top bar says LOCAL / SYNTHETIC and API connected.
2. Confirm only fictional identities, RFC 5737 addresses, and deterministic incidents are visible.
3. Ensure the displayed feature was exercised against the running API; do not substitute a static
   HTML page or design mock.
4. Record the capture date, viewport, demo command, and application revision in the commit message
   or pull-request notes.
5. Rerun the repository link, prohibited-data, and secret scans after adding image references.
