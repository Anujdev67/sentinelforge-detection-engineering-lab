# Security, privacy, and secret handling

## Data policy

SentinelForge accepts and generates synthetic lab data only. The committed fixtures use fictional `example.test` identities/hosts and RFC 5737 addresses (`192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`). The event model rejects globally routable public addresses.

Do not paste or import employer, customer, production tenant, incident, identity, endpoint, credential, screenshot, or operating-procedure data. If extending fixtures, use the factories in `telemetry/generators` and run the repository safety tests.

## Secrets

`.env.example` contains change-me local placeholders. Copy it to ignored `.env` and replace the database password for your machine. Never commit:

- `.env` files other than `.env.example`;
- Azure client secrets, certificates, tokens, subscription/tenant identifiers, or exported connection objects;
- database dumps, Terraform state/plans, Logic Apps connection parameters, API keys, or evidence packages;
- private keys, access tokens, or production webhook URLs.

For an authorized Azure planning environment, use workload identity federation or short-lived environment-based credentials. Store CI secrets in the platform secret store; do not add them to variables files.

## SOAR safety model

Every local playbook uses a three-state workflow: requested, approved by a different identity, and simulated completion. Self-approval is rejected. Outputs can add context, recommendations, local status, evidence manifests, and audit records only.

No implementation can disable a user, revoke sessions, reset credentials, isolate a device, terminate a process, quarantine a file, block an address, send a message, create a ServiceNow ticket, or mutate Azure. The Logic Apps artifacts document how those connector boundaries would be designed but remain non-deployable and list forbidden actions.


## Threat-intelligence connector safety

The Threat Intelligence page works without an account by using the deterministic local connector.
VirusTotal API v3, AbuseIPDB API v2, and GreyNoise Community are optional read-only report lookups.
They are disabled unless both the global live-lookup switch and the provider API key are set.

~~~dotenv
SENTINELFORGE_LIVE_REPUTATION_ENABLED=true
SENTINELFORGE_VIRUSTOTAL_API_KEY=your-key
SENTINELFORGE_ABUSEIPDB_API_KEY=your-key
SENTINELFORGE_GREYNOISE_API_KEY=your-key
~~~

Set only the providers you intend to use, restart the API, and confirm connector state on
[Threat Intelligence](http://localhost:5173/threat-intelligence). Keys are read through Pydantic
SecretStr, are never returned by the status API, and must remain only in ignored .env or your
secret manager. Provider URLs are fixed in code, redirects are disabled, and the lookup endpoint
accepts bare IP addresses/domains rather than user-controlled URLs.

Before a live lookup, the API blocks private, loopback, reserved, link-local, multicast, and
documentation IP ranges, plus local/documentation domains. Only normalized enrichment fields are
cached; raw provider responses and API keys are not persisted. Provider verdicts are context for
human investigation and never trigger automatic containment. Review each provider's data-sharing,
quota, licensing, retention, and privacy terms before enabling it.

## Deployment boundaries

- The API has no authentication and is suitable only for a loopback/private local lab.
- The Compose database has no published host port.
- Azure rules and automation are disabled by default.
- The Entra connector is opt-in and requires a separate same-tenant permission review.
- The example does not create paid resources through any project command.
- An owner must perform privacy, retention, RBAC, connector, and cost review before adapting IaC.

## Reporting a secret exposure

Stop using the exposed value, revoke/rotate it through its owning platform, remove it from Git history using an approved process, and rerun secret scanning. Do not paste the value into an issue or chat while requesting help.
