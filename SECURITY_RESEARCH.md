# Cybersecurity Control Center

KRAKEN provides owner-controlled, bounded security assessments. All seven module switches default to OFF. The existing Security research switch is a master gate; Computer control and AI agent are also required. Active requests additionally require Internet. Module switches never grant arbitrary shell access.

## Enable and use

1. Open Settings, configure an owner password if none exists, and sign in. Passwords are salted PBKDF2 hashes; this upgrade does not set or replace your password.
2. Enable AI agent, Computer control and Security research in Command center. Enable Internet only for authorized network/web checks.
3. Open **Cybersecurity**. Enable the particular module you need.
4. Authorize a target: an existing workspace/project path, a literal IPv4 address plus at most eight ports, or an exact HTTP(S) URL using a literal IPv4 address. Record your ownership/written authorization and choose an expiry of 1–24 hours.
5. Select a matching target and run the assessment. Inspect findings and evidence, then export JSON if needed. Revoke scope or disable modules after use.

No module may run without a live, recently password-authenticated owner session and an explicit valid matching scope. Authentication is checked before enqueue, again at process creation, during execution, and before report persistence. Login expires after one hour; security operations require password verification within ten minutes. Security execution is owner-initiated through dedicated endpoints, not a model-generated command or scheduled general-tool task.

## Modules and actual coverage

| Module | Working implementation | Limits |
| --- | --- | --- |
| Network auditing | Python TCP connects to the exact authorized IPv4 address and ports; reports open versus closed/filtered | Maximum eight ports, one-second connection timeout each. No discovery, CIDRs, banners, service exploit probes or high-rate scanning |
| Web application security | One GET to the exact authorized URL; checks CSP, MIME-sniffing protection, referrer policy, HSTS where relevant and contradictory credentialed CORS configuration | No redirects, crawler, browser scripts, injection payloads or authenticated browsing. TLS certificates remain verified |
| Secure code review | Bandit 1.8.6 on a read-only snapshot; rule, severity, confidence, CWE and remediation | Static Python patterns only. No project code/config is executed, and no guarantee of complete vulnerability detection |
| Authentication security | HTTPS transport and Secure/HttpOnly/SameSite cookie attribute inspection | No usernames/passwords submitted, no login attempts, credential stuffing, brute force, session-token harvesting or access-control exploit validation |
| Vulnerability assessment | Local requirements/package version-pinning checks, or web configuration checks | Dependency hygiene, **not a CVE/advisory scan**. No vulnerability database, exploitability validation or exhaustive assessment |
| Defensive malware triage | SHA-256, size, entropy and selected static behavior indicators | Never executes samples. Indicators are hypotheses, not a malware verdict. No antivirus signatures, unpacking, dynamic detonation or malware generation |
| Reverse engineering | Native `file`, printable string counts and `otool -hv` for recognized Mach-O files | Static format/header inspection only; no debugger, disassembly/decompiler workflow or sample execution |

Bandit is a free open-source AST analyzer ([documentation](https://bandit.readthedocs.io/en/latest/man/bandit.html)). The other inspectors use Python's standard library and native macOS file/Mach-O inspection tools. No paid services, containers, cloud scanning, or additional privileged daemons are introduced. Nmap, YARA, Ghidra and commercial scanners are not installed or claimed by this release.

## Process and permission architecture

- `backend/cyber.py`: fixed module registry, authentication grants, exact expiring scopes, snapshot limits, task lifecycle and report persistence/export.
- `backend/security_worker.py`: immutable fixed inspectors; accepts a validated specification from the service. No user command or executable argument is accepted by the API.
- `backend/control.py`: shared subprocess ownership, permission monitoring, bounded output/runtime and process-group termination; security processes use security/computer permissions independently of the coding toggle.
- `frontend/src/CyberCenter.jsx`: module switches, scoped run form, tasks, reports and export. Security state/reports poll every two seconds; shared task history polls every four seconds. This is polling, not streaming terminal output.
- `cyber_scopes` and `cyber_reports` are additive SQLite tables; existing conversations, memory, projects, task history and settings are preserved.

Each assessment snapshots regular non-hidden source files into a private temporary directory under `memory/cyber-inputs`. The worker gets read access to that snapshot, trusted interpreter/runtime paths, and its fixed worker file; writes are restricted to a private scratch directory. Symlinks are not copied. Directories exclude hidden folders and node_modules. Limits: 80 files, 2 MB/file, 10 MB total, two concurrent assessments, 60 seconds per worker and 1 MB managed output. Snapshots and scratch directories are removed after the run; original owner files remain untouched.

The macOS loader requires read-data access to the **literal root directory itself**. The final sandbox includes `(allow file-read-data (literal "/"))`, which is not recursive access to its descendants. Live boundary checks verified that reading KRAKEN's private database and opening a network connection were denied in the offline profile. An earlier broader read-rule proposal was rejected by automatic approval review and was not retained.

Offline workers have no network. Active workers are fixed trusted programs with one validated literal target IP and explicit ports. Because the macOS profile syntax supports localhost/port or wildcard/port, the sandbox restricts port access while the fixed worker enforces the exact remote IP and URL; this is not a kernel-enforced per-IP firewall for arbitrary programs. Do not treat the sandbox as protection from malicious software already running as the macOS owner.

General coding processes retain their existing network-denied sandbox. Aider can reach only the authenticated inference gateway, which rejects administrative and non-inference routes. Generic tools and scheduled tasks cannot invoke `cyber.*` jobs. Private snapshots and the security database remain outside coding-tool roots. The legacy `security.audit` heuristic remains available only when the authenticated code-review module is enabled, a password is configured, and its separately configured legacy local-path scope allows the file.

These controls gate tools and network/process access. They do **not** semantically classify every program an owner can write or every local source inspection; that would conflict with general-purpose coding. Existing public research GET tools remain governed by the Internet toggle. Disabled modules cannot be invoked through a generic command interface, and arbitrary coding processes are not granted the active workers' network privileges.

## Emergency stop and revocation

Emergency stop is independent of inference. It disables the master permissions and all seven module switches, cancels queued/running tasks and pending schedules, and kills registered subprocess groups (including analyzer children). It stays latched across restart. Manual reset leaves permissions and modules disabled.

Module disable or scope deletion cancels matching assessments. Logout and expiry invalidate the live authentication grant; running workers detect revocation and are terminated. Generic locks and permission switches continue to revoke existing work. Process creation is protected against cancellation races so that an in-flight spawn cannot leave an unregistered child. No scope authorizes KRAKEN/Ollama control ports 8765, 8766 or 11434. Link-local/metadata, multicast, unspecified and reserved IP targets are blocked. DNS names, IPv6, CIDRs and wildcard target scopes are not supported in this release.

The controller cannot undo completed requests, stop user-owned external processes, or guarantee emergency responsiveness if the OS/backend is unresponsive. Only processes owned by KRAKEN are terminated.

## Reports and evidence

Reports contain the module, authorized scope and statement, timestamps, bounded observations, findings, severity, confidence, available CWE, remediation, input filenames/hashes and an evidence SHA-256 covering the observations, input manifest and findings. This is a reproducibility/integrity fingerprint, not a signed forensic chain of custody or a CVSS score.

No source excerpts, HTTP bodies, cookie names/values or credentials are retained by the new inspectors. Only cookie attribute observations are stored. Original samples are never executed or automatically uploaded. Reports live in the local SQLite database and are available through authenticated JSON export. They may contain project paths and target metadata; protect the Mac account and exported evidence appropriately. The new report list shows the latest 50 reports, while stored reports remain accessible by their IDs.

## Verified and unavailable

`scripts/cyber-check.py` creates a separate temporary application database and random test password, local file fixtures and an owned localhost HTTP service. It exercises all seven real macOS sandbox workers, module switches, scope creation, reports/export, authenticated reload, mobile layout and emergency termination during a real HTTP assessment. It stops only its own test servers and removes its fixtures; production passwords and targets are not changed. Evidence is recorded in `logs/cyber-validation.json` and screenshots under `logs/cyber-center-*.png`.

```sh
./scripts/test.sh
.venv/bin/python scripts/cyber-check.py
```

No public or third-party target was assessed during development. All seven modules were verified within the bounded coverage described above; HTTPS certificate failure handling is implemented but the live fixture uses HTTP, and public-target behavior is not claimed verified. The test suite also covers disabled capabilities, owner authentication, expired/revoked scope, unsafe target rejection, private snapshots, secret-free evidence and managed security process termination after emergency/module/scope/logout revocation.

Unrestricted attack execution, exploit payload runners, credential theft, persistence, malware authoring and malware execution are intentionally unavailable, including behind owner toggles. Advanced education and legitimate exploit investigation can use scoped code analysis and the owner's independent isolated lab, but this release does not claim to automate those broader workflows.
