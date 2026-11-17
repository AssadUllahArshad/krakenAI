# KRAKEN AI

An owner-controlled, local personal agent for Hamzi. Python 3.9+, FastAPI, React/Vite, SQLite, and an existing Ollama installation. Designed for a 16 GB Intel Mac. No subscriptions, cloud keys, Docker, or remote hosting.

## Start

The current checkout already has dependencies and a production dashboard build. Launch:

```sh
cd /Users/ali/KrakenAI
./scripts/start.sh --background
```

This leaves KRAKEN running independently of the terminal, verifies its dashboard, and prints its PID and full startup-log path. The current PID and log path are saved in `logs/server.pid` and `logs/server-log.txt`. Use `./scripts/start.sh` without the option for foreground operation (closing that process stops the dashboard). Background mode does not install login autostart or restart the agent after emergency stop. A duplicate launch never stops the existing server.

Open **http://127.0.0.1:8765** and click **Enable AI agent** if it is paused. The installed `kraken:latest` model is recognized when the configured name is `kraken`. The normal chat path and sandboxed Aider integration have been verified against this model; see `VALIDATION.md` for actual results.

Ollama must be running separately. If the dashboard reports it unavailable, start the existing Ollama application/service, or run `ollama serve` if no service is running. KRAKEN does not download or replace your model. Settings accepts other installed local models; agent actions require model tool-call support.

Startup rebuilds the dashboard if its source/configuration is newer than the existing build. It reserves both loopback ports before opening the database. A second launch or an occupied inference port exits with a clear message, releases reserved ports, and leaves the existing server alone. For frontend development, run `npm --prefix frontend run dev` alongside the backend. Listeners remain on loopback; do not expose this application through a public proxy.

For a fresh checkout or dependency repair, run `./scripts/install.sh` once. To import a different GGUF, use `./scripts/import-model.sh /absolute/path/to/model.gguf`; this explicitly replaces the Ollama model named `kraken`, so it is unnecessary for the currently working installation.

## Everyday use

- **AI workspace:** enter a message, press Enter to send, or Shift + Enter for a new line. Paused, unavailable-model, and disconnected states explain what to do. Failed requests keep your draft. A completed reply shows its elapsed time.
- **Stop reply:** cancels the current conversation request without turning off the agent or unrelated tools. **Emergency stop** locks all capabilities and cancels tracked work, independently of inference.
- **Tools & projects:** selecting a tool loads relevant example arguments. The runner lists missing permissions and stays disabled until they are enabled. Execution results with nonzero exit codes are recorded as failures.
- **Settings:** choose an installed model, configure an optional vision model, set an owner password, or edit explicit security scope. Current settings are loaded into the form, including authorized paths.
- **Reconnect:** if the backend goes offline, the dashboard keeps your draft and offers a retry. A session that needs reauthentication returns to the owner login.

Normal dashboard chat uses the `main` conversation. For isolated diagnostics, `/?conversation=your-test-name` selects a separate persistent conversation without clearing the main history.

For the optional browser tool:

```sh
.venv/bin/playwright install chromium
```

Existing `aider`, `ffmpeg`, `ffprobe`, and macOS `sandbox-exec` are detected at runtime. No webcam permission is requested.

## Cybersecurity Control Center

The existing dashboard now includes **Cybersecurity**, with seven independent modules that default to OFF. Configure an owner password and sign in, enable the required master permissions, then authorize an explicit expiring target scope before running assessments. This upgrade does not set or change your password or enable modules for you.

Working capabilities include bounded TCP reachability, web-header and cookie-attribute review, Bandit Python analysis, dependency pinning checks, static malware triage and Mach-O header inspection. Reports include classified findings, confidence, remediation, observed evidence and hashes, with JSON export. All security workers are managed by the existing emergency-stop controller.

See [SECURITY_RESEARCH.md](SECURITY_RESEARCH.md) for exact coverage, scope limits, sandbox boundaries and unavailable features. The new modules do not provide an exploit shell, credential attacks or a malware-generation toggle.

## What works

- Chat via local Ollama (4,096-token context, thinking disabled for ordinary replies) with persistent conversations and a bounded tool-calling loop (8 inference steps); verified tool results are returned to the model.
- SQLite memory notes, preferences, search, deletion, conversation deletion, task results, schedules, settings, and an activity log.
- Workspace-confined file listing, reading, writing, PDF/text/transcript reading, Python/JavaScript execution, Git status/diff, and existing Aider invocation.
- Public HTTP(S) webpage text extraction, configurable DuckDuckGo/Wikipedia search, downloads limited to 5 MB, and read-only Playwright extraction.
- Optional local vision-model image inspection, FFprobe metadata, and FFmpeg frame extraction (up to 20 frames). Vision is unavailable until an installed vision model is configured.
- Static defensive code review for explicitly authorized local paths; reports line numbers and heuristic findings without exposing matched secrets.
- Persistent one-time schedules with permission checks when queued and executed. Overdue jobs run on restart if still authorized; jobs dispatched during a crash are not replayed automatically.
- Owner password setup, PBKDF2-HMAC-SHA256 password hashes (600,000 iterations) with random salts, HTTP-only SameSite cookies, 1-hour sessions, login rate limiting, and fresh authentication required after 10 minutes for changes. Emergency stop remains usable throughout the live session.
- Functional permissions, lock-all, cut-network, and a latched emergency stop independent of model inference.

## Owner controls

The agent starts enabled, with all tool capabilities disabled. Enable only the capabilities you want in Command center. Tools check backend permissions regardless of how they are invoked. The agent toggle gates inference and every tool. Computer control gates accessible workspace files, not arbitrary macOS desktop control. Coding plus computer control is needed for editing and subprocesses. Security review additionally needs Security research, the code-review module, owner password authentication and an explicitly saved scope. New assessments use Cybersecurity scope; the legacy heuristic also retains its legacy path scope. Automation gates scheduling and dispatch.

Turning off any master capability cancels all currently tracked work as a conservative revocation policy. Lock-all disables every capability. Cut-network disables public web tools and cancels active tasks; local inference remains local. Emergency stop disables all capabilities, cancels tasks and pending schedules, kills tracked subprocess groups, and persists across restart. Manually reset it, then enable capabilities individually. Completed operations are not undone. External user-owned Ollama processes are never killed. Cancelling an HTTP request does not guarantee that Ollama has immediately stopped its internal computation.

The emergency endpoint is a direct backend operation, not an LLM instruction. Its responsiveness still depends on the backend and operating system; this is not a hardware kill switch. If the backend is unresponsive, terminate its process from Terminal or Activity Monitor.

## Execution isolation

Code and Aider run only inside macOS `sandbox-exec`; execution fails closed if the sandbox is unavailable or rejects the profile. They may read OS/runtime libraries and their selected project, and write their project plus a dedicated scratch folder. They receive a minimal environment without inherited API credentials. Python/JavaScript have no network access. Project code can modify any file inside its selected project; keep sensitive credentials outside projects.

Aider receives access only to an authenticated inference gateway at `127.0.0.1:8766`, started by `scripts/start.sh`. The gateway forwards chat/generation/model-inspection requests for the selected model and rejects model download/push/admin operations. It does not expose the dashboard API. Both servers share permission state. No arbitrary terminal endpoint is exposed. Git mutation can be performed by project code within this sandbox; direct Git tools provide status/diff only. Aider auto-commits, auto-tests, auto-lint, update checks, release-note browser prompts, URL detection and analytics are disabled. LiteLLM uses its bundled model metadata instead of fetching it online. Existing Git ignore updates are disabled; Aider may initialize a new repository and its ignore file in a previously empty project. The gateway bounds Aider to a 4,096-token context and 2,048 generated tokens, with thinking disabled for this Intel Mac.

This is a local application boundary, not protection from malicious software already running as your macOS user. `sandbox-exec` is a legacy macOS facility and must be verified on your OS. No claim is made that general-purpose code can be classified as defensive or offensive: isolation blocks network access to targets, while the dedicated security tool is a static, scoped review. Do not store live secrets or unrelated sensitive files in agent projects.

Public HTTP requests validate DNS results, pin an approved public IP, preserve TLS hostname verification, and revalidate redirects. Private/loopback/link-local destinations and non-web ports are blocked. Browser requests pass through the same checked gateway; JavaScript, service workers and subresources are disabled. This release offers document extraction, not interactive logged-in browser automation. It does not circumvent authentication or access restrictions.

## Tests

```sh
./scripts/test.sh
```

Tests cover disabled capabilities for every tool, path traversal/symlinks, emergency-stop persistence and reset, real child-process termination, authentication, memory, conversation adapter persistence, scheduling gates, static-audit scope, settings validation and interrupted-task recovery. Model adapter tests are **not** evidence that a real local model works. See `VALIDATION.md` for actual environment results and outstanding acceptance criteria.

## Source map

- `backend/app.py`: local API, authentication, agent loop, reply cancellation, schedules, lifecycle.
- `scripts/serve.py`: reserves both loopback ports before importing application state.
- `backend/cyber.py` and `backend/security_worker.py`: authenticated scoped security modules and fixed sandbox inspectors.
- `backend/control.py`: permissions, persistent emergency latch, task/process ownership.
- `backend/tools.py`: file/coding, web/browser, multimedia, and scoped security tools.
- `backend/inference.py`: restricted gateway for sandboxed Aider.
- `backend/store.py`: SQLite storage and recovery.
- `frontend/src/`: responsive dashboard with real backend controls.
- `tests/`: automated backend integration tests.
- `scripts/`: installation, startup, tests, and local GGUF import.

Database: `memory/kraken.sqlite3` (WAL mode). Activity appears in the dashboard; server errors are printed by Uvicorn. Back up SQLite using its backup API or stop the application before copying the database and its WAL files. Prompts, notes and tool results may contain sensitive project content; review and delete them in the dashboard and keep this Mac account protected. Password hashes are stored in SQLite; sessions and gateway credentials exist only in process memory.

## Deliberately unavailable

Face recognition, webcam owner verification, arbitrary macOS application control, unrestricted network scanning, malware execution, unrestricted shell access, and interactive authenticated browser automation are not implemented. The face switch is disabled and the backend rejects attempts to enable it. Video transcription generation and OCR require additional local models and are not claimed; existing text transcripts can be read. Jobs are one-time tools, not a general workflow graph. Running tests/programs requires an explicit project entrypoint; npm install/build inside projects has no network. The installed Qwen3 4B model has passed simple chat, file-list tool calling and Aider-edit checks. These checks do not establish reliability for large coding projects; model quality and speed vary with prompt size and hardware.

Integration references: [Ollama API](https://docs.ollama.com/api) and [Aider with Ollama](https://aider.chat/docs/llms/ollama.html). The exact tested Python dependency set is in `requirements.lock.txt`; the installer uses it. Frontend versions are locked by `frontend/package-lock.json`.
# KRAKENAI
