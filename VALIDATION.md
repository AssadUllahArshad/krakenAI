# Validation — November 17, 2026

Status: **real local inference, React chat, model tool calling, and sandboxed Aider edits verified**. This updates the November 16 record, when no model was installed.

## Cybersecurity upgrade — November 17, 2026

The existing application now includes the Cybersecurity Control Center and seven backend-enforced modules. **92 automated tests passed in 51.56 seconds**, including the four existing calculator tests. The production React build passed.

Live security QA used a separate temporary application/database, random test password and owned localhost service. No public targets were tested, and production passwords, projects and target scope were not modified.

| Module | Verified actual result |
| --- | --- |
| Secure code review | Bandit inspected a private Python snapshot, found B307 and hardcoded-password patterns, and excluded the sample secret from reports |
| Defensive malware triage | File hash, entropy and static behavior indicators produced; sample was not executed |
| Reverse engineering | Native file/Mach-O header inspection completed on an owned copy of `/usr/bin/true` |
| Vulnerability assessment | Unpinned dependency finding from a local requirements fixture; no CVE assessment claimed |
| Network auditing | The explicitly scoped localhost TCP service was reported reachable |
| Web security | One scoped GET produced missing-header observations; no redirects or exploit traffic |
| Authentication security | One scoped GET produced cookie-attribute/transport findings without storing cookie values |
| Emergency stop | Real running security worker terminated in approximately **0.10 seconds**; all module switches reset OFF and subsequent assessment denied with HTTP 423 |
| Dashboard | Owner login, seven module switches, scope creation, assessment run, reports/export, authenticated page reload and mobile layout verified; no JavaScript errors |
| Isolation | Offline profile denied private database reads and network access; readonly sample snapshots and per-task scratch enforced |
| Process lifecycle | Module/scope/logout revocation and emergency stop tested with real child processes; spawn cancellation and duplicate-signal races covered |

The first live worker failed in macOS's dynamic loader. OS logs identified a literal root-directory data read requirement. Automatic approval review rejected an initially broader read proposal. The final narrower rule grants `file-read-data` only for the root directory itself, not descendant files; private-file and network-denial checks passed. No unrestricted root-read rule was added to the new profile.

The security modules default OFF and require an owner password and matching expiring scope. Existing master switch preferences are preserved. The legacy static audit additionally respects the code-review module gate. A valid owner session now survives browser reload; no password requirement was removed.

Production is running after this upgrade as **PID 62399** on loopback ports **8765 and 8766**. HTTP 200, the Cybersecurity Control Center, all seven modules OFF, password-required module enable, preserved existing master permissions and an unchanged password state were verified. A real model connectivity reply completed in 11.69 seconds. Production evidence: `logs/cyber-production-verification.json`, `logs/cyber-production.png`, and `logs/startup-20261117T091925891391Z.log`. No production scope or sample reports were seeded. Configure an owner password in Settings before enabling security modules.

Evidence: `logs/cyber-validation.json`, `logs/cyber-qa-server.log`, `logs/cyber-center-desktop.png`, `logs/cyber-center-mobile.png`. The final fixture server log contained no traceback or unhandled cancellation warning. See **SECURITY_RESEARCH.md** for complete boundaries, reproduction steps and unavailable features.

Important limits: literal IPv4 scope only, eight TCP ports, single-request web review, no credential attacks, no exploit runner, no advisory/CVE feed, no debugger/decompiler, no dynamic malware execution or malware authoring. Generic coding remains network-isolated, but tool permissions cannot semantically classify every local program. Scoped workers are fixed trusted commands; there is no owner toggle for unrestricted attacks or malware generation.

## Connection-refused repair

The VS Code browser's `ERR_CONNECTION_REFUSED` was reproduced as **no listener on either port 8765 or 8766**. The earlier verification servers had deliberately been stopped after testing. The dashboard URL was correct; no active backend was available to accept the connection. There was no port conflict at the start of this repair.

Applied changes:

- `scripts/start.sh`: adds an optional `--background` mode; the existing foreground command still works.
- `scripts/start-background.py`: launches a detached process with stdin closed, captures complete stdout/stderr in a timestamped log, verifies HTTP health and dashboard responses, confirms that its own PID owns both loopback listeners, and records the PID/log path. It never terminates or replaces an existing listener.
- `backend/app.py`: keeps gateway startup logging at INFO; its previous WARNING configuration suppressed later Uvicorn startup messages for the main server as well.
- `tests/test_background_start.py`: tests listener ownership and ensures a failed launch cannot overwrite an existing PID record or terminate processes.
- README: documents background versus foreground operation and log locations.

Verification after repair: **58 tests passed in 6.61 seconds**, production dashboard build passed, and headless Chromium loaded HTTP 200, rendered Command center, navigated to AI workspace, and reported no JavaScript errors. A duplicate background launch exited 1 with a clear port-in-use message while the existing server stayed healthy.

**Server left running after repair: PID 59284, bound only to 127.0.0.1:8765 and 127.0.0.1:8766.** Complete successful startup log: `logs/startup-20261117T073430380236Z.log`; both servers reported `Application startup complete`. Screenshot: `logs/startup-browser-verified.png`; browser report: `logs/startup-browser-verification.json`. No project data was removed and no permissions, emergency-stop state, network restrictions, or unrelated processes were changed.

## Actual results

| Check | Result |
| --- | --- |
| Automated regression suite | **56 passed**, including the existing four calculator tests; no user calculator files changed |
| Production dashboard | React/Vite build succeeds; shell startup scripts pass syntax checks |
| Installed model | `kraken:latest`, Qwen3 4B GGUF Q4_K_M; local Ollama reports completion, thinking and tool capabilities |
| FastAPI → Ollama | Real reply: `KRAKEN connection verified.`; no adapter used in live checks |
| React → FastAPI → Ollama | Real reply: `Dashboard connection verified.`; browser round trip 3.7 seconds in the recorded run |
| Real conversation persistence | Browser reload restores the reply; reply remains in SQLite after backend restart |
| Model tool calling | Model invoked `files.list` against `workspace`; task completed and its result was returned to the model |
| Final Aider output | Successful edit with no remote-metadata, release-note, or browser-launch errors |
| Aider through KRAKEN | Aider 0.86.2 executed through the authenticated local inference gateway and created `greeting.py` in a new validation project |
| Generated code execution | Sandboxed verification asserted `greet('Hamzi') == 'Hello, Hamzi!'`, exited 0 and printed `Generated Aider code verified` |
| Existing coding tests | All four tests in `projects/test-app/test_calculator.py` pass |
| Dashboard permissions | All six available switches changed actual backend state; backend tests deny every tool when each required capability is off |
| Face recognition | Switch disabled; backend returns 501 when enabling is requested |
| Stop reply | Real pending inference request cancelled; agent remains enabled |
| Emergency during inference | Dashboard stop responded in **0.12 seconds** during a real pending inference request; all permissions revoked and new tools denied with HTTP 423 |
| Emergency persistence/processes | Regression tests verify persistent latch, manual reset without re-enabling tools, pending schedule cancellation and termination of a real owned child process |
| Browser QA | No JavaScript errors; 390 px mobile layout has no horizontal overflow |
| Disconnect recovery | Simulated failed status request produces a disconnected banner; reconnect succeeds without a page reload |
| Execution isolation | Live sandbox denies database reads and direct Ollama/network access; corrected Aider network profile parses and accepts the CLI |
| Startup and shutdown | Both listeners start and close cleanly; duplicate launch is rejected without stopping the running instance; an occupied gateway releases the dashboard reservation before application startup |

Timing results are examples, not performance guarantees. Baseline backend chat took 27.6 seconds before the chat options were tuned. Later short replies took approximately 3.6–16.6 seconds. Long prompts and code generation remain slower on this CPU-only Mac.

## Fixes made

- Startup reserves both ports before importing database state and reports occupied ports clearly. Rebuilds stale frontend source/configuration automatically.
- Gateway startup is awaited; the secondary server does not capture the main server's signals. Application construction no longer marks another server's live tasks interrupted; recovery happens at startup.
- Normal chat omits tools when none are enabled, uses a 4,096-token context, disables Qwen thinking for ordinary replies, and returns model/timing metadata.
- Tool-specific schemas replace the generic schema. The live model initially requested `path: "."`; the workspace boundary denied it. Clear schemas and concrete path examples fixed the tested workflow without weakening that boundary.
- Duplicate replies in one conversation receive HTTP 409. Reply cancellation propagates to any awaited child tool. Connection failures, timeouts, invalid responses and Ollama model errors receive specific actionable errors.
- Empty replies are rejected; nonzero subprocess exits are recorded as failed tasks.
- Corrected the macOS Aider sandbox rule to `localhost:8766`; this OS rejected the former numeric-host spelling.
- Aider uses explicit local model metadata, bundled LiteLLM metadata, no release-note/browser prompts and bounded inference context/output. Temporary metadata files are cleaned up.
- Dashboard adds paused/stop/disconnected guidance, one-click agent enable, stop-reply control, timing, draft retention, tool argument templates, missing-permission guidance, prefilled settings, larger switches and visible keyboard focus.

## Evidence and reproduction

Actual live reports are stored in `logs/ai-validation.json` and `logs/browser-ai-validation.json`. Screenshots: `logs/dashboard-desktop.png`, `logs/dashboard-chat.png`, and `logs/dashboard-mobile.png`. Generated validation code lives in the separate project identified in `logs/ai-validation.json`. Existing calculator source, tests, model configuration, and user conversation history were preserved.

```sh
./scripts/test.sh
# With the local server running, no active owner tasks, and password not configured:
.venv/bin/python scripts/ai-check.py
.venv/bin/python scripts/browser-ai-check.py
.venv/bin/python scripts/smoke.py
.venv/bin/python scripts/isolation-check.py
# With both KRAKEN ports free:
.venv/bin/python scripts/lifecycle-check.py
```

The live AI/browser checks use separate validation conversations and restore initial permissions. Browser emergency testing manually resets only the latch it creates. `ai-check.py` creates a new validation project and retains its generated files for review. Live tests intentionally toggle controls: do not run them during owner tasks. Development adapter tests are clearly separate from these real-model checks. Earlier feature-validation servers were stopped after testing; the connection-refused repair above leaves the application running in background mode. Initial permissions were restored (all capabilities disabled, emergency latch reset).

## Remaining limitations

- Simple tested tasks do not establish model reliability for complex applications. The 4,096-token context is intentional for this Intel Mac; large files/projects may need a different configuration or model.
- Chat responses are returned after completion, not streamed token by token. Status and activity poll every four seconds.
- Stopping a reply closes KRAKEN's request and cancels tracked work. External Ollama remains running; it may briefly continue internal computation. This is not a hardware kill switch and cannot undo completed operations.
- Face verification, arbitrary macOS desktop application control, unrestricted network security scanning, malware execution, authenticated interactive browser automation, OCR and video transcription remain unavailable. Local vision requires a separately installed vision model.
- Browser research remains read-only, with JavaScript disabled and requests checked against public-address restrictions. Security review is explicitly scoped static heuristic analysis.
- The execution sandbox relies on legacy macOS `sandbox-exec`. It is verified here but is not portable to other operating systems; execution fails closed elsewhere.
- Fresh authentication is required for changes after ten minutes when an owner password is configured. Live scripts assume passwordless local-owner mode; they do not bypass password authentication.
