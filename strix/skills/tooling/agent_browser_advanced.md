---
name: agent_browser_advanced
description: agent-browser advanced reference — tabs, parallel sessions, network mocking, video, iframes, dialogs, recovery, troubleshooting, global flags, React/Web-Vitals. Load on demand via load_skill when the core skill isn't enough.
---


# agent-browser — advanced reference

Load-on-demand companion to the always-loaded `agent_browser` core skill.
Everything here is for when the core loop (snapshot -> ref -> act) isn't enough.

### Handle multiple pages via tabs

```bash
agent-browser tab                      # list open tabs (with stable tabId)
agent-browser tab new https://docs...  # open a new tab (and switch to it)
agent-browser tab 2                    # switch to tab 2
agent-browser tab close 2              # close tab 2
```

Stable `tabId`s mean `tab 2` points at the same tab across commands even
when other tabs open or close. After switching, refs from a prior snapshot
on a different tab no longer apply — re-snapshot.

### Run multiple browsers in parallel

Each `--session <name>` is an isolated browser with its own cookies, tabs,
and refs. Useful for testing multi-user flows or parallel scraping:

```bash
agent-browser --session a open https://app.example.com
agent-browser --session b open https://app.example.com
agent-browser --session a fill @e1 "alice@test.com"
agent-browser --session b fill @e1 "bob@test.com"
```

`AGENT_BROWSER_SESSION=myapp` sets the default session for the current
shell.

Use a session named after yourself for your own work — that's what keeps a
concurrent agent from navigating the page out from under you. Every session is a
separate Chromium though, so hold one at a time rather than a collection, and
close each one when its flow is finished:

```bash
agent-browser --session a close
agent-browser --session b close
```

### Mock network requests

```bash
agent-browser network route "**/api/users" --body '{"users":[]}'   # stub a response
agent-browser network route "**/analytics" --abort                 # block entirely
agent-browser network requests                                     # inspect what fired
agent-browser network har start                                    # record all traffic
# ... perform actions ...
agent-browser network har stop /tmp/trace.har
```

### Record a video of the workflow

```bash
agent-browser record start demo.webm
agent-browser open https://example.com
agent-browser snapshot -i
agent-browser click @e3
agent-browser record stop
```

See [references/video-recording.md](references/video-recording.md) for
codec options, GIF export, and more.

### Iframes

Iframes are auto-inlined in the snapshot — their refs work transparently:

```bash
agent-browser snapshot -i
# @e3 [Iframe] "payment-frame"
#   @e4 [input] "Card number"
#   @e5 [button] "Pay"

agent-browser fill @e4 "4111111111111111"
agent-browser click @e5
```

To scope a snapshot to an iframe (for focus or deep nesting):

```bash
agent-browser frame @e3      # switch context to the iframe
agent-browser snapshot -i
agent-browser frame main     # back to main frame
```

### Dialogs

`alert` and `beforeunload` are auto-accepted so agents never block. For
`confirm` and `prompt`:

```bash
agent-browser dialog status          # is there a pending dialog?
agent-browser dialog accept           # accept
agent-browser dialog accept "text"    # accept with prompt input
agent-browser dialog dismiss          # cancel
```

## Readiness & recovery

The first `agent-browser open` in a session launches the headless-Chrome
daemon; later commands reuse it. A daemon left idle for 3 minutes shuts itself
down to free memory for the other agents, so an `open` after a long gap is a
fresh browser rather than a resumed one — expect to re-navigate, and re-`state
load` if you were logged in. Distinguish the failure modes and react differently
— do **not** blindly re-run the same failing command in a loop:

- **Daemon / connection failure** (`Failed to connect`, `connection refused`,
  socket missing, `browser not running`): the daemon isn't up or has died. Run
  `agent-browser doctor` (add `--fix` if it reports repairable problems), then
  re-open the page. Retrying the original command unchanged will keep failing.
- **Malformed command** (`Unknown command`, `Ref not found`, bad flag): fix the
  command itself — re-snapshot for fresh refs, or correct the syntax.

Invoke `agent-browser` directly through `exec_command`; there is no need to wrap
it in an extra `sh -c "..."` / `bash -lc "..."` layer, which only adds shell
quoting and startup-file pitfalls.

## Diagnosing install issues

If a command fails unexpectedly (`Unknown command`, `Failed to connect`,
stale daemons, version mismatches after `upgrade`, missing Chrome, etc.)
run `doctor` before anything else:

```bash
agent-browser doctor                     # full diagnosis (env, Chrome, daemons, config, providers, network, launch test)
agent-browser doctor --offline --quick   # fast, local-only
agent-browser doctor --fix               # also run destructive repairs (reinstall Chrome, purge old state, ...)
agent-browser doctor --json              # structured output for programmatic consumption
```

`doctor` auto-cleans stale socket/pid/version sidecar files on every run.
Destructive actions require `--fix`. Exit code is `0` if all checks pass
(warnings OK), `1` if any fail.

## Troubleshooting

**"Ref not found" / "Element not found: @eN"**
Page changed since the snapshot. Run `agent-browser snapshot -i` again,
then use the new refs.

**Element exists in the DOM but not in the snapshot**
It's probably off-screen or not yet rendered. Try:

```bash
agent-browser scroll down 1000
agent-browser snapshot -i
# or
agent-browser wait --text "..."
agent-browser snapshot -i
```

**Click does nothing / overlay swallows the click**
Some modals and cookie banners block other clicks. Snapshot, find the
dismiss/close button, click it, then re-snapshot.

**Fill / type doesn't work**
Some custom input components intercept key events. Try:

```bash
agent-browser focus @e1
agent-browser keyboard inserttext "text"    # bypasses key events
# or
agent-browser keyboard type "text"          # raw keystrokes, no selector
```

**Page needs JS you can't get right in one shot**
Use `eval --stdin` with a heredoc instead of inline:

```bash
cat <<'EOF' | agent-browser eval --stdin
// Complex script with quotes, backticks, whatever
document.querySelectorAll('[data-id]').length
EOF
```

**Cross-origin iframe not accessible**
Cross-origin iframes that block accessibility tree access are silently
skipped. Use `frame "#iframe"` to switch into them explicitly if the
parent opts in, otherwise the iframe's contents aren't available via
snapshot — fall back to `eval` in the iframe's origin or use the
`--headers` flag to satisfy CORS.

**Authentication expires mid-workflow**
Use `--session-name <name>` or `state save`/`state load` so your session
survives browser restarts. See [references/session-management.md](references/session-management.md)
and [references/authentication.md](references/authentication.md).

## Global flags worth knowing

```bash
--session <name>        # isolated browser session
--json                  # JSON output (for machine parsing)
--headed                # show the window (default is headless)
--auto-connect          # connect to an already-running Chrome
--cdp <port>            # connect to a specific CDP port
--profile <name|path>   # use a Chrome profile (login state survives)
--headers <json>        # HTTP headers scoped to the URL's origin
--proxy <url>           # proxy server
--state <path>          # load saved auth state from JSON
--session-name <name>   # auto-save/restore session state by name
```

## React / Web Vitals (built-in, any React app)

agent-browser ships with first-class React introspection. Works on any
React app — Next.js, Remix, Vite+React, CRA, TanStack Start, React Native
Web, etc. The `react …` commands require the React DevTools hook to be
installed at launch via `--enable react-devtools`:

```bash
agent-browser open --enable react-devtools http://localhost:3000
agent-browser react tree                         # component tree
agent-browser react inspect <fiberId>            # props, hooks, state, source
agent-browser react renders start                # begin re-render recording
agent-browser react renders stop                 # print render profile
agent-browser react suspense [--only-dynamic]    # Suspense boundaries + classifier
agent-browser vitals [url]                       # LCP/CLS/TTFB/FCP/INP + hydration
agent-browser pushstate <url>                    # SPA navigation (auto-detects Next router)
```

Without `--enable react-devtools`, the `react …` commands error. `vitals`
and `pushstate` work on any site regardless of framework.

## Full reference

Everything covered here plus the complete command/flag/env listing:

```bash
agent-browser skills get core --full
```

That pulls in:

- `references/commands.md` — every command, flag, alias
- `references/snapshot-refs.md` — deep dive on the snapshot + ref model
- `references/authentication.md` — auth vault, credential handling
- `references/trust-boundaries.md` — safety rules for driving a real browser
- `references/session-management.md` — persistence, multi-session workflows
- `references/profiling.md` — Chrome DevTools tracing and profiling
- `references/video-recording.md` — video capture options
- `references/proxy-support.md` — proxy configuration
- `templates/*` — starter shell scripts for auth, capture, form automation
