(() => {
  "use strict";

  const form = document.getElementById("scan-form");
  const scanBtn = document.getElementById("scan-btn");
  const connDot = document.getElementById("conn-dot");
  const connText = document.getElementById("conn-text");
  const errorBanner = document.getElementById("error-banner");
  const gnewsBanner = document.getElementById("gnews-banner");
  const reportPanel = document.getElementById("report-panel");
  const reportBody = document.getElementById("report-body");
  const downloadMd = document.getElementById("download-md");
  const downloadPdf = document.getElementById("download-pdf");

  const moduleRows = {};
  document.querySelectorAll(".module-row").forEach((row) => {
    moduleRows[row.dataset.module] = {
      row,
      status: row.querySelector(".module-status"),
      summary: row.querySelector(".module-summary"),
      startedAt: null,
      timer: null,
    };
  });

  const stats = {};
  document.querySelectorAll(".stat-tile").forEach((tile) => {
    stats[tile.dataset.stat] = tile.querySelector(".stat-value");
  });

  function setConn(state, label) {
    connDot.className = "dot " + state;
    connText.textContent = label;
  }

  function showError(message) {
    errorBanner.textContent = message;
    errorBanner.classList.remove("hidden");
  }

  function clearError() {
    errorBanner.classList.add("hidden");
  }

  function resetUI() {
    clearError();
    reportPanel.classList.add("hidden");
    reportBody.innerHTML = "";
    Object.values(stats).forEach((el) => (el.textContent = "—"));
    Object.values(moduleRows).forEach((m) => {
      m.row.className = "module-row";
      m.summary.textContent = "";
      stopTimer(m);
    });
  }

  function startTimer(mod) {
    mod.startedAt = Date.now();
    mod.timer = setInterval(() => {
      const secs = Math.floor((Date.now() - mod.startedAt) / 1000);
      mod.summary.textContent = `running… ${secs}s`;
    }, 1000);
  }

  function stopTimer(mod) {
    if (mod.timer) {
      clearInterval(mod.timer);
      mod.timer = null;
    }
  }

  const SUMMARY_FORMATTERS = {
    org: (d) => `${d.total_related_domains} related domains, ${d.total_subdomains} subdomains`,
    recon: (d) => `${d.total_subdomains} subdomains, ${d.total_open_ports} open ports`,
    threat: (d) => `${d.total_leaks} leaks, ${d.total_credentials} exposed creds`,
    typosquat: (d) => `${d.total_active} active of ${d.total_generated} generated`,
    news: (d) => `${d.total_articles} articles (${d.days_monitored}d window)`,
  };

  function applyStats(moduleName, data) {
    if (moduleName === "recon") {
      stats.subdomains.textContent = data.total_subdomains;
      stats.ports.textContent = data.total_open_ports;
    } else if (moduleName === "org" && stats.subdomains.textContent === "—") {
      stats.subdomains.textContent = data.total_subdomains;
    } else if (moduleName === "threat") {
      stats.leaks.textContent = data.total_leaks + data.total_credentials;
    } else if (moduleName === "typosquat") {
      stats.typosquats.textContent = data.total_active;
    } else if (moduleName === "news") {
      stats.news.textContent = data.total_articles;
    }
  }

  function handleEvent(ev) {
    switch (ev.type) {
      case "scan_started":
        resetUI();
        break;

      case "module_started": {
        const mod = moduleRows[ev.module];
        if (!mod) break;
        mod.row.className = "module-row running";
        startTimer(mod);
        break;
      }

      case "module_completed": {
        const mod = moduleRows[ev.module];
        if (!mod) break;
        stopTimer(mod);
        mod.row.className = "module-row done";
        const fmt = SUMMARY_FORMATTERS[ev.module];
        mod.summary.textContent = fmt && ev.data ? fmt(ev.data) : "done";
        if (ev.data) applyStats(ev.module, ev.data);
        break;
      }

      case "module_error": {
        const mod = moduleRows[ev.module];
        if (!mod) break;
        stopTimer(mod);
        mod.row.className = "module-row error";
        mod.summary.textContent = ev.message || "failed";
        break;
      }

      case "scan_completed":
        setConn("connected", "scan complete");
        if (ev.data && ev.data.failed_modules && ev.data.failed_modules.length) {
          showError(
            `Scan finished with issues in: ${ev.data.failed_modules.join(", ")}. Other modules still ran.`
          );
        }
        scanBtn.disabled = false;
        break;

      case "report_ready":
        loadReport(ev.data.report_id, ev.data.has_pdf);
        break;

      case "scan_rejected":
        showError(ev.message || "scan rejected");
        scanBtn.disabled = false;
        break;

      case "scan_failed":
        showError(ev.message || "scan failed");
        scanBtn.disabled = false;
        break;
    }
  }

  async function loadReport(reportId, hasPdf) {
    reportPanel.classList.remove("hidden");
    downloadMd.href = `/api/report/${reportId}/download?fmt=md`;
    if (hasPdf) {
      downloadPdf.href = `/api/report/${reportId}/download?fmt=pdf`;
      downloadPdf.classList.remove("hidden");
    } else {
      downloadPdf.classList.add("hidden");
    }
    try {
      const resp = await fetch(`/api/report/${reportId}/html`);
      reportBody.innerHTML = await resp.text();
    } catch (e) {
      reportBody.textContent = "Failed to load report preview; use the download links above.";
    }
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const domain = document.getElementById("domain").value.trim();
    if (!domain) return;
    const depth = parseInt(document.getElementById("depth").value, 10);
    const modules = Array.from(
      form.querySelectorAll('input[name="modules"]:checked')
    ).map((el) => el.value);

    resetUI();
    scanBtn.disabled = true;
    setConn("connected", "connecting…");

    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/ws`);

    ws.onopen = () => {
      setConn("connected", "scanning…");
      ws.send(JSON.stringify({ domain, depth, modules }));
    };

    ws.onmessage = (msg) => {
      try {
        handleEvent(JSON.parse(msg.data));
      } catch (err) {
        showError("Received an unreadable message from the server.");
      }
    };

    ws.onerror = () => {
      setConn("disconnected", "connection error");
    };

    ws.onclose = () => {
      setConn("disconnected", "idle");
      scanBtn.disabled = false;
    };
  });

  fetch("/api/health")
    .then((r) => r.json())
    .then((data) => {
      setConn("disconnected", "idle");
      if (!data.gnews_available) {
        gnewsBanner.classList.remove("hidden");
      }
    })
    .catch(() => setConn("disconnected", "server unreachable"));
})();
