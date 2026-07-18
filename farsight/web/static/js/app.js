(() => {
  "use strict";

  const form = document.getElementById("scan-form");
  const scanBtn = document.getElementById("scan-btn");
  const connDot = document.getElementById("conn-dot");
  const connText = document.getElementById("conn-text");
  const errorBanner = document.getElementById("error-banner");
  const gnewsBanner = document.getElementById("gnews-banner");
  const demoBanner = document.getElementById("demo-banner");
  const reportPanel = document.getElementById("report-panel");
  const reportBody = document.getElementById("report-body");
  const downloadMd = document.getElementById("download-md");
  const downloadPdf = document.getElementById("download-pdf");
  const graphContainer = document.getElementById("graph");
  const typosquatPanel = document.getElementById("typosquat-panel");
  const typosquatGrid = document.getElementById("typosquat-grid");
  const threatPanel = document.getElementById("threat-panel");
  const attackSurfacePanel = document.getElementById("attack-surface-panel");
  const cloudBadges = {
    aws: document.querySelector('[data-cloud="aws"]'),
    azure: document.querySelector('[data-cloud="azure"]'),
    gcp: document.querySelector('[data-cloud="gcp"]'),
  };
  const threatLists = {
    leaks: document.getElementById("threat-leaks"),
    dark_web: document.getElementById("threat-dark-web"),
    credentials: document.getElementById("threat-credentials"),
    intelx_phonebook: document.getElementById("threat-phonebook"),
  };

  let currentDomain = null;

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

  function createPaginatedTable(mountEl, { headers, rowRenderer, pageSize, emptyText }) {
    mountEl.innerHTML = "";
    const wrap = document.createElement("div");
    wrap.className = "paginated-table";

    const table = document.createElement("table");
    const thead = document.createElement("thead");
    const headRow = document.createElement("tr");
    headers.forEach((h) => {
      const th = document.createElement("th");
      th.textContent = h;
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    const tbody = document.createElement("tbody");
    table.appendChild(thead);
    table.appendChild(tbody);

    const pager = document.createElement("div");
    pager.className = "pager";
    const prevBtn = document.createElement("button");
    prevBtn.type = "button";
    prevBtn.className = "pager-btn";
    prevBtn.textContent = "‹ Prev";
    const pageLabel = document.createElement("span");
    pageLabel.className = "pager-label";
    const nextBtn = document.createElement("button");
    nextBtn.type = "button";
    nextBtn.className = "pager-btn";
    nextBtn.textContent = "Next ›";
    pager.appendChild(prevBtn);
    pager.appendChild(pageLabel);
    pager.appendChild(nextBtn);

    wrap.appendChild(table);
    wrap.appendChild(pager);
    mountEl.appendChild(wrap);

    let rows = [];
    let page = 0;
    const size = pageSize || 10;

    function renderPage() {
      tbody.innerHTML = "";
      const totalPages = Math.max(1, Math.ceil(rows.length / size));
      page = Math.min(page, totalPages - 1);

      if (!rows.length) {
        const tr = document.createElement("tr");
        const td = document.createElement("td");
        td.colSpan = headers.length;
        td.className = "pager-empty";
        td.textContent = emptyText || "No results.";
        tr.appendChild(td);
        tbody.appendChild(tr);
        pager.classList.add("hidden");
        return;
      }

      pager.classList.toggle("hidden", totalPages <= 1);
      const start = page * size;
      rows.slice(start, start + size).forEach((row) => {
        tbody.appendChild(rowRenderer(row));
      });
      pageLabel.textContent = `Page ${page + 1} of ${totalPages} (${rows.length} total)`;
      prevBtn.disabled = page === 0;
      nextBtn.disabled = page >= totalPages - 1;
    }

    prevBtn.addEventListener("click", () => {
      page = Math.max(0, page - 1);
      renderPage();
    });
    nextBtn.addEventListener("click", () => {
      page += 1;
      renderPage();
    });

    return {
      setRows(newRows) {
        rows = newRows || [];
        page = 0;
        renderPage();
      },
    };
  }

  function makeCell(text, className) {
    const td = document.createElement("td");
    if (className) td.className = className;
    td.textContent = text === undefined || text === null || text === "" ? "-" : text;
    return td;
  }

  function makeBadgeCell(type) {
    const td = document.createElement("td");
    if (!type) {
      td.textContent = "-";
      return td;
    }
    const badge = document.createElement("span");
    badge.className = `type-badge ${type.toLowerCase()}`;
    badge.textContent = type;
    td.appendChild(badge);
    return td;
  }

  const bucketsTable = createPaginatedTable(document.getElementById("buckets-table"), {
    headers: ["Bucket", "Type", "Files", "Matched Keyword"],
    pageSize: 10,
    emptyText: "No exposed storage buckets discovered.",
    rowRenderer: (b) => {
      const tr = document.createElement("tr");
      tr.appendChild(makeCell(b.bucket, "mono"));
      tr.appendChild(makeBadgeCell(b.type));
      tr.appendChild(makeCell(b.file_count));
      tr.appendChild(makeCell(b.matched_keyword));
      return tr;
    },
  });

  const asnsTable = createPaginatedTable(document.getElementById("asns-table"), {
    headers: ["ASN", "Holder", "Matched Keyword", "Source"],
    pageSize: 10,
    emptyText: "No ASNs discovered.",
    rowRenderer: (a) => {
      const tr = document.createElement("tr");
      tr.appendChild(makeCell(`AS${a.asn}`, "mono"));
      tr.appendChild(makeCell(a.ripestat_holder || a.description || a.name));
      tr.appendChild(makeCell(a.matched_keyword));
      tr.appendChild(makeCell(a.source));
      return tr;
    },
  });

  const netblocksTable = createPaginatedTable(document.getElementById("netblocks-table"), {
    headers: ["CIDR", "ASN", "Description", "Cloud"],
    pageSize: 10,
    emptyText: "No netblocks discovered.",
    rowRenderer: (n) => {
      const tr = document.createElement("tr");
      tr.appendChild(makeCell(n.cidr, "mono"));
      tr.appendChild(makeCell(n.asn ? `AS${n.asn}` : null, "mono"));
      tr.appendChild(makeCell(n.description));
      tr.appendChild(makeBadgeCell(n.cloud ? n.cloud.provider : null));
      return tr;
    },
  });

  function renderAttackSurfacePanel(data) {
    const cloud = data.cloud_summary || {};
    cloudBadges.aws.textContent = cloud.aws || 0;
    cloudBadges.azure.textContent = cloud.azure || 0;
    cloudBadges.gcp.textContent = cloud.gcp || 0;

    bucketsTable.setRows(data.exposed_buckets || []);
    asnsTable.setRows(data.asns || []);
    netblocksTable.setRows(data.netblocks || []);

    attackSurfacePanel.classList.remove("hidden");
  }

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
    typosquatPanel.classList.add("hidden");
    typosquatGrid.innerHTML = "";
    threatPanel.classList.add("hidden");
    Object.values(threatLists).forEach((el) => (el.innerHTML = ""));
    attackSurfacePanel.classList.add("hidden");
    bucketsTable.setRows([]);
    asnsTable.setRows([]);
    netblocksTable.setRows([]);
    Object.values(cloudBadges).forEach((el) => (el.textContent = "0"));
    Object.values(stats).forEach((el) => (el.textContent = "-"));
    Object.values(moduleRows).forEach((m) => {
      m.row.className = "module-row";
      m.summary.textContent = "";
      stopTimer(m);
    });
  }

  function riskClass(score) {
    if (score >= 70) return "high";
    if (score >= 40) return "medium";
    return "low";
  }

  function renderTyposquatPanel(data) {
    const active = (data.typosquats || [])
      .filter((t) => t.has_dns || t.has_mx || t.http_status)
      .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
      .slice(0, 12);

    typosquatGrid.innerHTML = "";
    if (!active.length) return;

    active.forEach((t) => {
      const card = document.createElement("div");
      card.className = "typosquat-card";

      const domainEl = document.createElement("div");
      domainEl.className = "typosquat-domain";
      domainEl.textContent = t.domain;

      const meta = document.createElement("div");
      meta.className = "typosquat-meta";

      const typeEl = document.createElement("span");
      typeEl.className = "typosquat-type";
      typeEl.textContent = t.type || "typosquat";

      const badge = document.createElement("span");
      badge.className = `risk-badge ${riskClass(t.risk_score || 0)}`;
      badge.textContent = `${t.risk_score || 0}`;

      meta.appendChild(typeEl);
      meta.appendChild(badge);
      card.appendChild(domainEl);
      card.appendChild(meta);
      typosquatGrid.appendChild(card);
    });

    typosquatPanel.classList.remove("hidden");
  }

  function makeThreatItem(titleText, metaText, badgeText) {
    const li = document.createElement("li");
    li.className = "threat-item";

    const title = document.createElement("span");
    title.className = "threat-item-title";
    title.textContent = titleText;
    li.appendChild(title);

    if (badgeText) {
      const badge = document.createElement("span");
      badge.className = `risk-badge ${riskLevelClass(badgeText)}`;
      badge.textContent = badgeText;
      li.appendChild(badge);
    }

    if (metaText) {
      const meta = document.createElement("span");
      meta.className = "threat-item-meta";
      meta.textContent = metaText;
      li.appendChild(meta);
    }

    return li;
  }

  function emptyThreatItem(text) {
    const li = document.createElement("li");
    li.className = "threat-item threat-item-empty";
    li.textContent = text;
    return li;
  }

  function riskLevelClass(level) {
    if (level === "critical") return "critical";
    if (level === "high") return "high";
    if (level === "low") return "low";
    return "medium";
  }

  function fillThreatList(listEl, items, emptyText, builder) {
    listEl.innerHTML = "";
    if (!items.length) {
      listEl.appendChild(emptyThreatItem(emptyText));
      return;
    }
    items.forEach((item) => listEl.appendChild(builder(item)));
  }

  function renderThreatPanel(data) {
    fillThreatList(
      threatLists.leaks,
      data.leaks || [],
      "No data leaks found.",
      (leak) =>
        makeThreatItem(
          leak.title || leak.details || leak.source || "Untitled",
          `${leak.source || "Unknown"} · ${leak.date || "Unknown"}`
        )
    );

    fillThreatList(
      threatLists.dark_web,
      data.dark_web || [],
      "No dark web mentions found.",
      (mention) =>
        makeThreatItem(
          mention.target || mention.title || mention.source || "Unknown",
          mention.source || "",
          mention.risk_level
        )
    );

    fillThreatList(
      threatLists.credentials,
      data.credentials || [],
      "No exposed credentials found.",
      (cred) =>
        makeThreatItem(
          cred.email || "Unknown",
          `${cred.source || "Unknown"}${cred.has_password ? " · password exposed" : ""}`
        )
    );

    fillThreatList(
      threatLists.intelx_phonebook,
      data.intelx_phonebook || [],
      "No related selectors found.",
      (sel) => makeThreatItem(sel.value || "Unknown", sel.type || "Unknown")
    );

    threatPanel.classList.remove("hidden");
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
    attack_surface: (d) =>
      `${d.total_asns} ASNs, ${d.total_netblocks} netblocks, ${d.total_exposed_buckets} buckets`,
    threat: (d) =>
      `${d.total_leaks} leaks, ${d.total_credentials} exposed creds, ${d.total_intelx_phonebook} phonebook hits`,
    typosquat: (d) => `${d.total_active} active of ${d.total_generated} generated`,
    news: (d) => `${d.total_articles} articles (${d.days_monitored}d window)`,
  };

  function applyStats(moduleName, data) {
    if (moduleName === "recon") {
      stats.subdomains.textContent = data.total_subdomains;
      stats.ports.textContent = data.total_open_ports;
    } else if (moduleName === "org" && stats.subdomains.textContent === "-") {
      stats.subdomains.textContent = data.total_subdomains;
    } else if (moduleName === "attack_surface") {
      stats.asns.textContent = data.total_asns;
      stats.buckets.textContent = data.total_exposed_buckets;
    } else if (moduleName === "threat") {
      stats.leaks.textContent = data.total_leaks + data.total_credentials;
      stats.phonebook.textContent = data.total_intelx_phonebook;
    } else if (moduleName === "typosquat") {
      stats.typosquats.textContent = data.total_active;
    } else if (moduleName === "news") {
      stats.news.textContent = data.total_articles;
    }
  }

  function updateGraph(moduleName, data) {
    if (!window.FarsightGraph || !currentDomain) return;
    if (moduleName === "org") {
      window.FarsightGraph.ingestOrg(graphContainer, currentDomain, data);
    } else if (moduleName === "recon") {
      window.FarsightGraph.ingestRecon(graphContainer, currentDomain, data);
    } else if (moduleName === "typosquat") {
      window.FarsightGraph.ingestTyposquat(graphContainer, currentDomain, data);
    }
  }

  function handleEvent(ev) {
    switch (ev.type) {
      case "scan_started":
        currentDomain = ev.data ? ev.data.domain : null;
        resetUI();
        if (window.FarsightGraph) {
          window.FarsightGraph.reset(graphContainer, currentDomain);
        }
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
        if (ev.data) {
          applyStats(ev.module, ev.data);
          updateGraph(ev.module, ev.data);
          if (ev.module === "typosquat") renderTyposquatPanel(ev.data);
          if (ev.module === "threat") renderThreatPanel(ev.data);
          if (ev.module === "attack_surface") renderAttackSurfacePanel(ev.data);
        }
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
      if (data.demo_mode) {
        demoBanner.classList.remove("hidden");
      }
    })
    .catch(() => setConn("disconnected", "server unreachable"));
})();
