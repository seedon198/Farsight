/* Attack-surface graph, built incrementally from MODULE_COMPLETED event
 * data already sent to the browser (see orchestrator.py's _org_summary /
 * _recon_summary / _typosquat_summary). No extra network calls. */
(() => {
  "use strict";

  let cy = null;
  const nodeIds = new Set();

  const STYLE = [
    {
      selector: "node",
      style: {
        "background-color": "#56d4dd",
        label: "data(label)",
        "font-size": 7,
        color: "#c9d1d9",
        "text-outline-width": 0,
        width: 12,
        height: 12,
      },
    },
    {
      selector: 'node[kind = "root"]',
      style: { "background-color": "#39ff88", width: 28, height: 28, "font-size": 11 },
    },
    { selector: 'node[kind = "subdomain"]', style: { "background-color": "#56d4dd" } },
    { selector: 'node[kind = "related"]', style: { "background-color": "#8892a0" } },
    {
      selector: 'node[kind = "typosquat-high"]',
      style: { "background-color": "#ff5f56" },
    },
    {
      selector: 'node[kind = "typosquat-med"]',
      style: { "background-color": "#f0c674" },
    },
    {
      selector: "edge",
      style: { "line-color": "#202a33", width: 1, "curve-style": "haystack" },
    },
  ];

  function ensureCy(container, rootDomain) {
    if (cy) return cy;
    cy = cytoscape({
      container,
      elements: [{ data: { id: rootDomain, label: rootDomain, kind: "root" } }],
      style: STYLE,
      layout: { name: "preset" },
    });
    nodeIds.add(rootDomain);
    return cy;
  }

  function addNode(id, kind) {
    if (!id || nodeIds.has(id)) return;
    nodeIds.add(id);
    cy.add({ data: { id, label: id, kind } });
  }

  function addEdge(source, target) {
    if (!target || source === target) return;
    const edgeId = `${source}->${target}`;
    if (cy.getElementById(edgeId).length) return;
    cy.add({ data: { id: edgeId, source, target } });
  }

  function relayout() {
    cy.layout({ name: "cose", animate: true, animationDuration: 400, fit: true }).run();
  }

  function reset(container, rootDomain) {
    if (cy) {
      cy.destroy();
      cy = null;
    }
    nodeIds.clear();
    if (rootDomain) ensureCy(container, rootDomain);
  }

  function ingestOrg(container, rootDomain, data) {
    ensureCy(container, rootDomain);
    (data.related_domains || []).forEach((d) => {
      addNode(d, "related");
      addEdge(rootDomain, d);
    });
    (data.discovered_subdomains || []).forEach((d) => {
      addNode(d, "subdomain");
      addEdge(rootDomain, d);
    });
    relayout();
  }

  function ingestRecon(container, rootDomain, data) {
    ensureCy(container, rootDomain);
    (data.subdomains || []).forEach((d) => {
      addNode(d, "subdomain");
      addEdge(rootDomain, d);
    });
    relayout();
  }

  function ingestTyposquat(container, rootDomain, data) {
    ensureCy(container, rootDomain);
    (data.typosquats || []).forEach((t) => {
      if (!(t.has_dns || t.has_mx || t.http_status)) return;
      addNode(t.domain, t.risk_score >= 70 ? "typosquat-high" : "typosquat-med");
      addEdge(rootDomain, t.domain);
    });
    relayout();
  }

  window.FarsightGraph = { reset, ingestOrg, ingestRecon, ingestTyposquat };
})();
