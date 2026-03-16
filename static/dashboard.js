// The Agentic SOC — Premium Dashboard Controller
// - Light-mode vis-network graph with blue/red theme
// - Animated metrics, live feed, interrogation log
// - Threat level indicator
// - Blockchain audit trail visualization
// - Uptime counter

(function () {
  // ---------------------------------------------------------------------------
  // DOM refs
  // ---------------------------------------------------------------------------
  const networkContainer = document.getElementById("network");
  const overlay = document.getElementById("containment-overlay");
  const feedEl = document.getElementById("feed");
  const yaraEl = document.getElementById("yara");
  const undoBtn = document.getElementById("undo-btn");
  const undoStatus = document.getElementById("undo-status");
  const incidentCountEl = document.getElementById("incident-count");
  const roiEl = document.getElementById("roi-saved");
  const statusBeacon = document.getElementById("status-beacon");
  const threatLabel = document.getElementById("threat-label");
  const threatDots = document.querySelectorAll(".threat-dot");
  const uptimeEl = document.getElementById("uptime");
  const interrogationLog = document.getElementById("interrogation-log");
  const reasoningBadge = document.getElementById("reasoning-badge");
  const feedBadge = document.getElementById("feed-badge");
  const chainVisual = document.getElementById("chain-visual");
  const chainStatus = document.getElementById("chain-status");

  let latestIncidentId = null;
  let seenIncidents = new Set();
  let totalAnomalies = 0;
  const startTime = Date.now();
  let firstFeedEntry = true;

  // ---------------------------------------------------------------------------
  // Uptime clock
  // ---------------------------------------------------------------------------
  function updateUptime() {
    const elapsed = Date.now() - startTime;
    const mins = Math.floor(elapsed / 60000);
    const secs = Math.floor((elapsed % 60000) / 1000);
    const hrs = Math.floor(mins / 60);
    if (hrs > 0) {
      uptimeEl.textContent = `${hrs}:${String(mins % 60).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;
    } else {
      uptimeEl.textContent = `${String(mins).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;
    }
  }
  setInterval(updateUptime, 1000);
  updateUptime();

  // ---------------------------------------------------------------------------
  // Graph setup (vis-network) — Detailed Threat Map
  // ---------------------------------------------------------------------------
  const graphStatusEl = document.getElementById("graph-status");
  const graphStatusText = document.getElementById("graph-status-text");
  const graphBadge = document.getElementById("graph-badge");

  // Simulated enterprise network nodes with IPs and roles
  const nodes = new vis.DataSet([
    {
      id: 1,
      label: "Patient Zero\n10.0.22.221\nWorkstation",
      group: "core",
      title: "Patient Zero — The initially compromised host.\nIP: 10.0.22.221\nRole: Employee workstation\nThis node originates lateral movement or stolen token attacks.",
    },
    {
      id: 2,
      label: "DB Server\n10.0.1.50\nPostgreSQL",
      group: "peer",
      title: "Database Server\nIP: 10.0.1.50\nRole: Primary database (PostgreSQL)\nStores sensitive customer and financial data.",
    },
    {
      id: 3,
      label: "App Server\n10.0.2.10\nFlask API",
      group: "peer",
      title: "Application Server\nIP: 10.0.2.10\nRole: Flask API backend\nServes the main application and handles business logic.",
    },
    {
      id: 4,
      label: "HR Portal\n10.0.3.25\nInternal App",
      group: "peer",
      title: "HR Portal\nIP: 10.0.3.25\nRole: Human Resources portal\nContains employee PII, payroll data, and org charts.",
    },
    {
      id: 5,
      label: "Finance\n10.0.4.100\nSAP ERP",
      group: "peer",
      title: "Finance System\nIP: 10.0.4.100\nRole: SAP ERP / Financial system\nManages billing, invoices, and financial transactions.",
    },
  ]);

  const edges = new vis.DataSet([
    { id: "e1-2", from: 1, to: 2, label: "SMB", title: "SMB connection (port 445)\nPatient Zero → DB Server\nUsed for file sharing; common lateral movement vector." },
    { id: "e1-3", from: 1, to: 3, label: "HTTPS", title: "HTTPS connection (port 443)\nPatient Zero → App Server\nAPI traffic; may carry stolen tokens." },
    { id: "e2-4", from: 2, to: 4, label: "RDP", title: "RDP connection (port 3389)\nDB Server → HR Portal\nRemote desktop; high-risk lateral movement path." },
    { id: "e3-5", from: 3, to: 5, label: "SSH", title: "SSH connection (port 22)\nApp Server → Finance\nSecure shell; used for admin access." },
    { id: "e4-5", from: 4, to: 5, label: "LDAP", title: "LDAP connection (port 389)\nHR Portal → Finance\nDirectory services link; authentication path." },
  ]);

  const graphOptions = {
    autoResize: true,
    physics: {
      enabled: true,
      stabilization: { iterations: 120 },
      barnesHut: {
        gravitationalConstant: -4000,
        centralGravity: 0.25,
        springLength: 160,
        springConstant: 0.035,
        damping: 0.1,
      },
    },
    nodes: {
      shape: "dot",
      size: 28,
      borderWidth: 3,
      shadow: {
        enabled: true,
        color: "rgba(0,0,0,0.06)",
        x: 0,
        y: 4,
        size: 14,
      },
      font: {
        color: "#334155",
        size: 11,
        face: "Inter, system-ui, sans-serif",
        multi: "md",
        strokeWidth: 0,
      },
    },
    groups: {
      core: {
        color: {
          background: "#dbeafe",
          border: "#2563eb",
          highlight: { background: "#bfdbfe", border: "#1d4ed8" },
          hover: { background: "#bfdbfe", border: "#1d4ed8" },
        },
      },
      peer: {
        color: {
          background: "#f1f5f9",
          border: "#94a3b8",
          highlight: { background: "#e2e8f0", border: "#64748b" },
          hover: { background: "#e2e8f0", border: "#64748b" },
        },
      },
    },
    edges: {
      color: { color: "#cbd5e1", highlight: "#94a3b8", hover: "#94a3b8" },
      width: 1.5,
      smooth: { type: "continuous" },
      font: { color: "#94a3b8", size: 9, face: "JetBrains Mono, monospace", strokeWidth: 0, align: "top" },
      arrows: { to: { enabled: false } },
    },
    interaction: {
      dragNodes: false,
      dragView: true,
      zoomView: true,
      hover: true,
      tooltipDelay: 200,
    },
  };

  const network = new vis.Network(networkContainer, { nodes, edges }, graphOptions);

  // --- Graph State Functions ---
  function setGraphHealthy() {
    // Reset Patient Zero
    nodes.update({
      id: 1,
      color: { background: "#dbeafe", border: "#2563eb" },
    });
    // Reset all peers to normal
    [2, 3, 4, 5].forEach((id) => {
      nodes.update({
        id,
        color: { background: "#f1f5f9", border: "#94a3b8" },
      });
    });
    // Reset all edges to normal
    edges.forEach((edge) => {
      edges.update({
        id: edge.id,
        color: { color: "#cbd5e1" },
        width: 1.5,
        dashes: false,
        arrows: { to: { enabled: false } },
      });
    });

    overlay.classList.add("hidden");
    statusBeacon.classList.remove("danger");
    graphBadge.textContent = "Live";
    graphBadge.className = "panel-badge live";

    graphStatusEl.className = "graph-status";
    graphStatusText.innerHTML =
      '<strong>Status: All Clear.</strong> The enterprise network topology shows 5 interconnected systems. ' +
      'No anomalies detected. All nodes are healthy and operating normally.';
  }

  function setGraphAnomalous(containmentAction, incident) {
    // Patient Zero turns red
    nodes.update({
      id: 1,
      color: { background: "#fecaca", border: "#dc2626" },
    });

    // Direct neighbors (DB Server, App Server) become "at risk" (amber)
    [2, 3].forEach((id) => {
      nodes.update({
        id,
        color: { background: "#fef3c7", border: "#f59e0b" },
      });
    });

    // Attack path edges turn red with arrows
    ["e1-2", "e1-3"].forEach((eid) => {
      edges.update({
        id: eid,
        color: { color: "#dc2626" },
        width: 2.5,
        dashes: [6, 3],
        arrows: { to: { enabled: true, scaleFactor: 0.8 } },
      });
    });

    statusBeacon.classList.add("danger");
    graphBadge.textContent = "Threat";
    graphBadge.className = "panel-badge danger";

    if (containmentAction === "isolate" || containmentAction === "revoke") {
      overlay.classList.remove("hidden");
    } else {
      overlay.classList.add("hidden");
    }

    // Build detailed status text
    const attackType = incident?.log?.attack_type || "unknown";
    const sourceIp = incident?.log?.source_ip || "unknown";
    const destIp = incident?.log?.dest_ip || "unknown";
    const protocol = incident?.log?.protocol || "unknown";
    const containmentText = containmentAction === "isolate"
      ? "Network isolation has been activated — Patient Zero is now quarantined from all peers."
      : containmentAction === "revoke"
      ? "Token/credential revocation is in effect — compromised sessions are invalidated."
      : "Traffic is being routed to a honeypot for observation.";

    graphStatusEl.className = "graph-status danger";
    graphStatusText.innerHTML =
      `<strong>Alert: ${attackType.replace("_", " ").toUpperCase()} detected.</strong> ` +
      `Source <strong>${sourceIp}</strong> attacked <strong>${destIp}</strong> via <strong>${protocol}</strong>. ` +
      `Nodes directly connected to Patient Zero (DB Server, App Server) are marked <strong>at risk</strong>. ` +
      containmentText;
  }

  setGraphHealthy();

  // ---------------------------------------------------------------------------
  // Threat Level System
  // ---------------------------------------------------------------------------
  function updateThreatLevel(anomalyCount) {
    let level, label, colorClass;
    if (anomalyCount === 0) {
      level = 1; label = "Low"; colorClass = "low";
    } else if (anomalyCount <= 2) {
      level = 2; label = "Medium"; colorClass = "med";
    } else if (anomalyCount <= 5) {
      level = 3; label = "High"; colorClass = "high";
    } else {
      level = 5; label = "Critical"; colorClass = "crit";
    }

    threatLabel.textContent = label;
    threatLabel.style.color =
      colorClass === "low" ? "#10b981" :
      colorClass === "med" ? "#f59e0b" :
      colorClass === "high" ? "#f97316" : "#ef4444";

    threatDots.forEach((dot, i) => {
      dot.className = "threat-dot";
      if (i < level) {
        dot.classList.add("active", colorClass);
      }
    });
  }

  updateThreatLevel(0);

  // ---------------------------------------------------------------------------
  // Currency formatter
  // ---------------------------------------------------------------------------
  function formatCurrency(value) {
    try {
      return new Intl.NumberFormat("en-US", {
        style: "currency",
        currency: "USD",
        maximumFractionDigits: 0,
      }).format(value || 0);
    } catch (e) {
      return "$" + (value || 0).toLocaleString();
    }
  }

  // ---------------------------------------------------------------------------
  // Animated counter
  // ---------------------------------------------------------------------------
  function animateValue(el, start, end, duration, formatter) {
    if (start === end) return;
    const range = end - start;
    const startTime = performance.now();

    function step(now) {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // Ease out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      const current = start + range * eased;
      el.textContent = formatter ? formatter(current) : Math.round(current).toString();
      if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  // ---------------------------------------------------------------------------
  // Live Feed
  // ---------------------------------------------------------------------------
  function prependFeedEntry(incident) {
    if (!incident) return;

    // Clear the empty state on first entry
    if (firstFeedEntry) {
      feedEl.innerHTML = "";
      firstFeedEntry = false;
    }

    const ts = new Date(incident.created_at || Date.now());
    const tsStr = ts.toLocaleTimeString([], { hour12: false });
    const attack = incident.log?.attack_type || "anomaly";

    const wrapper = document.createElement("div");
    wrapper.className = "feed-entry anomaly";

    const meta = document.createElement("div");
    meta.className = "feed-meta";
    meta.innerHTML = `
      <span>${tsStr}</span>
      <span class="tag anomaly">${attack.replace("_", " ")}</span>
      <span class="tag contained">${incident.containment_action}</span>
      <span>${incident.incident_id}</span>
    `;

    const text = document.createElement("div");
    text.className = "feed-text";
    text.textContent = incident.play_by_play_narrative || "Anomaly detected and contained.";

    wrapper.appendChild(meta);
    wrapper.appendChild(text);

    if (feedEl.firstChild) {
      feedEl.insertBefore(wrapper, feedEl.firstChild);
    } else {
      feedEl.appendChild(wrapper);
    }

    // Keep feed manageable
    while (feedEl.children.length > 50) {
      feedEl.removeChild(feedEl.lastChild);
    }
  }

  // ---------------------------------------------------------------------------
  // Interrogation Log
  // ---------------------------------------------------------------------------
  function renderInterrogationLog(steps) {
    if (!steps || !steps.length) return;

    interrogationLog.innerHTML = "";
    reasoningBadge.textContent = "Active";
    reasoningBadge.className = "panel-badge live";

    steps.forEach((step, i) => {
      const li = document.createElement("li");
      li.className = "interrogation-step";

      const num = document.createElement("span");
      num.className = "step-number";
      num.textContent = i + 1;

      const txt = document.createElement("span");
      txt.textContent = step;

      li.appendChild(num);
      li.appendChild(txt);
      interrogationLog.appendChild(li);
    });
  }

  // ---------------------------------------------------------------------------
  // Blockchain Audit Trail
  // ---------------------------------------------------------------------------
  let blockCount = 0;

  function addBlockToChain(incidentId) {
    blockCount++;

    // Add arrow
    const arrow = document.createElement("span");
    arrow.className = "chain-arrow";
    arrow.textContent = "→";
    chainVisual.appendChild(arrow);

    // Add block
    const block = document.createElement("div");
    block.className = "chain-block";
    block.title = `Block #${blockCount} — ${incidentId}`;
    block.textContent = `#${blockCount}`;
    chainVisual.appendChild(block);

    // Scroll to end
    chainVisual.scrollLeft = chainVisual.scrollWidth;

    // Update chain status
    chainStatus.innerHTML = `
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
      Chain valid · ${blockCount + 1} blocks
    `;
  }

  // ---------------------------------------------------------------------------
  // Polling /api/state
  // ---------------------------------------------------------------------------
  let prevCount = 0;
  let prevRoi = 0;

  async function fetchState() {
    try {
      const res = await fetch("/api/state");
      if (!res.ok) return;
      const state = await res.json();
      renderState(state);
    } catch (err) {
      console.error("state poll error", err);
    }
  }

  function renderState(state) {
    const incidents = state.incidents || [];
    const count = state.incident_count || incidents.length || 0;
    const roi = state.total_roi_saved || 0;

    // Animate counters
    if (count !== prevCount) {
      animateValue(incidentCountEl, prevCount, count, 600);
      prevCount = count;
    }
    if (roi !== prevRoi) {
      animateValue(roiEl, prevRoi, roi, 800, formatCurrency);
      prevRoi = roi;
    }

    if (!incidents.length) {
      setGraphHealthy();
      yaraEl.textContent = "No rules generated yet.";
      undoBtn.disabled = true;
      latestIncidentId = null;
      updateThreatLevel(0);
      return;
    }

    const latest = incidents[0];
    const containmentAction =
      latest.status === "undo"
        ? "undo"
        : latest.containment_action || "isolate";
    latestIncidentId = latest.incident_id;

    if (containmentAction === "undo") {
      setGraphHealthy();
    } else {
      setGraphAnomalous(containmentAction, latest);
    }

    if (latest.generated_yara_rule) {
      yaraEl.textContent = latest.generated_yara_rule;
    }

    undoBtn.disabled = !latestIncidentId;

    // Process new incidents
    for (let i = incidents.length - 1; i >= 0; i--) {
      const inc = incidents[i];
      if (!seenIncidents.has(inc.incident_id)) {
        seenIncidents.add(inc.incident_id);
        totalAnomalies++;
        prependFeedEntry(inc);
        addBlockToChain(inc.incident_id);

        // Update feed badge
        feedBadge.textContent = "Alert";
        feedBadge.className = "panel-badge danger";
        setTimeout(() => {
          feedBadge.textContent = "Monitoring";
          feedBadge.className = "panel-badge live";
        }, 3000);
      }
    }

    // Interrogation log from latest
    if (latest.interrogation_log && latest.interrogation_log.length) {
      renderInterrogationLog(latest.interrogation_log);
    }

    updateThreatLevel(totalAnomalies);
  }

  // ---------------------------------------------------------------------------
  // UNDO containment
  // ---------------------------------------------------------------------------
  async function undoContainment() {
    if (!latestIncidentId) return;
    undoBtn.disabled = true;
    undoStatus.textContent = "Reversing containment...";

    try {
      const res = await fetch(`/api/contain/undo/${latestIncidentId}`, {
        method: "POST",
      });
      if (!res.ok) {
        undoStatus.textContent = "Undo failed (API error).";
        undoBtn.disabled = false;
        return;
      }
      const body = await res.json();
      undoStatus.textContent = `Containment reversed for ${
        body.incident?.incident_id || latestIncidentId
      }.`;
      setGraphHealthy();
    } catch (err) {
      console.error("undo error", err);
      undoStatus.textContent = "Undo failed (network error).";
    }
  }

  undoBtn.addEventListener("click", undoContainment);

  // ---------------------------------------------------------------------------
  // Kick off
  // ---------------------------------------------------------------------------
  fetchState();
  setInterval(fetchState, 2000);
})();
