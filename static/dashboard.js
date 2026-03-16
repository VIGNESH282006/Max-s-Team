// The Agentic SOC — Premium Dashboard Controller
// - Sidebar tabs layout
// - Light-mode vis-network graph
// - Animated metrics, live feed, AI reasoning, Detection Explanations

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
  const explanationBox = document.getElementById("explanation-box");
  const navItems = document.querySelectorAll(".nav-item");
  const tabContents = document.querySelectorAll(".tab-content");
  const menuToggle = document.getElementById("menu-toggle");
  const sidebar = document.getElementById("sidebar");
  const sidebarOverlay = document.getElementById("sidebar-overlay");
  const pipelineBadge = document.getElementById("pipeline-badge");
  const pipelineSteps = document.querySelectorAll(".pipeline-step");
  const pipelineEventIdEl = document.getElementById("pipeline-event-id");
  const pipelineMlProbEl = document.getElementById("pipeline-ml-prob");
  const pipelineTopFeatureEl = document.getElementById("pipeline-top-feature");
  const pipelineActionEl = document.getElementById("pipeline-action");
  const pipelineLastUpdateEl = document.getElementById("pipeline-last-update");
  const pipelineStageLog = document.getElementById("pipeline-stage-log");

  let latestIncidentId = null;
  let seenIncidents = new Set();
  let totalAnomalies = 0;
  const startTime = Date.now();
  let firstFeedEntry = true;
  let incidentStore = {}; // store full incidents for clicking
  let lastPipelineIncidentId = null;
  let pipelineTimers = [];

  const PIPELINE_STAGE_TEXT = [
    "Layer 1/5: Input trust guard stripped attacker-controlled steering fields.",
    "Layer 2/5: Probe defense evaluated request-rate and decision-boundary behavior.",
    "Layer 3/5: Feature hardening extracted temporal, unusual-port, and canary signals.",
    "Layer 4/5: Ensemble ML scored the event using RF + IF + OSINT guardrails.",
    "Layer 5/5: Hardened AI reasoning selected containment and generated response artifacts.",
  ];

  // ---------------------------------------------------------------------------
  // Mobile menu: toggle sidebar
  // ---------------------------------------------------------------------------
  function openSidebar() {
    sidebar.classList.add("open");
    sidebarOverlay.classList.add("visible");
    sidebarOverlay.setAttribute("aria-hidden", "false");
    menuToggle.setAttribute("aria-label", "Close menu");
  }
  function closeSidebar() {
    sidebar.classList.remove("open");
    sidebarOverlay.classList.remove("visible");
    sidebarOverlay.setAttribute("aria-hidden", "true");
    menuToggle.setAttribute("aria-label", "Open menu");
  }
  menuToggle.addEventListener("click", () => {
    if (sidebar.classList.contains("open")) closeSidebar();
    else openSidebar();
  });
  sidebarOverlay.addEventListener("click", closeSidebar);

  // ---------------------------------------------------------------------------
  // Tab Switching Logic
  // ---------------------------------------------------------------------------
  navItems.forEach(item => {
    item.addEventListener("click", () => {
      // Deactivate all
      navItems.forEach(nav => nav.classList.remove("active"));
      tabContents.forEach(tab => tab.classList.remove("active"));
      
      // Activate target
      item.classList.add("active");
      const targetId = item.getAttribute("data-target");
      document.getElementById(targetId).classList.add("active");
      closeSidebar();
    });
  });

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
  // Real-Time Pipeline Visualization (Tab 3)
  // ---------------------------------------------------------------------------
  function clearPipelineTimers() {
    pipelineTimers.forEach((t) => clearTimeout(t));
    pipelineTimers = [];
  }

  function resetPipelineSteps() {
    pipelineSteps.forEach((stepEl) => {
      stepEl.classList.remove("active", "done");
      stepEl.classList.add("pending");
    });
  }

  function setPipelineIdle() {
    clearPipelineTimers();
    resetPipelineSteps();
    if (pipelineBadge) {
      pipelineBadge.textContent = "Idle";
      pipelineBadge.className = "panel-badge";
    }
    if (pipelineEventIdEl) pipelineEventIdEl.textContent = "Waiting...";
    if (pipelineMlProbEl) pipelineMlProbEl.textContent = "-";
    if (pipelineTopFeatureEl) pipelineTopFeatureEl.textContent = "-";
    if (pipelineActionEl) pipelineActionEl.textContent = "-";
    if (pipelineLastUpdateEl) pipelineLastUpdateEl.textContent = "-";
    if (pipelineStageLog) pipelineStageLog.textContent = "Pipeline idle. Waiting for anomaly...";
    lastPipelineIncidentId = null;
  }

  function updatePipelineMetrics(incident) {
    if (!incident) return;
    const top = incident.top_features && incident.top_features.length ? incident.top_features[0] : null;
    const prob = typeof incident.ml_probability === "number"
      ? `${(incident.ml_probability * 100).toFixed(1)}%`
      : "-";

    pipelineEventIdEl.textContent = incident.incident_id || "unknown";
    pipelineMlProbEl.textContent = prob;
    pipelineTopFeatureEl.textContent = top ? `${top.feature} (${Number(top.impact || 0).toFixed(2)})` : "n/a";
    pipelineActionEl.textContent = (incident.containment_action || "unknown").toUpperCase();
    pipelineLastUpdateEl.textContent = new Date(incident.created_at || Date.now()).toLocaleTimeString([], { hour12: false });
  }

  function animatePipelineForIncident(incident) {
    if (!incident || !incident.incident_id) return;

    updatePipelineMetrics(incident);
    if (lastPipelineIncidentId === incident.incident_id) {
      if (pipelineBadge) {
        pipelineBadge.textContent = "Contained";
        pipelineBadge.className = "panel-badge live";
      }
      return;
    }

    lastPipelineIncidentId = incident.incident_id;
    clearPipelineTimers();
    resetPipelineSteps();

    if (pipelineBadge) {
      pipelineBadge.textContent = "Processing";
      pipelineBadge.className = "panel-badge";
    }
    if (pipelineStageLog) {
      pipelineStageLog.textContent = "Incoming anomaly detected. Starting 5-layer defense pipeline...";
    }

    pipelineSteps.forEach((stepEl, idx) => {
      const activeTimer = setTimeout(() => {
        stepEl.classList.remove("pending", "done");
        stepEl.classList.add("active");
        if (pipelineStageLog) pipelineStageLog.textContent = PIPELINE_STAGE_TEXT[idx];
      }, idx * 500);
      pipelineTimers.push(activeTimer);

      const doneTimer = setTimeout(() => {
        stepEl.classList.remove("active", "pending");
        stepEl.classList.add("done");
      }, idx * 500 + 350);
      pipelineTimers.push(doneTimer);
    });

    const finishTimer = setTimeout(() => {
      if (pipelineBadge) {
        pipelineBadge.textContent = "Contained";
        pipelineBadge.className = "panel-badge live";
      }
      if (pipelineStageLog) {
        const action = (incident.containment_action || "unknown").toUpperCase();
        pipelineStageLog.textContent = `Pipeline complete: anomaly confirmed and containment action ${action} executed.`;
      }
    }, PIPELINE_STAGE_TEXT.length * 500 + 200);
    pipelineTimers.push(finishTimer);
  }

  setPipelineIdle();

  // ---------------------------------------------------------------------------
  // Graph setup (vis-network) — Detailed Threat Map
  // ---------------------------------------------------------------------------
  const graphStatusEl = document.getElementById("graph-status");
  const graphStatusText = document.getElementById("graph-status-text");
  const graphBadge = document.getElementById("graph-badge");

  const nodes = new vis.DataSet([
    { id: 1, label: "Patient Zero\n10.0.22.221\nWorkstation", group: "core" },
    { id: 2, label: "DB Server\n10.0.1.50\nPostgreSQL", group: "peer" },
    { id: 3, label: "App Server\n10.0.2.10\nFlask API", group: "peer" },
    { id: 4, label: "HR Portal\n10.0.3.25\nInternal App", group: "peer" },
    { id: 5, label: "Finance\n10.0.4.100\nSAP ERP", group: "peer" },
  ]);

  const edges = new vis.DataSet([
    { id: "e1-2", from: 1, to: 2, label: "SMB" },
    { id: "e1-3", from: 1, to: 3, label: "HTTPS" },
    { id: "e2-4", from: 2, to: 4, label: "RDP" },
    { id: "e3-5", from: 3, to: 5, label: "SSH" },
    { id: "e4-5", from: 4, to: 5, label: "LDAP" },
  ]);

  const graphOptions = {
    autoResize: true,
    physics: {
      enabled: true,
      stabilization: { iterations: 120 },
      barnesHut: { gravitationalConstant: -4000, centralGravity: 0.25, springLength: 160, springConstant: 0.035, damping: 0.1 },
    },
    nodes: { shape: "dot", size: 28, borderWidth: 3, font: { color: "#334155", size: 11, face: "Inter", multi: "md", strokeWidth: 0 } },
    groups: {
      core: { color: { background: "#dbeafe", border: "#2563eb", highlight: { background: "#bfdbfe", border: "#1d4ed8" }, hover: { background: "#bfdbfe", border: "#1d4ed8" } } },
      peer: { color: { background: "#f1f5f9", border: "#94a3b8", highlight: { background: "#e2e8f0", border: "#64748b" }, hover: { background: "#e2e8f0", border: "#64748b" } } },
    },
    edges: { color: { color: "#cbd5e1" }, width: 1.5, smooth: { type: "continuous" }, font: { color: "#94a3b8", size: 9, face: "JetBrains Mono" }, arrows: { to: { enabled: false } } },
    interaction: { dragNodes: false, dragView: true, zoomView: true, hover: true },
  };

  const network = new vis.Network(networkContainer, { nodes, edges }, graphOptions);

  function setGraphHealthy() {
    nodes.update({ id: 1, color: { background: "#dbeafe", border: "#2563eb" } });
    [2, 3, 4, 5].forEach((id) => { nodes.update({ id, color: { background: "#f1f5f9", border: "#94a3b8" } }); });
    edges.forEach((edge) => { edges.update({ id: edge.id, color: { color: "#cbd5e1" }, width: 1.5, dashes: false, arrows: { to: { enabled: false } } }); });
    overlay.classList.add("hidden");
    statusBeacon.classList.remove("danger");
    graphBadge.textContent = "Live";
    graphBadge.className = "panel-badge live";
    graphStatusEl.className = "graph-status";
    graphStatusText.innerHTML = '<strong>Status: All Clear.</strong> The enterprise network topology shows 5 interconnected systems. No anomalies detected.';
  }

  function setGraphAnomalous(containmentAction, incident) {
    nodes.update({ id: 1, color: { background: "#fecaca", border: "#dc2626" } });
    [2, 3].forEach((id) => { nodes.update({ id, color: { background: "#fef3c7", border: "#f59e0b" } }); });
    ["e1-2", "e1-3"].forEach((eid) => { edges.update({ id: eid, color: { color: "#dc2626" }, width: 2.5, dashes: [6, 3], arrows: { to: { enabled: true, scaleFactor: 0.8 } } }); });
    statusBeacon.classList.add("danger");
    graphBadge.textContent = "Threat";
    graphBadge.className = "panel-badge danger";
    if (containmentAction === "isolate" || containmentAction === "revoke") { overlay.classList.remove("hidden"); } else { overlay.classList.add("hidden"); }
    const attackType = incident?.log?.attack_type || "unknown";
    const sourceIp = incident?.log?.source_ip || "unknown";
    const destIp = incident?.log?.dest_ip || "unknown";
    const protocol = incident?.log?.protocol || "unknown";
    const containmentText = containmentAction === "isolate" ? "Network isolation has been activated." : containmentAction === "revoke" ? "Token revocation is in effect." : "Traffic routed to honeypot.";
    graphStatusEl.className = "graph-status danger";
    graphStatusText.innerHTML = `<strong>Alert: ${attackType.replace("_", " ").toUpperCase()} detected.</strong> Source <strong>${sourceIp}</strong> attacked <strong>${destIp}</strong> via <strong>${protocol}</strong>. ${containmentText}`;
  }

  setGraphHealthy();

  // ---------------------------------------------------------------------------
  // Threat Level System
  // ---------------------------------------------------------------------------
  function updateThreatLevel(anomalyCount) {
    let level, label, colorClass;
    if (anomalyCount === 0) { level = 1; label = "Low"; colorClass = "low"; }
    else if (anomalyCount <= 2) { level = 2; label = "Medium"; colorClass = "med"; }
    else if (anomalyCount <= 5) { level = 3; label = "High"; colorClass = "high"; }
    else { level = 5; label = "Critical"; colorClass = "crit"; }

    threatLabel.textContent = label;
    threatLabel.style.color = colorClass === "low" ? "#10b981" : colorClass === "med" ? "#f59e0b" : colorClass === "high" ? "#f97316" : "#ef4444";

    threatDots.forEach((dot, i) => {
      dot.className = "threat-dot";
      if (i < level) { dot.classList.add("active", colorClass); }
    });
  }
  updateThreatLevel(0);

  function formatCurrency(value) {
    try { return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 0 }).format(value || 0); }
    catch (e) { return "$" + (value || 0).toLocaleString(); }
  }

  function animateValue(el, start, end, duration, formatter) {
    if (start === end) return;
    const range = end - start;
    const startTime = performance.now();
    function step(now) {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      const current = start + range * eased;
      el.textContent = formatter ? formatter(current) : Math.round(current).toString();
      if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  // ---------------------------------------------------------------------------
  // Explanation Box Rendering (Tab 2)
  // ---------------------------------------------------------------------------
  function renderExplanation(incidentId) {
    const inc = incidentStore[incidentId];
    if (!inc) return;

    // Reset active states in feed
    document.querySelectorAll(".feed-entry").forEach(el => el.classList.remove("active-item"));
    const activeEl = document.querySelector(`.feed-entry[data-id="${incidentId}"]`);
    if (activeEl) activeEl.classList.add("active-item");

    const attack = inc.log?.attack_type || "anomaly";
    const src = inc.log?.source_ip || "unknown";
    const target = inc.log?.dest_ip || "unknown";
    
    let featuresHtml = "";
    if (inc.top_features && inc.top_features.length > 0) {
      const maxImpact = Math.max(...inc.top_features.map(f => Math.abs(f.impact)));
      inc.top_features.forEach(f => {
        let valStr = typeof f.value === 'number' && !Number.isInteger(f.value) ? f.value.toFixed(2) : f.value;
        const impactIndicator = f.impact > 0 ? "Drastically increased likelihood" : "Neutralized factors";
        featuresHtml += `
          <li class="${f.impact < 0 ? 'bad-point' : ''}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
            <div>
              <strong>${f.feature.replace("_ord", "")} (${valStr}):</strong>
              ${impactIndicator} by a factor of ${Math.abs(f.impact).toFixed(2)}.
            </div>
          </li>
        `;
      });
    }

    explanationBox.innerHTML = `
      <div class="exp-section">
        <h3>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          Why is this an Anomaly?
        </h3>
        <p style="margin-bottom: 12px;">The signature <strong>${attack.replace("_"," ").toUpperCase()}</strong> was statistically flagged between <strong>${src}</strong> and <strong>${target}</strong> based on mathematical deviations from normal enterprise traffic.</p>
        <ul class="point-list">
          ${featuresHtml || '<li><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12.01" y2="8"/><polyline points="11 12 12 12 12 16 13 16"/></svg> Black-box ensemble outlier detected (IF Score).</li>'}
        </ul>
      </div>

      <div class="exp-section" style="margin-top: 0;">
        <h3>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
          Why was it not normal traffic?
        </h3>
        <ul class="point-list">
          <li>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
            Normal traffic typically originates from corporate VPN subnets and occurs during standard business hours.
          </li>
          <li>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
            Normal authentication events don't attempt access across multiple disparate geographical regions simultaneously.
          </li>
          <li>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
            The protocol frequency deviated heavily from historical distributions of the ${target} server.
          </li>
        </ul>
      </div>
    `;
  }

  // ---------------------------------------------------------------------------
  // Live Feed
  // ---------------------------------------------------------------------------
  function prependFeedEntry(incident) {
    if (!incident) return;
    if (firstFeedEntry) { feedEl.innerHTML = ""; firstFeedEntry = false; }

    incidentStore[incident.incident_id] = incident;

    const ts = new Date(incident.created_at || Date.now());
    const tsStr = ts.toLocaleTimeString([], { hour12: false });
    const attack = incident.log?.attack_type || "anomaly";

    const wrapper = document.createElement("div");
    wrapper.className = "feed-entry anomaly";
    wrapper.setAttribute("data-id", incident.incident_id);
    
    wrapper.addEventListener("click", () => {
      renderExplanation(incident.incident_id);
    });

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

    if (feedEl.firstChild) { feedEl.insertBefore(wrapper, feedEl.firstChild); } 
    else { feedEl.appendChild(wrapper); }

    while (feedEl.children.length > 50) { feedEl.removeChild(feedEl.lastChild); }
    
    // Auto-select latest if nothing is selected
    if(!document.querySelector(".feed-entry.active-item")) {
      renderExplanation(incident.incident_id);
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
      li.innerHTML = `<span class="step-num">[${String(i+1).padStart(2,'0')}]</span> ${step}`;
      interrogationLog.appendChild(li);
    });
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
    } catch (err) { }
  }

  function renderState(state) {
    const incidents = state.incidents || [];
    const count = state.incident_count || incidents.length || 0;
    const roi = state.total_roi_saved || 0;

    if (count !== prevCount) { animateValue(incidentCountEl, prevCount, count, 600); prevCount = count; }
    if (roi !== prevRoi) { animateValue(roiEl, prevRoi, roi, 800, formatCurrency); prevRoi = roi; }

    if (!incidents.length) {
      setGraphHealthy();
      yaraEl.textContent = "No rules generated yet.";
      undoBtn.disabled = true;
      latestIncidentId = null;
      updateThreatLevel(0);
      setPipelineIdle();
      return;
    }

    const latest = incidents[0];
    const containmentAction = latest.status === "undo" ? "undo" : latest.containment_action || "isolate";
    latestIncidentId = latest.incident_id;

    if (containmentAction === "undo") { setGraphHealthy(); } else { setGraphAnomalous(containmentAction, latest); }
    if (latest.generated_yara_rule) { yaraEl.textContent = latest.generated_yara_rule; }
    undoBtn.disabled = !latestIncidentId;

    for (let i = incidents.length - 1; i >= 0; i--) {
      const inc = incidents[i];
      if (!seenIncidents.has(inc.incident_id)) {
        seenIncidents.add(inc.incident_id);
        totalAnomalies++;
        prependFeedEntry(inc);
      }
    }

    if (latest.interrogation_log && latest.interrogation_log.length) {
      renderInterrogationLog(latest.interrogation_log);
    }

    animatePipelineForIncident(latest);

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
      const res = await fetch(`/api/contain/undo/${latestIncidentId}`, { method: "POST" });
      if (!res.ok) { undoStatus.textContent = "Undo failed (API error)."; undoBtn.disabled = false; return; }
      const body = await res.json();
      undoStatus.textContent = `Containment reversed for ${body.incident?.incident_id || latestIncidentId}.`;
      setGraphHealthy();
    } catch (err) {
      undoStatus.textContent = "Undo failed (network error).";
    }
  }

  undoBtn.addEventListener("click", undoContainment);

  fetchState();
  setInterval(fetchState, 2000);
})();
