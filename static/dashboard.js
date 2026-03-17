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
  const totalIncidentsEl = document.getElementById("total-incidents");
  const totalRoiEl = document.getElementById("total-roi");
  const threatLevelEl = document.getElementById("threat-level");
  const statusBeacon = document.getElementById("status-beacon");
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
  const pipelineProfitEl = document.getElementById("pipeline-profit");
  const pipelineTotalTimeEl = document.getElementById("pipeline-total-time");
  const pipelineLastUpdateEl = document.getElementById("pipeline-last-update");
  const pipelineStageLog = document.getElementById("pipeline-stage-log");
  const retrainingBadge = document.getElementById("retraining-badge");
  const queueTotalCountEl = document.getElementById("queue-total-count");
  const queueAnomalyCountEl = document.getElementById("queue-anomaly-count");
  const queueNormalCountEl = document.getElementById("queue-normal-count");
  const retrainingQueueListEl = document.getElementById("retraining-queue-list");
  
  let skeletonsRevealed = false;

  let latestIncidentId = null;
  let seenIncidents = new Set();
  let totalAnomalies = 0;
  const startTime = Date.now();
  let firstFeedEntry = true;
  let incidentStore = {}; // store full incidents for clicking
  let lastPipelineIncidentId = null;
  let pipelineTimers = [];

  const PIPELINE_STAGE_TEXT = [
    "Step 1/4: Data is fetched from incoming logs and threat-intelligence context.",
    "Step 2/4: Data is loaded and scored in the ML model stack.",
    "Step 3/4: Claude reasoning analyzes evidence and selects a containment decision.",
    "Step 4/4: Decision and metrics are rendered on the frontend UI for analysts.",
  ];

  function formatDurationMs(ms) {
    if (typeof ms !== "number" || Number.isNaN(ms)) return "-";
    if (ms >= 1000) return `${(ms / 1000).toFixed(2)}s`;
    return `${ms.toFixed(0)}ms`;
  }

  function renderRetrainingQueue(queue) {
    if (!queue) return;

    const total = Number(queue.total_labeled || 0);
    const anomaly = Number(queue.anomaly_labels || 0);
    const normal = Number(queue.normal_labels || 0);
    const items = Array.isArray(queue.recent_items) ? queue.recent_items : [];

    if (queueTotalCountEl) queueTotalCountEl.textContent = String(total);
    if (queueAnomalyCountEl) queueAnomalyCountEl.textContent = String(anomaly);
    if (queueNormalCountEl) queueNormalCountEl.textContent = String(normal);

    if (retrainingBadge) {
      retrainingBadge.textContent = total > 0 ? "Queued" : "Idle";
      retrainingBadge.className = total > 0 ? "panel-badge live" : "panel-badge";
    }

    if (!retrainingQueueListEl) return;
    retrainingQueueListEl.innerHTML = "";

    if (!items.length) {
      const empty = document.createElement("li");
      empty.className = "retraining-empty";
      empty.textContent = "No analyst labels yet. Review incidents and submit labels.";
      retrainingQueueListEl.appendChild(empty);
      return;
    }

    items.forEach((item) => {
      const li = document.createElement("li");
      li.className = "retraining-item";
      const when = item.feedback_timestamp
        ? new Date(item.feedback_timestamp).toLocaleTimeString([], { hour12: false })
        : "--:--:--";
      const labelClass = item.label === "anomaly" ? "label-anomaly" : "label-normal";
      li.innerHTML = `
        <div class="retraining-meta">
          <span>${when}</span>
          <span class="queue-label ${labelClass}">${String(item.label || "unknown").toUpperCase()}</span>
          <span>${item.incident_id || "unknown"}</span>
        </div>
        <div class="retraining-text">
          ${item.attack_type || "unknown_anomaly"} | ${item.source_ip || "unknown"} -> ${item.dest_ip || "unknown"}
        </div>
      `;
      retrainingQueueListEl.appendChild(li);
    });
  }

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
  // Logout
  // ---------------------------------------------------------------------------
  const logoutBtn = document.getElementById("logout-btn");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", () => {
      localStorage.removeItem("soc_session");
      window.location.href = "/login";
    });
  }

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
    if (pipelineProfitEl) pipelineProfitEl.textContent = "-";
    if (pipelineTotalTimeEl) pipelineTotalTimeEl.textContent = "-";
    if (pipelineLastUpdateEl) pipelineLastUpdateEl.textContent = "-";
    if (pipelineStageLog) pipelineStageLog.textContent = "Pipeline idle. Waiting for anomaly...";
    if (pipelineMlProbEl) {
      pipelineMlProbEl.classList.remove("value-critical", "value-high", "value-medium", "value-low");
    }
    if (pipelineActionEl) {
      pipelineActionEl.classList.remove("value-isolate", "value-revoke", "value-honeypot");
    }
    lastPipelineIncidentId = null;
  }

  function updatePipelineMetrics(incident) {
    if (!incident) return;
    const top = incident.top_features && incident.top_features.length ? incident.top_features[0] : null;
    const probNum = typeof incident.ml_probability === "number" ? incident.ml_probability : null;
    const prob = probNum !== null ? `${(probNum * 100).toFixed(1)}%` : "-";
    const topFeatureName = top && top.feature
      ? String(top.feature).replace(/_/g, " ")
      : "n/a";

    pipelineEventIdEl.textContent = incident.incident_id || "unknown";
    pipelineMlProbEl.textContent = prob;
    pipelineTopFeatureEl.textContent = top ? `${topFeatureName} (${Number(top.impact || 0).toFixed(2)})` : "n/a";
    const action = String(incident.containment_action || "unknown").toLowerCase();
    pipelineActionEl.textContent = action.toUpperCase();
    pipelineProfitEl.textContent = formatCurrency(Number(incident.estimated_roi_saved || 0));
    pipelineTotalTimeEl.textContent = formatDurationMs(Number(incident.pipeline_total_ms));
    pipelineLastUpdateEl.textContent = new Date(incident.created_at || Date.now()).toLocaleTimeString([], { hour12: false });

    pipelineMlProbEl.classList.remove("value-critical", "value-high", "value-medium", "value-low");
    if (probNum !== null) {
      if (probNum >= 0.85) pipelineMlProbEl.classList.add("value-critical");
      else if (probNum >= 0.65) pipelineMlProbEl.classList.add("value-high");
      else if (probNum >= 0.45) pipelineMlProbEl.classList.add("value-medium");
      else pipelineMlProbEl.classList.add("value-low");
    }

    pipelineActionEl.classList.remove("value-isolate", "value-revoke", "value-honeypot");
    if (action === "isolate") pipelineActionEl.classList.add("value-isolate");
    if (action === "revoke") pipelineActionEl.classList.add("value-revoke");
    if (action === "honeypot") pipelineActionEl.classList.add("value-honeypot");
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
        const stageTiming = incident.pipeline_timing_ms || {};
        const dataMs = formatDurationMs(Number(stageTiming.data_fetch_osint));
        const mlMs = formatDurationMs(Number(stageTiming.ml_load_train_reason));
        const llmMs = formatDurationMs(Number(stageTiming.llm_claude_reasoning));
        const uiMs = formatDurationMs(Number(stageTiming.frontend_prepare));
        const totalMs = formatDurationMs(Number(incident.pipeline_total_ms));
        pipelineStageLog.textContent = `Flow complete: Data fetched (${dataMs}) -> ML loaded/scored (${mlMs}) -> Claude reasoning (${llmMs}) -> Frontend decision shown (${uiMs}). Decision: ${action}. Total: ${totalMs}.`;
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
      stabilization: { iterations: 200, fit: true },
      barnesHut: { gravitationalConstant: -3000, centralGravity: 0.5, springLength: 140, springConstant: 0.04, damping: 0.15 },
    },
    nodes: { shape: "dot", size: 28, borderWidth: 3, font: { color: "#334155", size: 11, face: "Inter", multi: "md", strokeWidth: 0 } },
    groups: {
      core: { color: { background: "#dbeafe", border: "#2563eb", highlight: { background: "#bfdbfe", border: "#1d4ed8" }, hover: { background: "#bfdbfe", border: "#1d4ed8" } } },
      peer: { color: { background: "#f1f5f9", border: "#94a3b8", highlight: { background: "#e2e8f0", border: "#64748b" }, hover: { background: "#e2e8f0", border: "#64748b" } } },
    },
    edges: { color: { color: "#cbd5e1" }, width: 1.5, smooth: { type: "continuous" }, font: { color: "#94a3b8", size: 9, face: "JetBrains Mono" }, arrows: { to: { enabled: false } } },
    interaction: { dragNodes: false, dragView: false, zoomView: false, hover: true },
  };

  const network = new vis.Network(networkContainer, { nodes, edges }, graphOptions);

  // Center and fit graph after physics stabilizes
  network.once('stabilized', () => {
    network.fit({ animation: { duration: 400, easingFunction: 'easeInOutQuad' } });
    // Disable physics after stabilization to keep nodes fixed in place
    network.setOptions({ physics: { enabled: false } });
  });

  function setGraphHealthy() {
    nodes.update({ id: 1, color: { background: "#dbeafe", border: "#2563eb" } });
    [2, 3, 4, 5].forEach((id) => { nodes.update({ id, color: { background: "#f1f5f9", border: "#94a3b8" } }); });
    edges.forEach((edge) => { edges.update({ id: edge.id, color: { color: "#cbd5e1" }, width: 1.5, dashes: false, arrows: { to: { enabled: false } } }); });
    if (overlay) overlay.classList.add("hidden");
    if (statusBeacon) statusBeacon.classList.remove("danger");
    if (graphBadge) { graphBadge.textContent = "Live"; graphBadge.className = "panel-badge live"; }
    if (graphStatusEl) graphStatusEl.className = "graph-status";
    if (graphStatusText) graphStatusText.innerHTML = '<strong>Status: All Clear.</strong> The enterprise network topology shows 5 interconnected systems. No anomalies detected.';
  }

  function setGraphAnomalous(containmentAction, incident) {
    nodes.update({ id: 1, color: { background: "#fecaca", border: "#dc2626" } });
    [2, 3].forEach((id) => { nodes.update({ id, color: { background: "#fef3c7", border: "#f59e0b" } }); });
    ["e1-2", "e1-3"].forEach((eid) => { edges.update({ id: eid, color: { color: "#dc2626" }, width: 2.5, dashes: [6, 3], arrows: { to: { enabled: true, scaleFactor: 0.8 } } }); });
    if (statusBeacon) statusBeacon.classList.add("danger");
    if (graphBadge) { graphBadge.textContent = "Threat"; graphBadge.className = "panel-badge danger"; }
    if (containmentAction === "isolate" || containmentAction === "revoke") { if (overlay) overlay.classList.remove("hidden"); } else { if (overlay) overlay.classList.add("hidden"); }
    const attackType = incident?.log?.attack_type || "unknown";
    const sourceIp = incident?.log?.source_ip || "unknown";
    const destIp = incident?.log?.dest_ip || "unknown";
    const protocol = incident?.log?.protocol || "unknown";
    const containmentText = containmentAction === "isolate" ? "Network isolation has been activated." : containmentAction === "revoke" ? "Token revocation is in effect." : "Traffic routed to honeypot.";
    if (graphStatusEl) graphStatusEl.className = "graph-status danger";
    if (graphStatusText) graphStatusText.innerHTML = `<strong>Alert: ${attackType.replace("_", " ").toUpperCase()} detected.</strong> Source <strong>${sourceIp}</strong> attacked <strong>${destIp}</strong> via <strong>${protocol}</strong>. ${containmentText}`;
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

    // Update the threat level text in the metric card
    if (threatLevelEl) {
      threatLevelEl.textContent = label;
      threatLevelEl.style.color = colorClass === "low" ? "#10b981" : colorClass === "med" ? "#f59e0b" : colorClass === "high" ? "#f97316" : "#ef4444";
    }

    // Update threat dots (star indicators)
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
  async function submitAnalystFeedback(incidentId, analystLabel) {
    const statusEl = document.getElementById("feedback-status");
    const btnThreat = document.getElementById("btn-mark-threat");
    const btnNormal = document.getElementById("btn-mark-normal");
    if (!incidentId || !statusEl) return;

    if (btnThreat) btnThreat.disabled = true;
    if (btnNormal) btnNormal.disabled = true;
    statusEl.textContent = "Saving analyst decision for retraining...";

    try {
      const res = await fetch("/api/feedback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ incident_id: incidentId, analyst_label: analystLabel }),
      });
      const body = await res.json();
      if (!res.ok) {
        statusEl.textContent = body.error || "Failed to save feedback.";
        if (btnThreat) btnThreat.disabled = false;
        if (btnNormal) btnNormal.disabled = false;
        return;
      }

      if (incidentStore[incidentId]) {
        incidentStore[incidentId].analyst_label = analystLabel;
      }
      statusEl.textContent = `Feedback saved: labeled as ${analystLabel.toUpperCase()} for retraining.`;
      fetchRetrainingQueue();
    } catch (err) {
      statusEl.textContent = "Network error while saving feedback.";
      if (btnThreat) btnThreat.disabled = false;
      if (btnNormal) btnNormal.disabled = false;
    }
  }

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
    const isoOutlier = !!inc.model_signals?.isolation_forest_outlier;
    const osintHit = !!inc.model_signals?.osint_known_bad_ip;
    const mlProbPct = typeof inc.ml_probability === "number" ? `${(inc.ml_probability * 100).toFixed(2)}%` : "-";
    
    // Render OSINT findings with threat categories
    let osintHtml = "";
    if (inc.osint_findings && inc.osint_findings.length > 0) {
      osintHtml = `
        <div class="exp-section" style="background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%); border-left: 4px solid #dc2626; margin-top: 0;">
          <h3 style="color: #b91c1c; margin-top: 0;">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v2m0 4v2m7.07-10.07a10 10 0 0 0-14.14 0"/><path d="M12 3v3m0 12v3"/></svg>
            OSINT Threat Intelligence Match
          </h3>
          <p style="color: #7f1d1d; margin: 0 0 12px 0;"><strong>Severity: ${inc.osint_severity?.toUpperCase() || 'UNKNOWN'}</strong> - ${inc.osint_summary || ''}</p>
          <div class="osint-threats">
      `;
      
      inc.osint_findings.forEach(threat => {
        const threatType = threat.type?.toUpperCase() || 'UNKNOWN';
        const severityClass = threat.severity === 'critical' ? 'threat-critical' : threat.severity === 'high' ? 'threat-high' : 'threat-medium';
        const categories = threat.categories?.join(', ') || 'Unknown';
        const sources = threat.sources?.join(', ') || 'Unknown';
        
        osintHtml += `
          <div class="threat-card ${severityClass}">
            <div class="threat-header">
              <strong>${threatType}</strong>
              <span class="threat-badge">${threat.severity?.toUpperCase() || 'UNKNOWN'}</span>
            </div>
            <div class="threat-detail"><strong>Indicator:</strong> ${threat.indicator}</div>
            <div class="threat-detail"><strong>Categories:</strong> ${categories}</div>
            <div class="threat-detail"><strong>Sources:</strong> ${sources}</div>
          </div>
        `;
      });
      
      osintHtml += `
          </div>
        </div>
      `;
    }
    
    let featuresHtml = "";
    if (inc.top_features && inc.top_features.length > 0) {
      inc.top_features.forEach(f => {
        let valStr = typeof f.value === 'number' && !Number.isInteger(f.value) ? f.value.toFixed(2) : f.value;
        const impactIndicator = f.impact > 0 ? "Increased anomaly likelihood" : "Lowered anomaly likelihood";
        featuresHtml += `
          <li class="${f.impact < 0 ? 'bad-point' : ''}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
            <div>
              <strong>${f.feature.replace("_ord", "")} (${valStr}):</strong>
              ${impactIndicator} with SHAP impact ${Math.abs(f.impact).toFixed(3)}.
            </div>
          </li>
        `;
      });
    }

    const analystLabelText = inc.analyst_label
      ? `Current analyst label: ${inc.analyst_label.toUpperCase()}`
      : "No analyst feedback yet.";

    explanationBox.innerHTML = `
      ${osintHtml}
      
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
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 12l2 2 4-4"/><path d="M21 12c.552 0 1-.449.975-1-.233-5.141-4.506-9.2-9.7-8.973C7.682 2.226 4 5.932 4 10.5V12"/><path d="M3 12h18"/></svg>
          Isolation + SHAP Threat Drivers
        </h3>
        <div class="model-evidence-grid">
          <div class="evidence-card ${isoOutlier ? "evidence-on" : "evidence-off"}">
            <span>IsolationForest Outlier</span>
            <strong>${isoOutlier ? "YES" : "NO"}</strong>
            <small>${isoOutlier ? "Zero-day style outlier path triggered." : "No IF outlier override on this event."}</small>
          </div>
          <div class="evidence-card ${osintHit ? "evidence-on" : "evidence-off"}">
            <span>OSINT Known-Bad IP</span>
            <strong>${osintHit ? "MATCH" : "NO MATCH"}</strong>
            <small>${osintHit ? "Known threat intel IP detected in this flow." : "No static threat intel IP match."}</small>
          </div>
          <div class="evidence-card">
            <span>ML Anomaly Probability</span>
            <strong>${mlProbPct}</strong>
            <small>Combined ensemble confidence for anomaly classification.</small>
          </div>
        </div>
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

      <div class="exp-section" style="margin-top: 0;">
        <h3>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M12 4h9"/><path d="M4 9h16"/><path d="M4 15h16"/></svg>
          SOC Analyst Decision & Retraining Label
        </h3>
        <p style="margin-bottom:10px;">Review SHAP + Isolation evidence, then choose the final label for retraining.</p>
        <div class="feedback-row">
          <button id="btn-mark-threat" class="btn btn-success" type="button">Mark as Real Threat (Anomaly)</button>
          <button id="btn-mark-normal" class="btn btn-neutral" type="button">Mark as Not Anomaly (Normal)</button>
        </div>
        <p class="status-text" id="feedback-status">${analystLabelText}</p>
      </div>
    `;

    const btnThreat = document.getElementById("btn-mark-threat");
    const btnNormal = document.getElementById("btn-mark-normal");
    if (btnThreat) {
      btnThreat.addEventListener("click", () => submitAnalystFeedback(incidentId, "anomaly"));
    }
    if (btnNormal) {
      btnNormal.addEventListener("click", () => submitAnalystFeedback(incidentId, "normal"));
    }
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
      const [stateRes, queueRes] = await Promise.all([
        fetch("/api/state"),
        fetch("/api/retraining_queue"),
      ]);

      if (!stateRes.ok) return;
      const state = await stateRes.json();
      renderState(state);

      if (queueRes.ok) {
        const queue = await queueRes.json();
        renderRetrainingQueue(queue);
      }
    } catch (err) { }
  }

  async function fetchRetrainingQueue() {
    try {
      const res = await fetch("/api/retraining_queue");
      if (!res.ok) return;
      const queue = await res.json();
      renderRetrainingQueue(queue);
    } catch (err) { }
  }

  function renderState(state) {
    // Hide skeletons after a small delay to ensure they are seen (Only run once)
    if (!skeletonsRevealed) {
      setTimeout(() => {
        const skeletons = [
            "graph-skeleton", "feed-skeleton", "explanation-skeleton"
        ];
        skeletons.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.classList.add("hidden");
        });
        const networkEl = document.getElementById("network");
        if (networkEl) networkEl.classList.remove("hidden");
        // Fit the graph now that the container is visible
        if (network) {
          setTimeout(() => {
            network.fit({ animation: { duration: 400, easingFunction: 'easeInOutQuad' } });
          }, 50);
        }
        const feedEmpties = document.querySelectorAll(".feed-empty");
        feedEmpties.forEach(el => el.classList.remove("hidden"));
        skeletonsRevealed = true;
      }, 1500); // 1.5s delay for skeleton visibility
    }

    const incidents = state.incidents || [];
    const count = incidents.length || 0;
    const roi = state.total_roi_saved || 0;
    const threat = state.threat_level || "Low";

    // If backend has no incidents but frontend still has stale state, reset everything
    if (count === 0 && seenIncidents.size > 0) {
      seenIncidents.clear();
      totalAnomalies = 0;
      prevCount = 0;
      prevRoi = 0;
      firstFeedEntry = true;
      incidentStore = {};
      latestIncidentId = null;
      lastPipelineIncidentId = null;
      // Clear the feed
      if (feedEl) {
        const feedEmpty = feedEl.querySelector('.feed-empty');
        feedEl.innerHTML = '';
        if (feedEmpty) { feedEl.appendChild(feedEmpty); feedEmpty.classList.remove('hidden'); }
      }
      // Clear explanation box
      if (explanationBox) {
        const explEmpty = explanationBox.querySelector('.feed-empty');
        explanationBox.innerHTML = '';
        if (explEmpty) { explanationBox.appendChild(explEmpty); explEmpty.classList.remove('hidden'); }
      }
      // Clear interrogation log
      if (interrogationLog) {
        interrogationLog.innerHTML = '<li class="feed-empty">Waiting for anomaly detection...</li>';
      }
    }

    if (totalIncidentsEl) {
      if (count !== prevCount) {
        animateValue(totalIncidentsEl, prevCount, count, 600);
        prevCount = count;
      } else {
        totalIncidentsEl.textContent = String(count);
      }
    }

    if (totalRoiEl) {
      if (roi !== prevRoi) {
        animateValue(totalRoiEl, prevRoi, roi, 800, formatCurrency);
        prevRoi = roi;
      } else {
        totalRoiEl.textContent = `$${roi.toLocaleString()}`;
      }
    }

    if (threatLevelEl) {
      threatLevelEl.textContent = threat;
      const indicatorLabel = threatLevelEl.closest('.metric-card')?.querySelector('.threat-label');
      if (indicatorLabel) indicatorLabel.textContent = threat;
    }

    if (!incidents.length) {
      setGraphHealthy();
      if (yaraEl) yaraEl.textContent = "No rules generated yet.";
      if (undoBtn) undoBtn.disabled = true;
      latestIncidentId = null;
      updateThreatLevel(0);
      setPipelineIdle();
      return;
    }

    const latest = incidents[0];
    const containmentAction = latest.status === "undo" ? "undo" : latest.containment_action || "isolate";
    latestIncidentId = latest.incident_id;

    if (containmentAction === "undo") { setGraphHealthy(); } else { setGraphAnomalous(containmentAction, latest); }
    if (latest.generated_yara_rule && yaraEl) { yaraEl.textContent = latest.generated_yara_rule; }
    if (undoBtn) undoBtn.disabled = !latestIncidentId;

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
