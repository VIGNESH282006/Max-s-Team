// The Agentic SOC - Frontend Dashboard
// - Renders a 5-node Patient Zero graph with vis-network
// - Polls /api/state for latest incidents
// - Updates Live Feed, ROI metrics, YARA panel, and UNDO button

(function () {
  const networkContainer = document.getElementById("network");
  const overlay = document.getElementById("containment-overlay");
  const feedEl = document.getElementById("feed");
  const yaraEl = document.getElementById("yara");
  const undoBtn = document.getElementById("undo-btn");
  const undoStatus = document.getElementById("undo-status");
  const incidentCountEl = document.getElementById("incident-count");
  const roiEl = document.getElementById("roi-saved");

  let latestIncidentId = null;

  // ---------------------------------------------------------------------------
  // Graph setup (vis-network)
  // ---------------------------------------------------------------------------
  const nodes = new vis.DataSet([
    { id: 1, label: "Patient Zero", group: "core" },
    { id: 2, label: "DB", group: "peer" },
    { id: 3, label: "App", group: "peer" },
    { id: 4, label: "HR", group: "peer" },
    { id: 5, label: "Finance", group: "peer" },
  ]);

  const edges = new vis.DataSet([
    { from: 1, to: 2 },
    { from: 1, to: 3 },
    { from: 2, to: 4 },
    { from: 3, to: 5 },
    { from: 4, to: 5 },
  ]);

  const network = new vis.Network(networkContainer, { nodes, edges }, {
    autoResize: true,
    physics: {
      enabled: true,
      stabilization: { iterations: 50 },
    },
    nodes: {
      shape: "dot",
      size: 18,
      borderWidth: 2,
      font: { color: "#f9fafb", size: 13 },
    },
    groups: {
      core: { color: { background: "#4b5563", border: "#f59e0b" } },
      peer: { color: { background: "#1f2937", border: "#64748b" } },
    },
    edges: {
      color: { color: "#4b5563" },
      width: 1.2,
      smooth: {
        type: "dynamic",
      },
    },
    interaction: {
      dragNodes: false,
      dragView: true,
      zoomView: true,
    },
  });

  function setGraphHealthy() {
    nodes.update({ id: 1, color: { background: "#4b5563", border: "#f59e0b" } });
    overlay.classList.add("hidden");
  }

  function setGraphAnomalous(containmentAction) {
    nodes.update({ id: 1, color: { background: "#f97373", border: "#fecaca" } });
    if (containmentAction === "isolate" || containmentAction === "revoke") {
      overlay.classList.remove("hidden");
    } else {
      overlay.classList.add("hidden");
    }
  }

  setGraphHealthy();

  // ---------------------------------------------------------------------------
  // Live Feed helpers
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

  function prependFeedEntry(incident) {
    if (!incident) return;

    const ts = new Date(incident.created_at || Date.now());
    const tsStr = ts.toLocaleTimeString([], { hour12: false });

    const wrapper = document.createElement("div");
    wrapper.className = "feed-entry";

    const meta = document.createElement("div");
    meta.className = "feed-meta";
    meta.textContent = `[${tsStr}] ${incident.incident_id} · ${
      incident.log?.attack_type || "anomaly"
    } · action=${incident.containment_action}`;

    const text = document.createElement("div");
    text.className = "feed-text";
    text.textContent = incident.play_by_play_narrative;

    wrapper.appendChild(meta);
    wrapper.appendChild(text);

    if (feedEl.firstChild) {
      feedEl.insertBefore(wrapper, feedEl.firstChild);
    } else {
      feedEl.appendChild(wrapper);
    }
  }

  // ---------------------------------------------------------------------------
  // Polling /api/state
  // ---------------------------------------------------------------------------
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
    incidentCountEl.textContent = String(count);
    roiEl.textContent = formatCurrency(state.total_roi_saved || 0);

    if (!incidents.length) {
      setGraphHealthy();
      yaraEl.textContent = "";
      undoBtn.disabled = true;
      latestIncidentId = null;
      return;
    }

    const latest = incidents[0];
    const containmentAction = latest.containment_action || "isolate";
    latestIncidentId = latest.incident_id;

    setGraphAnomalous(containmentAction);

    if (latest.generated_yara_rule) {
      yaraEl.textContent = latest.generated_yara_rule;
    }

    undoBtn.disabled = !latestIncidentId;

    if (!feedEl.dataset.lastIncident || feedEl.dataset.lastIncident !== latestIncidentId) {
      prependFeedEntry(latest);
      feedEl.dataset.lastIncident = latestIncidentId;
    }
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
      undoStatus.textContent = `Containment undone for ${
        body.incident?.incident_id || latestIncidentId
      }.`;
    } catch (err) {
      console.error("undo error", err);
      undoStatus.textContent = "Undo failed (network error).";
    }
  }

  undoBtn.addEventListener("click", undoContainment);

  // Kick off polling
  fetchState();
  setInterval(fetchState, 2000);
})();

