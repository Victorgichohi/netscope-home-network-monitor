let csrfToken = null;
let refreshTimer = null;
let setupMode = false;
const state = { devices: [], overview: null, timeline: [], activeView: "overview", diagnostic: null, system: null, speedtest: null, hours: 24 };
const viewMeta = {
  overview: ["NETWORK COMMAND CENTER", "Overview"], diagnose: ["ACTIVE PATH ANALYSIS", "Diagnostics"],
  devices: ["ASSET INVENTORY", "Devices"], traffic: ["FLOW ANALYTICS", "Traffic"],
  security: ["SIGNALS & EVENTS", "Security"], router: ["GATEWAY MANAGEMENT", "Router"],
};

async function api(path, options = {}) {
  const headers = { ...(options.body ? { "Content-Type": "application/json" } : {}), ...(options.headers || {}) };
  if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  const response = await fetch(path, { ...options, headers });
  if (response.status === 401 && path !== "/api/auth/login") {
    clearInterval(refreshTimer);
    document.querySelector("#app-shell").hidden = true;
    document.querySelector("#login-panel").hidden = false;
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || `Request failed (${response.status})`);
  }
  return response.json();
}

function escapeHtml(value) { const node = document.createElement("span"); node.textContent = value ?? ""; return node.innerHTML; }
function formatBytes(value) {
  if (!value) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(Math.floor(Math.log(Number(value)) / Math.log(1024)), units.length - 1);
  return `${(Number(value) / (1024 ** index)).toFixed(index ? 1 : 0)} ${units[index]}`;
}
function formatDate(value) { return value ? new Date(value).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "Never"; }
function formatAgo(value) {
  if (!value) return "Never";
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return "Just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}
function iconFor(category) { return ({ computer: "▰", phone: "▯", tablet: "▭", iot: "◆", media: "▶", network: "⌘", server: "▤" })[category] || "●"; }
function showToast(message) {
  const toast = document.querySelector("#toast"); toast.textContent = message; toast.hidden = false;
  window.setTimeout(() => { toast.hidden = true; }, 2800);
}

function showView(view) {
  state.activeView = view;
  document.querySelectorAll(".nav-item[data-view]").forEach(item => item.classList.toggle("active", item.dataset.view === view));
  document.querySelectorAll(".view").forEach(panel => panel.classList.toggle("active", panel.dataset.viewPanel === view));
  document.querySelector("#view-eyebrow").textContent = viewMeta[view][0];
  document.querySelector("#view-title").textContent = viewMeta[view][1];
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function chartSvg(rows) {
  if (rows.length > 240) {
    const groupSize = Math.ceil(rows.length / 240);
    rows = Array.from({ length: Math.ceil(rows.length / groupSize) }, (_, index) => {
      const group = rows.slice(index * groupSize, (index + 1) * groupSize);
      return {
        upload_bytes: group.reduce((sum, row) => sum + Number(row.upload_bytes), 0),
        download_bytes: group.reduce((sum, row) => sum + Number(row.download_bytes), 0),
      };
    });
  }
  if (!rows.length || !rows.some(row => Number(row.upload_bytes) || Number(row.download_bytes))) return `<div class="chart-empty">Traffic will appear here once capture is enabled.</div>`;
  const width = 900, height = 260, padding = 12;
  const max = Math.max(...rows.flatMap(row => [Number(row.upload_bytes), Number(row.download_bytes)]), 1);
  const points = key => rows.map((row, index) => {
    const x = padding + (index / Math.max(rows.length - 1, 1)) * (width - padding * 2);
    const y = height - padding - (Number(row[key]) / max) * (height - padding * 2);
    return [x, y];
  });
  const path = values => values.map(([x, y], index) => `${index ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const area = values => `${path(values)} L${values.at(-1)[0]},${height} L${values[0][0]},${height} Z`;
  const upload = points("upload_bytes"), download = points("download_bytes");
  return `<svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" aria-label="Traffic timeline">
    <defs><linearGradient id="upload-gradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#4ae4ff" stop-opacity=".24"/><stop offset="1" stop-color="#4ae4ff" stop-opacity="0"/></linearGradient><linearGradient id="download-gradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#a77bff" stop-opacity=".2"/><stop offset="1" stop-color="#a77bff" stop-opacity="0"/></linearGradient></defs>
    ${[.2,.4,.6,.8].map(ratio => `<line class="chart-grid" x1="0" y1="${height * ratio}" x2="${width}" y2="${height * ratio}"/>`).join("")}
    <path class="area-download" d="${area(download)}"/><path class="area-upload" d="${area(upload)}"/><path class="line-download" d="${path(download)}"/><path class="line-upload" d="${path(upload)}"/>
  </svg>`;
}

function renderSummary(overview) {
  const cards = [
    ["◉", overview.devices_online, "Devices online", `${overview.devices_total} known`, "#4ce6a6"],
    ["↓", formatBytes(overview.download_bytes_24h), "Downloaded", "Last 24 hours", "#a77bff"],
    ["↑", formatBytes(overview.upload_bytes_24h), "Uploaded", "Last 24 hours", "#4ae4ff"],
    ["◇", overview.unread_alerts, "Unread alerts", `${overview.new_devices_24h} new devices`, "#ffcc66"],
  ];
  document.querySelector("#summary-cards").innerHTML = cards.map(([icon, value, label, caption, color]) => `<article class="stat-card" style="--accent:${color}"><div class="stat-head"><span>${label}</span><i class="stat-icon">${icon}</i></div><div class="stat-value">${escapeHtml(String(value))}</div><div class="stat-caption">${caption}</div></article>`).join("");
  document.querySelector("#traffic-total").textContent = `${formatBytes(overview.bytes_24h)} observed`;
}

function rankList(rows) {
  if (!rows.length) return `<div class="empty">No device traffic has been observed yet.</div>`;
  const maximum = Math.max(...rows.map(item => Number(item.bytes)), 1);
  return rows.map(item => `<button class="rank-row text-button" data-device-id="${item.id}"><span class="rank-icon">${iconFor(item.category)}</span><span class="rank-label"><strong>${escapeHtml(item.hostname || item.ip_address)}</strong><small>${escapeHtml(item.ip_address)}</small></span><span class="meter"><i style="width:${Math.max(3, Number(item.bytes) / maximum * 100)}%"></i></span><span class="rank-value">${formatBytes(item.bytes)}</span></button>`).join("");
}
function destinationList(rows) {
  if (!rows.length) return `<div class="empty">No remote destinations yet.</div>`;
  return rows.map((item, index) => `<div class="destination-row"><strong>${String(index + 1).padStart(2, "0")} · ${escapeHtml(item.organization || item.destination)}<small>${escapeHtml(item.category || "Unclassified")} · ${escapeHtml(item.destination)}</small></strong><span>${formatBytes(item.bytes)}</span></div>`).join("");
}
function renderProtocols(rows) {
  if (!rows.length) { document.querySelector("#protocols").innerHTML = `<div class="empty">Waiting for protocol data.</div>`; return; }
  const total = rows.reduce((sum, item) => sum + Number(item.bytes), 0) || 1;
  const colors = ["#4ae4ff", "#a77bff", "#ffcc66", "#4ce6a6"];
  let cursor = 0;
  const stops = rows.map((item, index) => { const start = cursor; cursor += Number(item.bytes) / total * 100; return `${colors[index % colors.length]} ${start}% ${cursor}%`; }).join(",");
  document.querySelector("#protocols").innerHTML = `<div class="donut" style="background:radial-gradient(circle,#0c1a27 52%,transparent 54%),conic-gradient(${stops})"><strong>${formatBytes(total)}</strong></div><div class="protocol-legend">${rows.map((item, index) => `<div class="protocol-item"><i style="background:${colors[index % colors.length]}"></i><span>${escapeHtml(item.protocol)}</span><b>${Math.round(Number(item.bytes) / total * 100)}%</b></div>`).join("")}</div>`;
}

function renderTopology(data) {
  const container = document.querySelector("#topology");
  const nodes = data.nodes.slice(0, 13);
  const positions = { router: [50, 49] };
  nodes.filter(node => node.id !== "router").forEach((node, index, devices) => {
    const angle = (Math.PI * 2 * index / Math.max(devices.length, 1)) - Math.PI / 2;
    positions[node.id] = [50 + Math.cos(angle) * 39, 48 + Math.sin(angle) * 34];
  });
  const lines = data.links.filter(link => positions[link.target]).map(link => {
    const [x1, y1] = positions[link.source], [x2, y2] = positions[link.target];
    const length = Math.hypot(x2 - x1, y2 - y1), angle = Math.atan2(y2 - y1, x2 - x1) * 180 / Math.PI;
    return `<span class="topology-line" style="left:${x1}%;top:${y1}%;width:${length}%;transform:rotate(${angle}deg)"></span>`;
  }).join("");
  const markup = nodes.map(node => { const [x, y] = positions[node.id]; return `<button class="topology-node ${node.kind === "router" ? "router" : ""} ${node.online ? "" : "offline"} ${node.trust_status === "unknown" || node.trust_status === "review" ? "review" : ""}" style="left:${x}%;top:${y}%" ${node.device_id ? `data-device-id="${node.device_id}"` : ""}>${node.kind === "router" ? "⌘" : iconFor(node.kind)}<span class="node-label">${escapeHtml(node.label)}</span></button>`; }).join("");
  container.innerHTML = lines + markup;
}

function renderDevices() {
  const search = document.querySelector("#device-search").value.toLowerCase();
  const filter = document.querySelector("#device-filter").value;
  const devices = state.devices.filter(device => {
    const matchesSearch = [device.hostname, device.ip_address, device.mac_address, device.vendor].some(value => (value || "").toLowerCase().includes(search));
    const matchesFilter = filter === "all" || (filter === "online" && device.is_online) || device.trust_status === filter || (filter === "review" && device.trust_status === "unknown");
    return matchesSearch && matchesFilter;
  });
  document.querySelector("#device-rows").innerHTML = devices.length ? devices.map(device => `<tr data-device-id="${device.id}"><td><span class="status-dot ${device.is_online ? "online" : ""}"></span>${device.is_online ? "Online" : "Offline"}</td><td><div class="device-cell"><span class="device-icon">${iconFor(device.category)}</span><div><strong>${escapeHtml(device.hostname || "Unnamed device")}</strong><br><small class="muted">${escapeHtml(device.mac_address)}</small></div></div></td><td>${escapeHtml(device.ip_address)}</td><td class="category">${escapeHtml(device.category)}</td><td><span class="trust ${device.trust_status}">${escapeHtml(device.trust_status)}</span></td><td>${escapeHtml(device.vendor || "Unknown")}</td><td>${formatAgo(device.last_seen)}</td></tr>`).join("") : `<tr><td colspan="7"><div class="empty">No devices match this view.</div></td></tr>`;
}

function renderSecurity(summary, alerts) {
  const status = document.querySelector("#health-status");
  status.textContent = summary.status; status.className = `pill ${summary.status}`;
  document.querySelector("#security-score").textContent = summary.score;
  document.querySelector("#score-ring").style.setProperty("--score", summary.score);
  document.querySelector("#health-copy").textContent = summary.unread_alerts ? `${summary.unread_alerts} signals need your attention.` : "No unread security signals.";
  document.querySelector("#security-heading").textContent = summary.unread_alerts ? `${summary.unread_alerts} signals need attention` : "Everything looks calm";
  const badge = document.querySelector("#alert-badge"); badge.textContent = summary.unread_alerts; badge.hidden = !summary.unread_alerts;
  document.querySelector("#alerts").innerHTML = alerts.length ? alerts.map(alert => `<article class="alert-card ${alert.severity} ${alert.is_read ? "" : "unread"}"><div class="alert-symbol">${alert.severity === "critical" ? "!" : alert.severity === "warning" ? "△" : "i"}</div><div class="alert-copy"><h3>${escapeHtml(alert.title)}</h3><p>${escapeHtml(alert.message)}</p></div><div class="alert-meta"><time>${formatAgo(alert.last_seen)}</time>${alert.is_read ? `<span class="muted small-text">Read</span>` : `<button class="text-button" data-alert-id="${alert.id}">Mark read</button>`}</div></article>`).join("") : `<article class="panel empty">No security events have been recorded.</article>`;
}

function renderRouter(router, system) {
  document.querySelector("#router-status").innerHTML = `<p><span class="status-dot ${router.available ? "online" : ""}"></span>${router.available ? "Available" : "Control unavailable"}</p><p class="muted">${escapeHtml(router.host || "No adapter configured")}</p><p class="muted small-text">${escapeHtml(router.detail || router.adapter)}</p>`;
  document.querySelector("#reboot").disabled = !router.available;
  document.querySelector("#system-services").innerHTML = `<div class="service"><strong>Device discovery</strong><span>${system.discovery_scheduler === "running" ? "On" : "Off"}</span></div><div class="service"><strong>Traffic capture</strong><span>${escapeHtml(system.traffic_capture)}</span></div><div class="service"><strong>Network address</strong><span>${escapeHtml(system.network.local_ip || "Unknown")}</span></div><div class="service"><strong>Router address</strong><span>${escapeHtml(system.network.gateway_ip || "Unknown")}</span></div>`;
  document.querySelector("#router-visibility-title").textContent = `${system.visibility_label} visibility`;
  document.querySelector("#router-visibility-copy").textContent = system.visibility_detail;
  const dot = document.querySelector("#capture-dot"); dot.className = `live-dot ${system.traffic_capture === "error" ? "error" : system.traffic_capture === "running" ? "" : "disabled"}`;
  document.querySelector("#capture-label").textContent = system.visibility_label;
  document.querySelector("#capture-subtitle").textContent = system.traffic_capture_error || (system.traffic_capture === "running" ? "Traffic view active" : "Device discovery active");
  const banner = document.querySelector("#visibility-banner");
  banner.className = `visibility-banner ${system.visibility}`;
  banner.querySelector("strong").textContent = `Traffic view: ${system.visibility_label}`;
  banner.querySelector("p").textContent = system.visibility_detail;
}

function checkCard(icon, title, check, healthyCopy) {
  const status = check?.status || "unknown";
  const value = check?.latency_ms == null ? (status === "ok" ? "Connected" : "Not checked") : `${check.latency_ms} ms`;
  const label = status === "ok" ? healthyCopy : status === "failed" ? "Needs attention" : "Unavailable";
  return `<article class="check-card ${status}"><div class="check-icon">${icon}</div><div><span>${escapeHtml(title)}</span><strong>${escapeHtml(value)}</strong><small>${escapeHtml(label)}</small></div><i>${status === "ok" ? "✓" : status === "failed" ? "!" : "—"}</i></article>`;
}

function renderDiagnostic(diagnostic, system) {
  const home = document.querySelector("#home-diagnostic");
  const hero = document.querySelector("#diagnostic-hero");
  const network = diagnostic?.network || system.network;
  if (!diagnostic) {
    home.className = "welcome-card technical-strip panel diagnostic-unknown";
    hero.className = "diagnostic-hero panel diagnostic-unknown";
    document.querySelector("#diagnostic-checks").innerHTML = ["Router", "Internet", "Website names"].map((title, index) => checkCard(["⌂", "◎", "Aa"][index], title, null, "Working")).join("");
    document.querySelector("#connection-details").innerHTML = connectionDetails(network);
    return;
  }
  const status = diagnostic.status;
  const symbol = status === "healthy" ? "✓" : status === "attention" ? "!" : "×";
  home.className = `welcome-card technical-strip panel diagnostic-${status}`;
  hero.className = `diagnostic-hero panel diagnostic-${status}`;
  document.querySelector("#home-diagnostic-title").textContent = diagnostic.summary;
  document.querySelector("#home-diagnostic-copy").textContent = diagnostic.recommendations[0] || "Open the detailed check for more information.";
  document.querySelector("#home-health-symbol").textContent = symbol;
  document.querySelector("#diagnostic-title").textContent = diagnostic.summary;
  document.querySelector("#diagnostic-summary").textContent = diagnostic.recommendations[0] || "Your connection check has finished.";
  document.querySelector("#diagnostic-time").textContent = `Last checked ${formatAgo(diagnostic.completed_at || diagnostic.created_at)}`;
  document.querySelector("#diagnostic-checks").innerHTML = [
    checkCard("⌂", "Your router", diagnostic.checks.router, "Wi-Fi path responds"),
    checkCard("◎", "The internet", diagnostic.checks.internet, "Internet reachable"),
    checkCard("Aa", "Website names", diagnostic.checks.dns, "DNS is working"),
  ].join("");
  document.querySelector("#recommendations").innerHTML = diagnostic.recommendations.map((item, index) => `<div class="recommendation"><span>${index + 1}</span><p>${escapeHtml(item)}</p></div>`).join("") || `<div class="empty">No action is needed.</div>`;
  document.querySelector("#connection-details").innerHTML = connectionDetails(network, diagnostic.checks.router.packet_loss_percent);
}

function speedSparkline(rows) {
  const values = [...rows].reverse().map(item => Number(item.download_mbps)).filter(Number.isFinite);
  if (!values.length) return `<div class="spark-empty">Awaiting baseline</div>`;
  const width = 260, height = 62, maximum = Math.max(...values, 1), minimum = Math.min(...values, 0);
  const range = Math.max(maximum - minimum, 1);
  const points = values.map((value, index) => {
    const x = 3 + index / Math.max(values.length - 1, 1) * (width - 6);
    const y = height - 5 - (value - minimum) / range * (height - 12);
    return [x, y];
  });
  if (points.length === 1) points.push([width - 3, points[0][1]]);
  const line = points.map(([x, y], index) => `${index ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const area = `${line} L${points.at(-1)[0]},${height} L${points[0][0]},${height} Z`;
  return `<svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" aria-label="Download speed history"><defs><linearGradient id="speed-gradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#4ae4ff" stop-opacity=".3"/><stop offset="1" stop-color="#4ae4ff" stop-opacity="0"/></linearGradient></defs><path class="speed-area" d="${area}"/><path class="speed-line" d="${line}"/></svg>`;
}

function renderSpeedtest(latest, history, system) {
  state.speedtest = latest;
  document.querySelector("#speed-download").textContent = latest ? Number(latest.download_mbps).toFixed(1) : "—";
  document.querySelector("#speed-upload").textContent = latest ? Number(latest.upload_mbps).toFixed(1) : "—";
  document.querySelector("#speed-latency").textContent = latest ? Number(latest.latency_ms).toFixed(0) : "—";
  document.querySelector("#speed-jitter").textContent = latest ? Number(latest.jitter_ms).toFixed(1) : "—";
  document.querySelector("#speed-tested-at").textContent = latest ? `${latest.provider} · ${formatAgo(latest.completed_at)}` : "No test recorded · approximately 12 MB per run";
  document.querySelector("#speed-sparkline").innerHTML = speedSparkline(history);
  document.querySelectorAll(".run-speedtest").forEach(button => { button.disabled = system.speedtest !== "available"; });
}

function renderQuality(uptime) {
  const values = [
    [uptime.availability_percent == null ? "—" : `${uptime.availability_percent}%`, "ISP availability", `${uptime.sample_count} probes / 7 days`],
    [uptime.average_latency_ms == null ? "—" : `${uptime.average_latency_ms} ms`, "Average latency", "External path response"],
    [String(uptime.outage_count), "Detected outages", "Consecutive failed probes"],
    [uptime.maximum_packet_loss_percent == null ? "—" : `${uptime.maximum_packet_loss_percent}%`, "Maximum loss", "Gateway probe loss"],
  ];
  document.querySelector("#quality-stats").innerHTML = values.map(([value, label, detail]) => `<article class="quality-stat"><span>${label}</span><strong>${value}</strong><small>${detail}</small></article>`).join("");
}

function connectionDetails(network, packetLoss = null) {
  return `<div class="service"><strong>This device</strong><span>${escapeHtml(network.local_ip || "Unknown")}</span></div><div class="service"><strong>Your router</strong><span>${escapeHtml(network.gateway_ip || "Unknown")}</span></div><div class="service"><strong>Network range</strong><span>${escapeHtml(network.subnet || "Unknown")}</span></div><div class="service"><strong>Wi-Fi adapter</strong><span>${escapeHtml(network.interface || "Automatic")}</span></div>${packetLoss == null ? "" : `<div class="service"><strong>Packet loss to router</strong><span>${packetLoss}%</span></div>`}`;
}

function renderHousehold(analytics) {
  const change = analytics.traffic_change_percent;
  const changeCopy = change == null ? "Building a comparison" : `${Math.abs(change)}% ${change >= 0 ? "more" : "less"} than yesterday`;
  const peak = analytics.peak_hour == null ? "Learning your routine" : `${String(analytics.peak_hour).padStart(2, "0")}:00–${String((analytics.peak_hour + 1) % 24).padStart(2, "0")}:00`;
  document.querySelector("#household-insights").innerHTML = `<div class="insight"><span>✓</span><div><strong>${analytics.recognized_percent}% recognized</strong><small>${analytics.recognized_devices} of ${analytics.total_devices} devices labeled</small></div></div><div class="insight"><span>↕</span><div><strong>${changeCopy}</strong><small>${formatBytes(analytics.traffic_bytes_24h)} observed today</small></div></div><div class="insight"><span>◷</span><div><strong>${peak}</strong><small>Usually your busiest hour</small></div></div><div class="insight"><span>＋</span><div><strong>${analytics.new_devices_7d} new this week</strong><small>Review anything you do not recognize</small></div></div>`;
}

function renderActivity(items) {
  document.querySelector("#activity-feed").innerHTML = items.length ? items.slice(0, 6).map(item => `<div class="activity-item"><span class="activity-symbol ${item.severity}">${item.type === "scan" ? "↻" : item.severity === "warning" ? "!" : "•"}</span><div><strong>${escapeHtml(item.title)}</strong><small>${escapeHtml(item.detail)}</small></div><time>${formatAgo(item.created_at)}</time></div>`).join("") : `<div class="empty">Nothing has changed yet.</div>`;
}

async function loadDashboard() {
  const hours = state.hours;
  const [overview, devices, destinations, timeline, topDevices, protocols, topology, security, alerts, router, system, diagnostic, analytics, activity, speedtest, speedHistory, uptime] = await Promise.all([
    api("/api/overview"), api("/api/devices"), api(`/api/traffic/top-destinations?hours=${hours}`), api(`/api/traffic/timeline?hours=${hours}`),
    api(`/api/traffic/top-devices?hours=${hours}`), api(`/api/traffic/protocols?hours=${hours}`), api("/api/topology"), api("/api/security/summary"),
    api("/api/alerts"), api("/api/router/status"), api("/api/system/status"), api("/api/diagnostics/latest"),
    api("/api/analytics/household"), api("/api/activity"), api("/api/speedtest/latest"), api("/api/speedtest/history"), api("/api/diagnostics/uptime"),
  ]);
  Object.assign(state, { overview, devices, timeline, diagnostic, system, speedtest });
  renderSummary(overview); renderDevices(); renderProtocols(protocols); renderTopology(topology); renderSecurity(security, alerts); renderRouter(router, system);
  renderDiagnostic(diagnostic, system); renderHousehold(analytics); renderActivity(activity); renderSpeedtest(speedtest, speedHistory, system); renderQuality(uptime);
  const chart = chartSvg(timeline); document.querySelector("#traffic-chart").innerHTML = chart; document.querySelector("#traffic-chart-large").innerHTML = chart;
  document.querySelector("#traffic-window-label").textContent = hours === 1 ? "Last hour" : hours === 24 ? "Last 24 hours" : "Last 7 days";
  document.querySelector("#traffic-total").textContent = `${formatBytes(timeline.reduce((sum, row) => sum + Number(row.bytes), 0))} observed`;
  const ranks = rankList(topDevices); document.querySelector("#top-devices").innerHTML = ranks; document.querySelector("#traffic-devices").innerHTML = ranks;
  const destinationMarkup = destinationList(destinations); document.querySelector("#top-destinations").innerHTML = destinationMarkup; document.querySelector("#traffic-destinations").innerHTML = destinationMarkup;
  document.querySelector("#last-updated").textContent = `Updated ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
}

async function openDevice(deviceId) {
  const detail = await api(`/api/devices/${deviceId}/detail`), device = detail.device, traffic = detail.traffic;
  document.querySelector("#device-detail").innerHTML = `<p class="eyebrow">DEVICE PROFILE</p><div class="detail-identity"><span class="device-icon">${iconFor(device.category)}</span><div><h2>${escapeHtml(device.hostname || "Unnamed device")}</h2><span class="muted">${escapeHtml(device.ip_address)} · ${escapeHtml(device.vendor || "Unknown vendor")}</span></div></div><div class="detail-grid"><div class="detail-stat"><strong>${formatBytes(traffic.download_bytes)}</strong><span>DOWNLOADED</span></div><div class="detail-stat"><strong>${formatBytes(traffic.upload_bytes)}</strong><span>UPLOADED</span></div><div class="detail-stat"><strong>${Number(traffic.packets).toLocaleString()}</strong><span>PACKETS</span></div><div class="detail-stat"><strong>${Number(traffic.destinations).toLocaleString()}</strong><span>DESTINATIONS</span></div></div><div class="drawer-section"><p class="eyebrow">IDENTITY</p><div class="detail-form"><label>Display name<input id="detail-hostname" value="${escapeHtml(device.hostname || "")}"></label><label>Category<select id="detail-category">${["unknown","computer","phone","tablet","iot","media","network","server"].map(value => `<option value="${value}" ${value === device.category ? "selected" : ""}>${value}</option>`).join("")}</select></label><label>Trust status<select id="detail-trust">${["unknown","trusted","guest","review","blocked"].map(value => `<option value="${value}" ${value === device.trust_status ? "selected" : ""}>${value}</option>`).join("")}</select></label><label>Notes<input id="detail-notes" value="${escapeHtml(device.notes || "")}"></label><button id="save-device" class="button primary full" data-device-id="${device.id}">Save profile <span>→</span></button></div></div><div class="drawer-section"><p class="muted small-text">MAC ${escapeHtml(device.mac_address)}<br>First seen ${formatDate(device.first_seen)}<br>Last seen ${formatDate(device.last_seen)}</p></div>`;
  document.querySelector("#device-drawer").classList.add("open"); document.querySelector("#device-drawer").setAttribute("aria-hidden", "false"); document.querySelector("#drawer-backdrop").hidden = false;
}
function closeDrawer() { document.querySelector("#device-drawer").classList.remove("open"); document.querySelector("#device-drawer").setAttribute("aria-hidden", "true"); document.querySelector("#drawer-backdrop").hidden = true; }

async function authenticate() {
  try { const me = await api("/api/auth/me"); csrfToken = me.csrf_token; document.querySelector("#login-panel").hidden = true; document.querySelector("#app-shell").hidden = false; await loadDashboard(); refreshTimer = window.setInterval(() => loadDashboard().catch(() => {}), 15000); }
  catch { const setup = await api("/api/auth/setup-status").catch(() => ({ required: false })); setupMode = setup.required; if (setupMode) { document.querySelector("#login-eyebrow").textContent = "WELCOME TO NETSCOPE"; document.querySelector("#login-title").innerHTML = "Set up your<br>home network."; document.querySelector("#login-copy").textContent = "Choose a username and a password with at least 12 characters. This first step is only available on this computer."; document.querySelector("#login-submit").innerHTML = `Create my dashboard <span>→</span>`; document.querySelector("#password").setAttribute("minlength", "12"); } document.querySelector("#login-panel").hidden = false; }
}

document.querySelector("#login-form").addEventListener("submit", async event => { event.preventDefault(); try { const result = await api(setupMode ? "/api/auth/setup" : "/api/auth/login", { method: "POST", body: JSON.stringify({ username: document.querySelector("#username").value, password: document.querySelector("#password").value }) }); csrfToken = result.csrf_token; setupMode = false; document.querySelector("#login-panel").hidden = true; document.querySelector("#app-shell").hidden = false; await loadDashboard(); refreshTimer = window.setInterval(() => loadDashboard().catch(() => {}), 15000); } catch (error) { document.querySelector("#login-error").textContent = error.message; } });
document.querySelector("#main-nav").addEventListener("click", event => { const item = event.target.closest("[data-view]"); if (item) showView(item.dataset.view); });
document.addEventListener("click", event => { const go = event.target.closest("[data-go]"); if (go) showView(go.dataset.go); const device = event.target.closest("[data-device-id]"); if (device && !device.matches("#save-device")) openDevice(device.dataset.deviceId).catch(error => showToast(error.message)); const alert = event.target.closest("[data-alert-id]"); if (alert) api(`/api/alerts/${alert.dataset.alertId}/read`, { method: "POST" }).then(loadDashboard).catch(error => showToast(error.message)); });
document.addEventListener("click", async event => { const button = event.target.closest(".run-diagnostic"); if (!button) return; document.querySelectorAll(".run-diagnostic").forEach(item => { item.disabled = true; item.textContent = "Probing…"; }); try { const result = await api("/api/diagnostics/run", { method: "POST" }); state.diagnostic = result; renderDiagnostic(result, state.system); showToast(result.summary); } catch (error) { showToast(error.message); } finally { document.querySelectorAll(".run-diagnostic").forEach(item => { item.disabled = false; item.innerHTML = `Run diagnostics <span>→</span>`; }); } });
document.addEventListener("click", async event => { const button = event.target.closest(".run-speedtest"); if (!button) return; document.querySelectorAll(".run-speedtest").forEach(item => { item.disabled = true; item.textContent = "…"; }); document.querySelector("#speed-tested-at").textContent = "Testing latency, download, and upload…"; try { const result = await api("/api/speedtest/run", { method: "POST" }); const history = await api("/api/speedtest/history"); renderSpeedtest(result, history, state.system); showToast(`Speed test complete: ${Number(result.download_mbps).toFixed(1)} Mbps down`); } catch (error) { document.querySelector("#speed-tested-at").textContent = error.message; showToast(error.message); } finally { document.querySelectorAll(".run-speedtest").forEach(item => { item.disabled = state.system.speedtest !== "available"; item.textContent = "↻"; }); } });
document.querySelector("#device-search").addEventListener("input", renderDevices); document.querySelector("#device-filter").addEventListener("change", renderDevices);
document.querySelector("#time-range").addEventListener("change", async event => { state.hours = Number(event.target.value); try { await loadDashboard(); } catch (error) { showToast(error.message); } });
document.querySelector("#device-detail").addEventListener("click", async event => { const button = event.target.closest("#save-device"); if (!button) return; await api(`/api/devices/${button.dataset.deviceId}`, { method: "PATCH", body: JSON.stringify({ hostname: document.querySelector("#detail-hostname").value || null, category: document.querySelector("#detail-category").value, trust_status: document.querySelector("#detail-trust").value, notes: document.querySelector("#detail-notes").value || null }) }); showToast("Device profile saved"); closeDrawer(); await loadDashboard(); });
document.querySelector("#close-drawer").addEventListener("click", closeDrawer); document.querySelector("#drawer-backdrop").addEventListener("click", closeDrawer);
document.querySelector("#read-all").addEventListener("click", async () => { await api("/api/alerts/actions/read-all", { method: "POST" }); showToast("All alerts marked as read"); await loadDashboard(); });
document.querySelector("#scan").addEventListener("click", async event => { const button = event.currentTarget; button.disabled = true; button.textContent = "Looking…"; try { const result = await api("/api/discovery/scan", { method: "POST" }); showToast(`${result.devices_found} devices found`); await loadDashboard(); } catch (error) { showToast(error.message); } finally { button.disabled = false; button.textContent = "↻ Find devices"; } });
document.querySelector("#logout").addEventListener("click", async () => { await api("/api/auth/logout", { method: "POST" }); location.reload(); });
document.querySelector("#reboot").addEventListener("click", () => document.querySelector("#reboot-dialog").showModal());
document.querySelector("#confirm-reboot").addEventListener("click", async event => { event.preventDefault(); try { await api("/api/router/reboot", { method: "POST", body: JSON.stringify({ confirmation: document.querySelector("#reboot-confirmation").value }) }); document.querySelector("#reboot-dialog").close(); showToast("Reboot command accepted"); } catch (error) { showToast(error.message); } });
let installPrompt = null;
window.addEventListener("beforeinstallprompt", event => { event.preventDefault(); installPrompt = event; document.querySelector("#install-app").hidden = false; });
document.querySelector("#install-app").addEventListener("click", async () => { if (!installPrompt) return; await installPrompt.prompt(); installPrompt = null; document.querySelector("#install-app").hidden = true; });
if ("serviceWorker" in navigator) navigator.serviceWorker.register("/service-worker.js").catch(() => {});
authenticate();
