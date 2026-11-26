"use strict";

const element = (id) => document.getElementById(id);
const risks = { low: "Bajo", medium: "Medio", high: "Alto" };
const statuses = {
  alert: "Alerta",
  pending_containment: "Contención pendiente",
  pending_verification: "Verificación pendiente",
  contained: "Bloqueo verificado",
  restoration_pending: "Restauración pendiente",
  restored: "Acceso restaurado",
  review: "En revisión",
};
const recommendations = { review: "Revisar", temporary_block: "Bloqueo temporal" };
const categories = {
  possible_brute_force: "Posible fuerza bruta",
  possible_password_spraying: "Posible password spraying",
};
const eventTypes = { failed_login: "Autenticación fallida", successful_login: "Autenticación correcta" };
const auditActions = {
  block_created: "Bloqueo aplicado",
  block_verified: "Rechazo verificado",
  block_expired: "Bloqueo vencido",
  block_released: "Restauración solicitada",
  access_restored: "Acceso restaurado y verificado",
  restoration_verified: "Restauración verificada",
  block_restored: "Restauración verificada",
  ai_decision: "Decisión del analista IA",
  containment_skipped: "Contención omitida por la política",
};
const actors = { admin: "Administrador", system: "Sistema", ai: "Analista IA", protected_app: "Servicio protegido" };
const numberFormat = new Intl.NumberFormat("es-PE");
const dateFormat = new Intl.DateTimeFormat("es-PE", { dateStyle: "medium", timeStyle: "medium" });
const clockFormat = new Intl.DateTimeFormat("es-PE", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const refreshIntervalMs = 8000;
const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
let session;

function node(tag, value, className) {
  const result = document.createElement(tag);
  result.textContent = value ?? "";
  if (className) result.className = className;
  return result;
}

function formatTime(value) {
  const date = new Date(value);
  return value && !Number.isNaN(date.getTime()) ? dateFormat.format(date) : "—";
}

function relativeTime(value) {
  const date = new Date(value);
  if (!value || Number.isNaN(date.getTime())) return "—";
  const seconds = Math.round((Date.now() - date.getTime()) / 1000);
  if (seconds < 5) return "ahora mismo";
  if (seconds < 60) return `hace ${seconds} s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `hace ${minutes} min`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `hace ${hours} h`;
  return dateFormat.format(date);
}

function setRelativeTime(target, value) {
  target.dataset.relativeTs = value ?? "";
  target.textContent = value ? relativeTime(value) : "—";
  if (target.tagName === "TIME") target.dateTime = value ?? "";
  target.title = value ? formatTime(value) : "";
}

function updateRelativeTimes() {
  for (const target of document.querySelectorAll("[data-relative-ts]")) {
    const value = target.dataset.relativeTs;
    if (value) target.textContent = relativeTime(value);
  }
}

function track(activeSession, name) {
  if (!activeSession[name]) activeSession[name] = { seen: new Set(), primed: false };
  return activeSession[name];
}

function isNewEntry(tracker, key, target) {
  const fresh = tracker.primed && !tracker.seen.has(key);
  tracker.seen.add(key);
  if (fresh) target.classList.add("flash");
  return fresh;
}

function animateMetric(id, value) {
  const target = element(id);
  const goal = Number(value) || 0;
  const start = Number(target.dataset.value ?? "0");
  target.dataset.value = String(goal);
  if (reduceMotion || start === goal) {
    target.textContent = numberFormat.format(goal);
    return;
  }
  const began = performance.now();
  const duration = 700;
  function frame(now) {
    const progress = Math.min(1, (now - began) / duration);
    const eased = 1 - Math.pow(1 - progress, 3);
    target.textContent = numberFormat.format(Math.round(start + (goal - start) * eased));
    if (progress < 1) requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
}

function displayConnection(state, label) {
  const indicator = element("connection-state");
  indicator.dataset.state = state;
  indicator.textContent = label;
}

function displayMessage(id, message) {
  const target = element(id);
  target.textContent = message;
  target.hidden = !message;
}

async function request(path, activeSession, signal = activeSession.controller.signal, method = "GET") {
  let response;
  try {
    response = await fetch(path, {
      headers: { Authorization: `Bearer ${activeSession.token}` },
      signal: AbortSignal.any([signal, AbortSignal.timeout(6000)]),
      cache: "no-store",
      method,
    });
  } catch (error) {
    if (signal.aborted) throw error;
    throw new Error("No se pudo conectar con la API de SentinelCore.");
  }
  if (response.status === 401 || response.status === 403) {
    const error = new Error("El token de administrador no fue aceptado.");
    error.unauthorized = true;
    throw error;
  }
  if (response.status === 404) throw new Error("El recurso solicitado ya no está disponible.");
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(typeof body.detail === "string" ? body.detail : `La API respondió con un error (${response.status}).`);
  }
  return response;
}

async function api(path, activeSession, signal = activeSession.controller.signal, method = "GET") {
  const response = await request(path, activeSession, signal, method);
  return response.json();
}

function riskBadge(severity) {
  const badge = node("span", risks[severity] ?? severity, "badge");
  badge.dataset.risk = severity;
  return badge;
}

function statusBadge(status, label = statuses[status] ?? status) {
  const badge = node("span", label, "status");
  badge.dataset.state = status;
  return badge;
}

function renderSystem(system) {
  element("system-analysis").textContent = system.ai_enabled ? `IA · ${system.ai_model}` : "Motor de reglas";
  element("system-containment").textContent = system.auto_containment ? "Activada" : "Desactivada";
  element("system-rule").textContent = `${system.high_threshold} fallos / ${system.window_seconds} s`;
  element("system-duration").textContent = `${system.block_seconds} segundos`;
  const fallback = new URL(window.location.href);
  fallback.port = "8001";
  fallback.pathname = "/";
  fallback.search = "";
  fallback.hash = "";
  const labUrl = new URL(system.protected_app_url || fallback.href, window.location.href);
  element("lab-link").href = ["http:", "https:"].includes(labUrl.protocol) ? labUrl.href : fallback.href;
}

function highlightSelection(activeSession) {
  for (const button of element("incident-rows").querySelectorAll("button")) {
    const selected = button.dataset.incident === activeSession.selected;
    button.closest("tr").classList.toggle("selected", selected);
    button.setAttribute("aria-pressed", String(selected));
  }
}

function renderIncidents(data, activeSession) {
  const rows = element("incident-rows");
  const previouslyFocused = rows.contains(document.activeElement) ? document.activeElement.dataset.incident : undefined;
  const fragment = document.createDocumentFragment();
  const tracker = track(activeSession, "incidentTracker");

  for (const incident of data.items) {
    const row = document.createElement("tr");
    const button = node("button", incident.id, "incident-link mono");
    button.type = "button";
    button.dataset.incident = incident.id;
    button.setAttribute("aria-controls", "evidence-content");
    const idCell = document.createElement("td");
    const riskCell = document.createElement("td");
    const statusCell = document.createElement("td");
    idCell.append(
      button,
      node("span", categories[incident.category] ?? incident.category, "cell-subtitle"),
      node("span", incident.source_ip, "cell-subtitle mono"),
    );
    riskCell.append(riskBadge(incident.severity));
    statusCell.append(statusBadge(incident.status));
    row.append(idCell, riskCell, statusCell, node("td", formatTime(incident.last_seen), "cell-date mono"));
    isNewEntry(tracker, `${incident.id}|${incident.event_count}|${incident.status}`, row);
    fragment.append(row);
  }

  tracker.primed = true;
  rows.replaceChildren(fragment);
  highlightSelection(activeSession);
  if (previouslyFocused) {
    const replacement = Array.from(rows.querySelectorAll("button")).find((button) => button.dataset.incident === previouslyFocused);
    replacement?.focus({ preventScroll: true });
  }
  element("incident-count").textContent = data.total > data.items.length
    ? `${numberFormat.format(data.items.length)} de ${numberFormat.format(data.total)}`
    : numberFormat.format(data.total);
  element("incident-empty").hidden = data.items.length > 0;
  element("incident-table").hidden = data.items.length === 0;
}

function renderDetail(incident) {
  const title = node("h3", incident.id, "evidence-name mono");
  title.append(riskBadge(incident.severity));
  const facts = node("dl", "", "evidence-facts");
  const fields = [
    ["Categoría", categories[incident.category] ?? incident.category],
    ["Origen", incident.source_ip],
    ["Servicio", incident.target],
    ["Estado", statuses[incident.status] ?? incident.status],
    ["Fallos", incident.event_count],
    ["Primer evento", formatTime(incident.first_seen)],
    ["Último evento", formatTime(incident.last_seen)],
    ["Acción sugerida", recommendations[incident.recommended_action] ?? incident.recommended_action],
  ];
  for (const [label, value] of fields) facts.append(node("dt", label), node("dd", value ?? "—"));

  const eventTitle = node("h3", "Eventos asociados", "evidence-events-title");
  const events = node("ol", "", "event-list");
  for (const event of incident.events) {
    const item = node("li", eventTypes[event.event_type] ?? event.event_type);
    const timestamp = node("time", formatTime(event.timestamp));
    timestamp.dateTime = event.timestamp;
    if (event.metadata?.username) {
      item.append(node("span", `Usuario: ${event.metadata.username}`, "event-user"));
    }
    item.append(timestamp);
    events.append(item);
  }
  const content = element("evidence-content");
  content.replaceChildren(
    title,
    facts,
    node("p", incident.reason || "La API no ha registrado un motivo para este incidente.", "evidence-note"),
    eventTitle,
    incident.events.length ? events : node("p", "No hay eventos asociados."),
  );
  content.hidden = false;
  const download = element("download-evidence");
  download.dataset.incident = incident.id;
  download.hidden = false;
  download.disabled = Boolean(session?.exporting);
  displayMessage("evidence-state", "");
}

function renderBlocks(blocks, activeSession) {
  if (activeSession.releaseFeedbackId) {
    const released = blocks.find((block) => block.id === activeSession.releaseFeedbackId);
    const newActiveBlock = released && blocks.some((block) => (
      block.status === "active" && block.source_ip === released.source_ip && block.target === released.target
    ));
    if (!released || released.restored_at || newActiveBlock) {
      activeSession.releaseFeedbackId = undefined;
      displayMessage("block-feedback", "");
    }
  }
  activeSession.blocks = blocks;
  const fragment = document.createDocumentFragment();
  const tracker = track(activeSession, "blockTracker");
  for (const block of blocks) {
    const row = document.createElement("tr");
    const source = node("td", block.source_ip, "mono");
    source.append(node("span", block.target, "cell-subtitle"));
    const status = document.createElement("td");
    let label;
    let state;
    if (block.status === "active") {
      label = block.verified_at ? "Bloqueo verificado" : "Verificación pendiente";
      state = block.verified_at ? "verified" : "pending_verification";
    } else {
      label = block.restored_at ? "Acceso restaurado" : "Restauración pendiente";
      state = block.restored_at ? "restored" : "restoration_pending";
    }
    status.append(statusBadge(state, label));
    status.append(node("span", block.status === "expired" ? "Plazo vencido" : block.status === "released" ? "Liberado manualmente" : "Activo", "cell-subtitle"));
    const proof = document.createElement("td");
    if (block.restored_at) {
      proof.append(node("span", `Acceso · ${formatTime(block.restored_at)}`, "cell-date"));
    } else if (block.verified_at) {
      proof.append(node("span", `Rechazo · ${formatTime(block.verified_at)}`, "cell-date"));
    } else {
      proof.append(node("span", "Esperando solicitud del origen", "cell-subtitle"));
    }
    const action = document.createElement("td");
    if (block.status === "active") {
      const button = node("button", "Restaurar acceso", "button button-secondary block-action");
      button.type = "button";
      button.dataset.release = block.id;
      button.setAttribute("aria-label", `Restaurar acceso de ${block.source_ip}`);
      button.disabled = Boolean(activeSession.releasing);
      action.append(button);
    } else {
      action.append(node("span", block.restored_at ? "Comprobado" : "Pendiente de comprobación", "cell-subtitle"));
    }
    row.append(source, status, node("td", formatTime(block.expires_at), "cell-date mono"), proof, action);
    isNewEntry(tracker, `${block.id}|${block.status}|${block.verified_at ?? ""}|${block.restored_at ?? ""}`, row);
    fragment.append(row);
  }
  tracker.primed = true;
  element("block-rows").replaceChildren(fragment);
  element("blocks-empty").hidden = blocks.length > 0;
  element("blocks-table").hidden = blocks.length === 0;
  element("blocks-count").textContent = `${numberFormat.format(blocks.filter((block) => block.status === "active").length)} activos`;
  if (activeSession.pendingRelease && !blocks.some((block) => block.id === activeSession.pendingRelease && block.status === "active")) {
    activeSession.pendingRelease = undefined;
    element("release-confirmation").hidden = true;
  }
}

function renderAudit(entries, activeSession) {
  const fragment = document.createDocumentFragment();
  const tracker = track(activeSession, "auditTracker");
  for (const entry of entries) {
    const item = document.createElement("li");
    const timestamp = node("time", "");
    setRelativeTime(timestamp, entry.timestamp);
    const content = document.createElement("div");
    content.append(node("p", auditActions[entry.action] ?? entry.action, "audit-action"));
    if (entry.detail) content.append(node("p", entry.detail, "audit-detail"));
    content.append(node("p", [actors[entry.actor] ?? entry.actor, entry.source_ip, entry.incident_id].filter(Boolean).join(" · "), "audit-context mono"));
    item.append(timestamp, content);
    isNewEntry(tracker, `${entry.timestamp}|${entry.action}|${entry.source_ip ?? ""}|${entry.incident_id ?? ""}`, item);
    fragment.append(item);
  }
  tracker.primed = true;
  element("audit-list").replaceChildren(fragment);
  element("audit-empty").hidden = entries.length > 0;
  element("audit-count").textContent = `${numberFormat.format(entries.length)} registros recientes`;
}

function renderThreat(incidents, blocks) {
  const items = incidents.items ?? [];
  const high = items.filter((incident) => incident.severity === "high").length;
  const unresolvedHigh = items.filter((incident) => incident.severity === "high" && incident.status !== "restored").length;
  const activeBlocks = blocks.filter((block) => block.status === "active").length;
  const last = items.reduce((latest, incident) => {
    const time = new Date(incident.last_seen).getTime();
    return Number.isNaN(time) ? latest : Math.max(latest, time);
  }, 0);
  let level = "calm";
  let state = "Sistema en calma";
  let detail = "Sin incidentes registrados. El laboratorio está preparado.";
  if (activeBlocks > 0 || unresolvedHigh > 0) {
    level = "danger";
    state = "Amenaza activa";
    detail = `${numberFormat.format(unresolvedHigh)} incidente(s) de riesgo alto sin resolver · ${numberFormat.format(activeBlocks)} bloqueo(s) activo(s).`;
  } else if (items.length > 0) {
    level = "watch";
    state = "Vigilancia activa";
    detail = `${numberFormat.format(items.length)} incidente(s) registrado(s), sin riesgo alto activo.`;
  }
  element("threat").dataset.level = level;
  element("threat-state").textContent = state;
  element("threat-detail").textContent = detail;
  element("threat-high").textContent = numberFormat.format(high);
  element("threat-blocks").textContent = numberFormat.format(activeBlocks);
  setRelativeTime(element("threat-last"), last ? new Date(last).toISOString() : "");
}

function renderRiskDonut(incidents) {
  const counts = { high: 0, medium: 0, low: 0 };
  for (const incident of incidents.items ?? []) {
    if (counts[incident.severity] !== undefined) counts[incident.severity] += 1;
  }
  const total = counts.high + counts.medium + counts.low;
  element("risk-total").textContent = numberFormat.format(total);
  element("risk-high").textContent = numberFormat.format(counts.high);
  element("risk-medium").textContent = numberFormat.format(counts.medium);
  element("risk-low").textContent = numberFormat.format(counts.low);
  const donut = element("risk-donut");
  if (total === 0) {
    donut.style.background = "conic-gradient(#25374a 0% 100%)";
    return;
  }
  const highEnd = (counts.high / total) * 100;
  const mediumEnd = ((counts.high + counts.medium) / total) * 100;
  donut.style.background = `conic-gradient(#ff7b7b 0% ${highEnd}%, #f2c75c ${highEnd}% ${mediumEnd}%, #64dbba ${mediumEnd}% 100%)`;
}

function blockFeedback(message, error = false) {
  element("block-feedback").dataset.state = error ? "error" : "success";
  displayMessage("block-feedback", message);
}

async function releaseBlock(activeSession) {
  const blockId = activeSession.pendingRelease;
  if (!blockId || activeSession.releasing) return;
  activeSession.releasing = true;
  element("confirm-release").disabled = true;
  element("cancel-release").disabled = true;
  element("confirm-release").textContent = "Restaurando…";
  try {
    const block = await api(`/api/blocks/${encodeURIComponent(blockId)}/release`, activeSession, activeSession.controller.signal, "POST");
    if (session !== activeSession) return;
    activeSession.pendingRelease = undefined;
    activeSession.releaseFeedbackId = blockId;
    element("release-confirmation").hidden = true;
    blockFeedback(block.restored_at
      ? "Acceso restaurado y comprobado por el servicio protegido."
      : "Bloqueo liberado. La restauración se confirmará cuando el origen vuelva a acceder al laboratorio.");
    await refresh(activeSession);
  } catch (error) {
    if (session !== activeSession) return;
    if (error.unauthorized) disconnect(error.message);
    else blockFeedback(error.message, true);
  } finally {
    activeSession.releasing = false;
    element("confirm-release").disabled = false;
    element("cancel-release").disabled = false;
    element("confirm-release").textContent = "Confirmar restauración";
    if (session === activeSession) renderBlocks(activeSession.blocks, activeSession);
  }
}

async function downloadEvidence(activeSession) {
  const incidentId = element("download-evidence").dataset.incident;
  if (!incidentId || activeSession.exporting) return;
  activeSession.exporting = incidentId;
  element("download-evidence").disabled = true;
  element("export-feedback").dataset.state = "success";
  displayMessage("export-feedback", "Preparando el archivo de evidencia…");

  try {
    const response = await request(`/api/incidents/${encodeURIComponent(incidentId)}/export`, activeSession);
    const blob = await response.blob();
    if (session !== activeSession) return;
    const filename = response.headers.get("Content-Disposition")?.match(/filename="([^"]+)"/i)?.[1]
      || `sentinelcore-${incidentId}-evidence.json`;
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename.split(/[\\/]/).pop();
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    if (activeSession.selected === incidentId) {
      displayMessage("export-feedback", "Descarga iniciada. El archivo JSON incluye los eventos, bloqueos y auditoría del incidente.");
    }
  } catch (error) {
    if (session !== activeSession) return;
    if (error.unauthorized) disconnect(error.message);
    else if (activeSession.selected === incidentId) {
      element("export-feedback").dataset.state = "error";
      displayMessage("export-feedback", error.message);
    }
  } finally {
    activeSession.exporting = undefined;
    if (session === activeSession) element("download-evidence").disabled = false;
  }
}

async function updateDetail(activeSession, id, showLoading) {
  activeSession.detailRequest?.abort();
  const request = new AbortController();
  activeSession.detailRequest = request;
  const current = () => session === activeSession && activeSession.detailRequest === request;
  if (showLoading) {
    element("download-evidence").hidden = true;
    displayMessage("export-feedback", "");
    element("evidence-content").hidden = true;
    displayMessage("evidence-state", "Cargando evidencia…");
  }
  try {
    const incident = await api(`/api/incidents/${encodeURIComponent(id)}`, activeSession, request.signal);
    if (current()) renderDetail(incident);
  } catch (error) {
    if (!current()) return;
    if (error.unauthorized) {
      disconnect(error.message);
      return;
    }
    element("evidence-content").hidden = true;
    element("download-evidence").hidden = true;
    displayMessage("evidence-state", error.message);
  } finally {
    if (current()) activeSession.detailRequest = undefined;
  }
}

async function refresh(activeSession, connecting = false) {
  if (activeSession.refreshing) return;
  activeSession.refreshing = true;
  element("refresh").disabled = true;

  try {
    const [metrics, incidents, blocks, audit, system] = await Promise.all([
      api("/api/metrics", activeSession),
      api("/api/incidents?limit=30", activeSession),
      api("/api/blocks", activeSession),
      api("/api/audit?limit=50", activeSession),
      api("/api/system", activeSession),
    ]);
    if (session !== activeSession) return;

    const metricIds = {
      events: "metric-events",
      incidents: "metric-incidents",
      alerts: "metric-alerts",
      verified_blocks: "metric-verified-blocks",
      active_blocks: "metric-active-blocks",
      restored_access: "metric-restored-access",
    };
    for (const [key, id] of Object.entries(metricIds)) {
      animateMetric(id, metrics[key]);
    }
    renderIncidents(incidents, activeSession);
    renderBlocks(blocks, activeSession);
    renderAudit(audit, activeSession);
    renderSystem(system);
    renderThreat(incidents, blocks);
    renderRiskDonut(incidents);
    updateRelativeTimes();

    const now = new Date().toISOString();
    element("updated").dateTime = now;
    element("updated").textContent = formatTime(now);
    displayConnection("online", "Conectado");
    displayMessage("refresh-error", "");
    if (activeSession.selected && !activeSession.detailRequest) {
      await updateDetail(activeSession, activeSession.selected, false);
    }
    return true;
  } catch (error) {
    if (session !== activeSession) return;
    if (connecting || error.unauthorized) {
      disconnect(error.message);
      return false;
    }
    displayConnection("error", "Error de conexión");
    displayMessage("refresh-error", error.message);
  } finally {
    activeSession.refreshing = false;
    if (session === activeSession) element("refresh").disabled = false;
  }
}

function disconnect(message = "") {
  if (session) {
    clearInterval(session.timer);
    session.controller.abort();
    session.detailRequest?.abort();
    session.token = "";
    session = undefined;
  }
  displayConnection("offline", "Desconectado");
  element("workspace").hidden = true;
  element("access").hidden = false;
  element("disconnect").hidden = true;
  element("connect").disabled = false;
  element("token").disabled = false;
  element("token").value = "";
  element("incident-rows").replaceChildren();
  element("block-rows").replaceChildren();
  element("audit-list").replaceChildren();
  for (const id of ["metric-events", "metric-incidents", "metric-alerts", "metric-verified-blocks", "metric-active-blocks", "metric-restored-access"]) {
    const metric = element(id);
    metric.dataset.value = "0";
    metric.textContent = "—";
  }
  element("threat").dataset.level = "calm";
  element("threat-state").textContent = "Sistema en calma";
  element("threat-detail").textContent = "Sin incidentes registrados. El laboratorio está preparado.";
  element("threat-high").textContent = "0";
  element("threat-blocks").textContent = "0";
  setRelativeTime(element("threat-last"), "");
  element("risk-total").textContent = "0";
  element("risk-high").textContent = "0";
  element("risk-medium").textContent = "0";
  element("risk-low").textContent = "0";
  element("risk-donut").style.background = "conic-gradient(#25374a 0% 100%)";
  element("release-confirmation").hidden = true;
  displayMessage("block-feedback", "");
  displayMessage("export-feedback", "");
  element("download-evidence").hidden = true;
  element("evidence-content").hidden = true;
  element("evidence-content").replaceChildren();
  displayMessage("evidence-state", "Selecciona un incidente para consultar sus eventos.");
  displayMessage("connect-error", message);
  element("token").focus();
}

element("connect-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (session) return;

  const input = element("token");
  const token = input.value.trim();
  if (!token) return;
  const activeSession = { token, controller: new AbortController() };
  session = activeSession;
  input.value = "";
  input.disabled = true;
  element("connect").disabled = true;
  displayMessage("connect-error", "");
  displayConnection("offline", "Conectando…");

  if (await refresh(activeSession, true)) {
    element("access").hidden = true;
    element("workspace").hidden = false;
    element("disconnect").hidden = false;
    element("workspace-title").focus();
    activeSession.timer = setInterval(() => refresh(activeSession), refreshIntervalMs);
  }
});

element("incident-rows").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-incident]");
  if (!button || !session) return;
  session.selected = button.dataset.incident;
  highlightSelection(session);
  if (matchMedia("(max-width: 53rem)").matches) element("evidence-title").focus();
  void updateDetail(session, session.selected, true);
});

element("refresh").addEventListener("click", () => {
  if (session) void refresh(session);
});
element("disconnect").addEventListener("click", () => disconnect());
element("download-evidence").addEventListener("click", () => {
  if (session) void downloadEvidence(session);
});

element("block-rows").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-release]");
  if (!button || !session || session.releasing) return;
  const block = session.blocks.find((item) => item.id === button.dataset.release);
  if (!block) return;
  session.pendingRelease = block.id;
  session.releaseFeedbackId = undefined;
  displayMessage("block-feedback", "");
  element("release-prompt").textContent = `Restaurar el acceso de ${block.source_ip} al servicio ${block.target}. El sistema comprobará el resultado con la siguiente solicitud del origen.`;
  element("release-confirmation").hidden = false;
  element("confirm-release").focus();
});

element("confirm-release").addEventListener("click", () => {
  if (session) void releaseBlock(session);
});

element("cancel-release").addEventListener("click", () => {
  if (!session) return;
  session.pendingRelease = undefined;
  element("release-confirmation").hidden = true;
});

function tickClock() {
  const now = new Date();
  const clock = element("clock");
  clock.textContent = clockFormat.format(now);
  clock.dateTime = now.toISOString();
}

tickClock();
setInterval(tickClock, 1000);
setInterval(updateRelativeTimes, 1000);
