"use strict";

const element = (id) => document.getElementById(id);
const risks = { low: "Bajo", medium: "Medio", high: "Alto" };
const statuses = {
  alert: "Alerta",
  pending_containment: "Contención pendiente",
  review: "En revisión",
};
const recommendations = { review: "Revisar", temporary_block: "Bloqueo temporal" };
const categories = { possible_brute_force: "Posible fuerza bruta" };
const eventTypes = { failed_login: "Autenticación fallida", successful_login: "Autenticación correcta" };
const numberFormat = new Intl.NumberFormat("es-PE");
const dateFormat = new Intl.DateTimeFormat("es-PE", { dateStyle: "medium", timeStyle: "medium" });
const refreshIntervalMs = 8000;
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

async function api(path, activeSession, signal = activeSession.controller.signal) {
  let response;
  try {
    response = await fetch(path, {
      headers: { Authorization: `Bearer ${activeSession.token}` },
      signal: AbortSignal.any([signal, AbortSignal.timeout(6000)]),
      cache: "no-store",
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
  if (!response.ok) throw new Error(`La API respondió con un error (${response.status}).`);
  return response.json();
}

function riskBadge(severity) {
  const badge = node("span", risks[severity] ?? severity, "badge");
  badge.dataset.risk = severity;
  return badge;
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

  for (const incident of data.items) {
    const row = document.createElement("tr");
    const button = node("button", incident.id, "incident-link mono");
    button.type = "button";
    button.dataset.incident = incident.id;
    button.setAttribute("aria-controls", "evidence-content");
    const idCell = document.createElement("td");
    const riskCell = document.createElement("td");
    idCell.append(button);
    riskCell.append(riskBadge(incident.severity));
    row.append(idCell, node("td", incident.source_ip, "mono"), riskCell, node("td", incident.event_count));
    fragment.append(row);
  }

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
    ["Motivo", incident.reason],
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
  content.replaceChildren(title, facts, eventTitle, incident.events.length ? events : node("p", "No hay eventos asociados."));
  content.hidden = false;
  displayMessage("evidence-state", "");
}

async function updateDetail(activeSession, id, showLoading) {
  activeSession.detailRequest?.abort();
  const request = new AbortController();
  activeSession.detailRequest = request;
  const current = () => session === activeSession && activeSession.detailRequest === request;
  if (showLoading) {
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
    const [metrics, incidents] = await Promise.all([
      api("/api/metrics", activeSession),
      api("/api/incidents?limit=30", activeSession),
    ]);
    if (session !== activeSession) return;

    const metricIds = {
      events: "metric-events",
      incidents: "metric-incidents",
      alerts: "metric-alerts",
      verified_blocks: "metric-verified-blocks",
    };
    for (const [key, id] of Object.entries(metricIds)) {
      element(id).textContent = numberFormat.format(metrics[key]);
    }
    renderIncidents(incidents, activeSession);

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
