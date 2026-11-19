const state = document.querySelector('#connection-status');
const source = document.querySelector('#source-ip');
const checkButton = document.querySelector('#check-access');
const demoButton = document.querySelector('#run-demo');
const sprayingButton = document.querySelector('#run-spraying');
const loginButton = document.querySelector('#login-button');
const results = document.querySelector('#demo-results');
const demoStatus = document.querySelector('#demo-status');
let actionInProgress = false;

async function send(path, body, timeout = 10000) {
  const response = await fetch(path, {
    method: body ? 'POST' : 'GET',
    headers: body ? {'Content-Type': 'application/json'} : {},
    body: body ? JSON.stringify(body) : undefined,
    cache: 'no-store',
    credentials: 'same-origin',
    signal: AbortSignal.timeout(timeout),
  });
  const data = await response.json();
  return {code: response.status, data};
}

async function checkAccess(timeout = 10000) {
  checkButton.disabled = true;
  try {
    const result = await send('/access', undefined, timeout);
    if (result.data.source_ip) source.textContent = result.data.source_ip;
    const labels = {200: 'Acceso disponible · HTTP 200', 403: 'Conexión bloqueada · HTTP 403', 503: 'Protección no disponible · HTTP 503'};
    state.textContent = labels[result.code] || `Respuesta HTTP ${result.code}`;
    state.className = `status ${result.code === 200 ? 'ok' : result.code === 403 ? 'blocked' : 'unavailable'}`;
    return result;
  } catch {
    state.textContent = 'No se pudo conectar con el servicio';
    state.className = 'status unavailable';
    return null;
  } finally {
    checkButton.disabled = false;
  }
}

function setActionRunning(running) {
  actionInProgress = running;
  demoButton.disabled = running;
  sprayingButton.disabled = running;
  loginButton.disabled = running;
}

checkButton.addEventListener('click', () => checkAccess());
document.querySelector('#login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (actionInProgress) return;
  setActionRunning(true);
  const message = document.querySelector('#login-result');
  try {
    const result = await send('/login', {
      username: document.querySelector('#username').value,
      password: document.querySelector('#password').value,
    });
    const text = result.code === 200 ? 'Autenticación correcta' : result.data.detail;
    message.textContent = `${text} · HTTP ${result.code}`;
  } catch {
    message.textContent = 'No se pudo conectar con el servicio';
  } finally {
    document.querySelector('#password').value = '';
    await checkAccess();
    setActionRunning(false);
  }
});

async function runDemo(severalUsers) {
  if (actionInProgress) return;
  setActionRunning(true);
  results.replaceChildren();
  demoStatus.textContent = 'Enviando intentos de autenticación…';
  document.querySelector('#demo-pattern').textContent = severalUsers
    ? 'Patrón de password spraying · una contraseña inválida en usuarios diferentes'
    : 'Patrón de fuerza bruta · contraseñas inválidas para el mismo usuario';
  const random = new Uint32Array(4);
  crypto.getRandomValues(random);
  const sharedPassword = Array.from(random).join('-');
  try {
    let lastCode;
    for (let attempt = 1; attempt <= 8; attempt += 1) {
      const username = severalUsers ? `sc-demo-${attempt}` : 'sc-demo';
      const password = severalUsers ? sharedPassword : `${sharedPassword}-${attempt}`;
      const result = await send('/login', {username, password});
      const row = document.createElement('li');
      const labels = {401: 'Credenciales inválidas registradas', 403: 'Acceso bloqueado por SentinelCore', 503: 'Protección no disponible'};
      row.textContent = `Intento ${attempt} · ${username} · HTTP ${result.code} · ${labels[result.code] || 'Respuesta recibida'}`;
      results.append(row);
      lastCode = result.code;
      if (result.code !== 401) break;
      await new Promise(resolve => setTimeout(resolve, 300));
    }
    let access = await checkAccess();
    let waitedForDecision = false;
    if (lastCode === 401 && access?.code === 200) {
      waitedForDecision = true;
      const deadline = Date.now() + 15000;
      demoStatus.textContent = 'Esperando decisión…';
      while (access?.code === 200 && Date.now() + 1000 < deadline) {
        await new Promise(resolve => setTimeout(resolve, 1000));
        const remaining = deadline - Date.now();
        if (remaining <= 0) break;
        access = await checkAccess(Math.min(10000, remaining));
      }
    }
    if (access?.code === 403) {
      demoStatus.textContent = 'Bloqueo confirmado · HTTP 403';
    } else if (access?.code === 200) {
      demoStatus.textContent = waitedForDecision
        ? 'Acceso disponible tras la espera · HTTP 200. Revisa la decisión en el panel.'
        : 'Acceso disponible · HTTP 200';
    } else if (access?.code === 503) {
      demoStatus.textContent = 'Protección no disponible · HTTP 503';
    } else {
      demoStatus.textContent = 'No se pudo confirmar el acceso. Pulsa Probar acceso para reintentar.';
    }
  } catch {
    const row = document.createElement('li');
    row.textContent = 'La conexión se interrumpió. Vuelve a probar el acceso.';
    results.append(row);
    demoStatus.textContent = 'La prueba terminó por un problema de conexión.';
  } finally {
    setActionRunning(false);
  }
}

demoButton.addEventListener('click', () => runDemo(false));
sprayingButton.addEventListener('click', () => runDemo(true));

checkAccess();
