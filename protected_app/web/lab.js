const state = document.querySelector('#connection-status');
const source = document.querySelector('#source-ip');
const checkButton = document.querySelector('#check-access');
const demoButton = document.querySelector('#run-demo');
const sprayingButton = document.querySelector('#run-spraying');
const loginButton = document.querySelector('#login-button');
const results = document.querySelector('#demo-results');

async function send(path, body) {
  const response = await fetch(path, {
    method: body ? 'POST' : 'GET',
    headers: body ? {'Content-Type': 'application/json'} : {},
    body: body ? JSON.stringify(body) : undefined,
    cache: 'no-store',
    credentials: 'same-origin',
  });
  const data = await response.json();
  return {code: response.status, data};
}

async function checkAccess() {
  checkButton.disabled = true;
  try {
    const result = await send('/access');
    if (result.data.source_ip) source.textContent = result.data.source_ip;
    const labels = {200: 'Acceso disponible · HTTP 200', 403: 'Conexión bloqueada · HTTP 403', 503: 'Protección no disponible · HTTP 503'};
    state.textContent = labels[result.code] || `Respuesta HTTP ${result.code}`;
    state.className = `status ${result.code === 200 ? 'ok' : result.code === 403 ? 'blocked' : 'unavailable'}`;
  } catch {
    state.textContent = 'No se pudo conectar con el servicio';
    state.className = 'status unavailable';
  } finally {
    checkButton.disabled = false;
  }
}

checkButton.addEventListener('click', checkAccess);
document.querySelector('#login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  loginButton.disabled = true;
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
    loginButton.disabled = false;
    await checkAccess();
  }
});

async function runDemo(severalUsers) {
  demoButton.disabled = true;
  sprayingButton.disabled = true;
  results.replaceChildren();
  document.querySelector('#demo-pattern').textContent = severalUsers
    ? 'Patrón de password spraying · una contraseña inválida en usuarios diferentes'
    : 'Patrón de fuerza bruta · contraseñas inválidas para el mismo usuario';
  const random = new Uint32Array(4);
  crypto.getRandomValues(random);
  const sharedPassword = Array.from(random).join('-');
  try {
    for (let attempt = 1; attempt <= 8; attempt += 1) {
      const username = severalUsers ? `sc-demo-${attempt}` : 'sc-demo';
      const password = severalUsers ? sharedPassword : `${sharedPassword}-${attempt}`;
      const result = await send('/login', {username, password});
      const row = document.createElement('li');
      const labels = {401: 'Credenciales inválidas registradas', 403: 'Acceso bloqueado por SentinelCore', 503: 'Protección no disponible'};
      row.textContent = `Intento ${attempt} · ${username} · HTTP ${result.code} · ${labels[result.code] || 'Respuesta recibida'}`;
      results.append(row);
      if (result.code !== 401) break;
      await new Promise(resolve => setTimeout(resolve, 300));
    }
  } catch {
    const row = document.createElement('li');
    row.textContent = 'La conexión se interrumpió. Vuelve a probar el acceso.';
    results.append(row);
  } finally {
    demoButton.disabled = false;
    sprayingButton.disabled = false;
    await checkAccess();
  }
}

demoButton.addEventListener('click', () => runDemo(false));
sprayingButton.addEventListener('click', () => runDemo(true));

checkAccess();
