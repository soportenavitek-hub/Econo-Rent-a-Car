require('dotenv').config();
const express = require('express');
const cors = require('cors');

const app = express();

const {
  PILOT_SERVER,
  PILOT_USER,
  PILOT_PASS,
  PORT = 3000,
  ALLOWED_ORIGIN = '*',
  TOKEN_SECRET,
  ADMIN_KEY,
} = process.env;

if (!PILOT_SERVER) {
  console.error('Falta PILOT_SERVER en el archivo .env');
  process.exit(1);
}
if (!PILOT_USER || !PILOT_PASS) {
  console.error('Falta PILOT_USER o PILOT_PASS en el archivo .env');
  process.exit(1);
}
if (!TOKEN_SECRET) {
  console.error('Falta TOKEN_SECRET en el archivo .env (clave fija para generar los tokens rotativos)');
  process.exit(1);
}
if (!ADMIN_KEY) {
  console.error('Falta ADMIN_KEY en el archivo .env (para consultar el link vigente)');
  process.exit(1);
}

const path = require('path');
const crypto = require('crypto');

app.use(cors({ origin: ALLOWED_ORIGIN }));

const ACCESS_COOKIE = 'pilot_access';
const HUNDRED_DAYS_MS = 1000 * 60 * 60 * 24 * 100; // cubre un trimestre con margen

// ---- Token rotativo cada 3 meses (sin cron, sin tocar nada a mano) ----
// El "periodo" cambia solo cada trimestre calendario (Q1-Q4). El token es un
// hash del secreto fijo + ese periodo, así que rota automáticamente y sigue
// siendo el mismo durante los 3 meses de cada trimestre.
function currentPeriod(date = new Date()) {
  const year = date.getUTCFullYear();
  const quarter = Math.floor(date.getUTCMonth() / 3) + 1; // 1-4
  return `${year}-Q${quarter}`;
}

function tokenForPeriod(period) {
  return crypto.createHmac('sha256', TOKEN_SECRET).update(period).digest('base64url').slice(0, 24);
}

function currentToken() {
  return tokenForPeriod(currentPeriod());
}

// ---- Puerta de acceso por link secreto ----
// Si viene ?token=... correcto (del trimestre actual), se guarda una cookie
// y se deja pasar. Si ya trae la cookie de una visita anterior (y sigue
// siendo el token del trimestre vigente), también se deja pasar.
app.use((req, res, next) => {
  if (req.path === '/health' || req.path === '/admin/link') return next();

  const validToken = currentToken();

  if (req.query.token && req.query.token === validToken) {
    res.cookie(ACCESS_COOKIE, validToken, {
      maxAge: HUNDRED_DAYS_MS,
      httpOnly: true,
      sameSite: 'lax',
    });
    return next();
  }

  const cookies = req.headers.cookie || '';
  const hasValidCookie = cookies
    .split(';')
    .map(c => c.trim())
    .some(c => c === `${ACCESS_COOKIE}=${validToken}`);

  if (hasValidCookie) return next();

  res.status(403).send('Acceso no autorizado. Usa el link vigente que te compartieron para entrar.');
});

// Endpoint para consultar el link vigente (protegido con ADMIN_KEY, no con
// el token rotativo — así puedes generarlo aunque el token haya cambiado).
app.get('/admin/link', (req, res) => {
  if (req.query.key !== ADMIN_KEY) {
    return res.status(403).json({ error: 'ADMIN_KEY inválida' });
  }
  const token = currentToken();
  const baseUrl = `${req.protocol}://${req.get('host')}`;
  res.json({
    periodo: currentPeriod(),
    token,
    link: `${baseUrl}/?token=${token}`,
  });
});

app.use(express.static(path.join(__dirname, 'public')));

// ---- Manejo de sesión con PILOT (cookie PILOTID) ----
// PILOT no usa Basic Auth para el panel: hay que loguearse igual que el
// formulario web y reutilizar la cookie de sesión que regresa.
let sessionCookie = null;

async function loginToPilot() {
  const body = new URLSearchParams({
    username: PILOT_USER,
    password: PILOT_PASS,
  });

  const res = await fetch(`${PILOT_SERVER}/backend/`, {
    method: 'POST',
    body,
  });

  const setCookie = res.headers.get('set-cookie');
  const match = setCookie && setCookie.match(/PILOTID=[^;]+/);

  if (!match) {
    throw new Error('El login a PILOT no devolvió cookie de sesión (revisa usuario/contraseña).');
  }

  sessionCookie = match[0];
  console.log('Sesión PILOT renovada.');
  return sessionCookie;
}

async function ensureSession() {
  if (!sessionCookie) {
    await loginToPilot();
  }
  return sessionCookie;
}

// Llama a una URL de PILOT con la cookie de sesión; si la sesión expiró
// (401/403), se loguea de nuevo una vez y reintenta.
async function pilotFetch(targetUrl) {
  await ensureSession();

  let res = await fetch(targetUrl, { headers: { Cookie: sessionCookie } });

  if (res.status === 401 || res.status === 403) {
    sessionCookie = null;
    await ensureSession();
    res = await fetch(targetUrl, { headers: { Cookie: sessionCookie } });
  }

  return res;
}

function basicAuthHeader() {
  const encoded = Buffer.from(`${PILOT_USER}:${PILOT_PASS}`).toString('base64');
  return { Authorization: `Basic ${encoded}` };
}

async function proxyToPilot(req, res, pilotPath, { useSession } = {}) {
  try {
    const params = new URLSearchParams(req.query).toString();
    const targetUrl = `${PILOT_SERVER}${pilotPath}${params ? `?${params}` : ''}`;

    const pilotRes = useSession
      ? await pilotFetch(targetUrl)
      : await fetch(targetUrl, { headers: basicAuthHeader() });

    const text = await pilotRes.text();

    res.status(pilotRes.status);
    res.type(pilotRes.headers.get('content-type') || 'application/json');
    res.send(text);
  } catch (err) {
    console.error(`Error al conectar con PILOT (${pilotPath}):`, err.message);
    res.status(502).json({ error: 'No se pudo contactar al servidor PILOT', detail: err.message });
  }
}

// Pronóstico de llegadas — usa Basic Auth (usuario/contraseña codificados)
app.get('/api/api.php', (req, res) => proxyToPilot(req, res, '/api/api.php'));

// Listado real de paradas (módulo Bus lines) — usa la sesión (cookie PILOTID)
app.get('/backend/ax/mod_buslines.php', (req, res) => proxyToPilot(req, res, '/backend/ax/mod_buslines.php', { useSession: true }));

app.get('/health', (req, res) => res.json({ ok: true, sessionActive: !!sessionCookie }));

app.listen(PORT, () => {
  console.log(`Proxy PILOT escuchando en http://localhost:${PORT}`);
  console.log(`Prueba paradas: http://localhost:${PORT}/backend/ax/mod_buslines.php?cmd=tree&node=_4`);
  console.log(`Prueba pronóstico: http://localhost:${PORT}/api/api.php?cmd=stationForecast&stopid=14`);
  console.log(`Periodo actual: ${currentPeriod()} · Link vigente: http://localhost:${PORT}/?token=${currentToken()}`);
  console.log(`(Consulta el link vigente en cualquier momento en /admin/link?key=TU_ADMIN_KEY)`);
});
