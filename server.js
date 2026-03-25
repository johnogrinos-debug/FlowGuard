/**
 * FlowGuard — Production Server v3
 * Xero + MYOB + QuickBooks OAuth, AI analysis, Auth, Stripe
 */

require('dotenv').config();

const express      = require('express');
const axios        = require('axios');
const cors         = require('cors');
const path         = require('path');
const crypto       = require('crypto');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const Database     = require('better-sqlite3');

const app = express();
app.use(cors({ origin: process.env.APP_URL || 'http://localhost:3000', credentials: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/webhook/stripe', express.raw({ type: 'application/json' }));
app.use(express.json());

// ── DATABASE ──────────────────────────────────────────────────────────
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'flowguard.db');
const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT    UNIQUE NOT NULL,
    password_hash TEXT    NOT NULL,
    name          TEXT,
    company       TEXT,
    plan          TEXT    DEFAULT 'trial',
    trial_ends_at INTEGER,
    stripe_customer_id   TEXT,
    stripe_subscription_id TEXT,
    created_at    INTEGER DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS connections (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    provider      TEXT    NOT NULL,
    tenant_id     TEXT,
    tenant_name   TEXT,
    access_token  TEXT,
    refresh_token TEXT,
    expires_at    INTEGER,
    realm_id      TEXT,
    created_at    INTEGER DEFAULT (strftime('%s','now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS analyses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    question    TEXT,
    result      TEXT,
    created_at  INTEGER DEFAULT (strftime('%s','now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS oauth_states (
    state      TEXT PRIMARY KEY,
    user_id    INTEGER,
    provider   TEXT,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );
`);

setInterval(() => {
  db.prepare('DELETE FROM oauth_states WHERE created_at < ?').run(Math.floor(Date.now()/1000) - 3600);
}, 3600000);

// ── CONFIG ────────────────────────────────────────────────────────────
const APP_URL    = process.env.APP_URL    || 'http://localhost:3000';
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_in_production';

const CONFIG = {
  xero: {
    clientId:     process.env.XERO_CLIENT_ID     || '',
    clientSecret: process.env.XERO_CLIENT_SECRET || '',
    redirectUri:  APP_URL + '/callback/xero',
    authUrl:      'https://login.xero.com/identity/connect/authorize',
    tokenUrl:     'https://identity.xero.com/connect/token',
    apiBase:      'https://api.xero.com/api.xro/2.0',
    scopes:       'openid profile email accounting.transactions.read accounting.reports.read accounting.settings.read offline_access',
  },
  myob: {
    clientId:     process.env.MYOB_CLIENT_ID     || '',
    clientSecret: process.env.MYOB_CLIENT_SECRET || '',
    redirectUri:  APP_URL + '/callback/myob',
    authUrl:      'https://secure.myob.com/oauth2/account/authorize',
    tokenUrl:     'https://secure.myob.com/oauth2/v1/authorize',
    apiBase:      'https://api.myob.com/accountright',
    scopes:       'CompanyFile',
  },
  quickbooks: {
    clientId:     process.env.QB_CLIENT_ID     || '',
    clientSecret: process.env.QB_CLIENT_SECRET || '',
    redirectUri:  APP_URL + '/callback/quickbooks',
    authUrl:      'https://appcenter.intuit.com/connect/oauth2',
    tokenUrl:     'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer',
    apiBase:      'https://quickbooks.api.intuit.com/v3/company',
    scopes:       'com.intuit.quickbooks.accounting',
  },
  anthropicKey:  process.env.ANTHROPIC_API_KEY     || '',
  stripeSecret:  process.env.STRIPE_SECRET_KEY     || '',
  stripeWebhook: process.env.STRIPE_WEBHOOK_SECRET || '',
  stripePriceId: process.env.STRIPE_PRICE_ID       || '',
};

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.cookies?.fg_token || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.userId);
    if (!user) return res.status(401).json({ error: 'User not found' });
    req.user = user;
    next();
  } catch(e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ── HEALTH ────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ ok: true, version: '3.0.0' }));

// ── SIGNUP ────────────────────────────────────────────────────────────
app.post('/api/auth/signup', async (req, res) => {
  const { email, password, name, company } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  if (db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase()))
    return res.status(400).json({ error: 'An account with this email already exists' });
  const hash = await bcrypt.hash(password, 12);
  const trialEnds = Math.floor(Date.now()/1000) + 14*24*60*60;
  const result = db.prepare(
    'INSERT INTO users (email, password_hash, name, company, plan, trial_ends_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(email.toLowerCase(), hash, name||'', company||'', 'trial', trialEnds);
  const token = jwt.sign({ userId: result.lastInsertRowid }, JWT_SECRET, { expiresIn: '30d' });
  res.cookie('fg_token', token, { httpOnly:true, secure: process.env.NODE_ENV==='production', maxAge:30*24*60*60*1000, sameSite:'lax' });
  res.json({ ok: true, user: db.prepare('SELECT id,email,name,company,plan,trial_ends_at FROM users WHERE id=?').get(result.lastInsertRowid), token });
});

// ── LOGIN ─────────────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
  if (!user || !await bcrypt.compare(password, user.password_hash))
    return res.status(401).json({ error: 'Invalid email or password' });
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
  res.cookie('fg_token', token, { httpOnly:true, secure: process.env.NODE_ENV==='production', maxAge:30*24*60*60*1000, sameSite:'lax' });
  const { password_hash, ...safeUser } = user;
  res.json({ ok: true, user: safeUser, token });
});

app.post('/api/auth/logout', (req, res) => { res.clearCookie('fg_token'); res.json({ ok: true }); });

app.get('/api/auth/me', auth, (req, res) => {
  const { password_hash, ...safeUser } = req.user;
  const connection = db.prepare('SELECT provider,tenant_name,created_at FROM connections WHERE user_id=? ORDER BY created_at DESC LIMIT 1').get(req.user.id);
  const analysisCount = db.prepare('SELECT COUNT(*) as count FROM analyses WHERE user_id=?').get(req.user.id);
  res.json({ user: safeUser, connection: connection||null, analysisCount: analysisCount.count });
});

// ── XERO OAUTH ────────────────────────────────────────────────────────
app.get('/auth/xero', auth, (req, res) => {
  if (!CONFIG.xero.clientId) return res.redirect('/app?error=xero_not_configured');
  const state = crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO oauth_states (state,user_id,provider) VALUES (?,?,?)').run(state, req.user.id, 'xero');
  const params = new URLSearchParams({ response_type:'code', client_id:CONFIG.xero.clientId, redirect_uri:CONFIG.xero.redirectUri, scope:CONFIG.xero.scopes, state });
  res.redirect(CONFIG.xero.authUrl + '?' + params);
});

app.get('/callback/xero', async (req, res) => {
  const { code, state } = req.query;
  const stateRow = db.prepare('SELECT * FROM oauth_states WHERE state=?').get(state);
  if (!stateRow) return res.redirect('/app?error=invalid_state');
  db.prepare('DELETE FROM oauth_states WHERE state=?').run(state);
  try {
    const creds = Buffer.from(CONFIG.xero.clientId+':'+CONFIG.xero.clientSecret).toString('base64');
    const t = await axios.post(CONFIG.xero.tokenUrl,
      new URLSearchParams({ grant_type:'authorization_code', code, redirect_uri:CONFIG.xero.redirectUri }),
      { headers:{ Authorization:'Basic '+creds, 'Content-Type':'application/x-www-form-urlencoded' } }
    );
    const { access_token, refresh_token, expires_in } = t.data;
    const tenants = await axios.get('https://api.xero.com/connections', { headers:{ Authorization:'Bearer '+access_token } });
    const tenant = tenants.data[0];
    const ex = db.prepare('SELECT id FROM connections WHERE user_id=? AND provider=?').get(stateRow.user_id,'xero');
    if (ex) {
      db.prepare('UPDATE connections SET tenant_id=?,tenant_name=?,access_token=?,refresh_token=?,expires_at=? WHERE id=?')
        .run(tenant?.tenantId, tenant?.tenantName, access_token, refresh_token, Date.now()+expires_in*1000, ex.id);
    } else {
      db.prepare('INSERT INTO connections (user_id,provider,tenant_id,tenant_name,access_token,refresh_token,expires_at) VALUES (?,?,?,?,?,?,?)')
        .run(stateRow.user_id,'xero',tenant?.tenantId,tenant?.tenantName,access_token,refresh_token,Date.now()+expires_in*1000);
    }
    res.redirect('/app?connected=xero');
  } catch(err) {
    console.error('Xero error:', err.response?.data||err.message);
    res.redirect('/app?error=xero_auth_failed');
  }
});

// ── MYOB OAUTH ────────────────────────────────────────────────────────
app.get('/auth/myob', auth, (req, res) => {
  if (!CONFIG.myob.clientId) return res.redirect('/app?error=myob_not_configured');
  const state = crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO oauth_states (state,user_id,provider) VALUES (?,?,?)').run(state, req.user.id, 'myob');
  const params = new URLSearchParams({ client_id:CONFIG.myob.clientId, redirect_uri:CONFIG.myob.redirectUri, response_type:'code', scope:CONFIG.myob.scopes, state });
  res.redirect(CONFIG.myob.authUrl + '?' + params);
});

app.get('/callback/myob', async (req, res) => {
  const { code, state } = req.query;
  const stateRow = db.prepare('SELECT * FROM oauth_states WHERE state=?').get(state);
  if (!stateRow) return res.redirect('/app?error=invalid_state');
  db.prepare('DELETE FROM oauth_states WHERE state=?').run(state);
  try {
    const t = await axios.post(CONFIG.myob.tokenUrl,
      new URLSearchParams({ client_id:CONFIG.myob.clientId, client_secret:CONFIG.myob.clientSecret, redirect_uri:CONFIG.myob.redirectUri, grant_type:'authorization_code', code }),
      { headers:{ 'Content-Type':'application/x-www-form-urlencoded' } }
    );
    const { access_token, refresh_token, expires_in } = t.data;
    const files = await axios.get(CONFIG.myob.apiBase+'/', { headers:{ Authorization:'Bearer '+access_token } });
    const file = files.data?.Items?.[0];
    const ex = db.prepare('SELECT id FROM connections WHERE user_id=? AND provider=?').get(stateRow.user_id,'myob');
    if (ex) {
      db.prepare('UPDATE connections SET tenant_name=?,access_token=?,refresh_token=?,expires_at=? WHERE id=?')
        .run(file?.Name, access_token, refresh_token, Date.now()+(expires_in||1800)*1000, ex.id);
    } else {
      db.prepare('INSERT INTO connections (user_id,provider,tenant_name,access_token,refresh_token,expires_at) VALUES (?,?,?,?,?,?)')
        .run(stateRow.user_id,'myob',file?.Name,access_token,refresh_token,Date.now()+(expires_in||1800)*1000);
    }
    res.redirect('/app?connected=myob');
  } catch(err) {
    console.error('MYOB error:', err.response?.data||err.message);
    res.redirect('/app?error=myob_auth_failed');
  }
});

// ── QUICKBOOKS OAUTH ──────────────────────────────────────────────────
app.get('/auth/quickbooks', auth, (req, res) => {
  if (!CONFIG.quickbooks.clientId) return res.redirect('/app?error=quickbooks_not_configured');
  const state = crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO oauth_states (state,user_id,provider) VALUES (?,?,?)').run(state, req.user.id, 'quickbooks');
  const params = new URLSearchParams({ client_id:CONFIG.quickbooks.clientId, redirect_uri:CONFIG.quickbooks.redirectUri, response_type:'code', scope:CONFIG.quickbooks.scopes, state });
  res.redirect(CONFIG.quickbooks.authUrl + '?' + params);
});

app.get('/callback/quickbooks', async (req, res) => {
  const { code, state, realmId } = req.query;
  const stateRow = db.prepare('SELECT * FROM oauth_states WHERE state=?').get(state);
  if (!stateRow) return res.redirect('/app?error=invalid_state');
  db.prepare('DELETE FROM oauth_states WHERE state=?').run(state);
  try {
    const creds = Buffer.from(CONFIG.quickbooks.clientId+':'+CONFIG.quickbooks.clientSecret).toString('base64');
    const t = await axios.post(CONFIG.quickbooks.tokenUrl,
      new URLSearchParams({ grant_type:'authorization_code', code, redirect_uri:CONFIG.quickbooks.redirectUri }),
      { headers:{ Authorization:'Basic '+creds, 'Content-Type':'application/x-www-form-urlencoded', Accept:'application/json' } }
    );
    const { access_token, refresh_token, expires_in } = t.data;
    let companyName = 'QuickBooks Company';
    try {
      const info = await axios.get(`${CONFIG.quickbooks.apiBase}/${realmId}/companyinfo/${realmId}`,
        { headers:{ Authorization:'Bearer '+access_token, Accept:'application/json' } });
      companyName = info.data?.QueryResponse?.CompanyInfo?.[0]?.CompanyName || companyName;
    } catch(e) {}
    const ex = db.prepare('SELECT id FROM connections WHERE user_id=? AND provider=?').get(stateRow.user_id,'quickbooks');
    if (ex) {
      db.prepare('UPDATE connections SET tenant_id=?,tenant_name=?,access_token=?,refresh_token=?,expires_at=?,realm_id=? WHERE id=?')
        .run(realmId, companyName, access_token, refresh_token, Date.now()+expires_in*1000, realmId, ex.id);
    } else {
      db.prepare('INSERT INTO connections (user_id,provider,tenant_id,tenant_name,access_token,refresh_token,expires_at,realm_id) VALUES (?,?,?,?,?,?,?,?)')
        .run(stateRow.user_id,'quickbooks',realmId,companyName,access_token,refresh_token,Date.now()+expires_in*1000,realmId);
    }
    res.redirect('/app?connected=quickbooks');
  } catch(err) {
    console.error('QuickBooks error:', err.response?.data||err.message);
    res.redirect('/app?error=quickbooks_auth_failed');
  }
});

app.delete('/api/connection', auth, (req, res) => {
  db.prepare('DELETE FROM connections WHERE user_id=?').run(req.user.id);
  res.json({ ok:true });
});

// ── TOKEN REFRESH ─────────────────────────────────────────────────────
async function getValidXeroToken(conn) {
  if (Date.now() < conn.expires_at - 60000) return conn.access_token;
  const creds = Buffer.from(CONFIG.xero.clientId+':'+CONFIG.xero.clientSecret).toString('base64');
  const r = await axios.post(CONFIG.xero.tokenUrl,
    new URLSearchParams({ grant_type:'refresh_token', refresh_token:conn.refresh_token }),
    { headers:{ Authorization:'Basic '+creds, 'Content-Type':'application/x-www-form-urlencoded' } }
  );
  db.prepare('UPDATE connections SET access_token=?,refresh_token=?,expires_at=? WHERE id=?')
    .run(r.data.access_token, r.data.refresh_token, Date.now()+r.data.expires_in*1000, conn.id);
  return r.data.access_token;
}

async function getValidQBToken(conn) {
  if (Date.now() < conn.expires_at - 60000) return conn.access_token;
  const creds = Buffer.from(CONFIG.quickbooks.clientId+':'+CONFIG.quickbooks.clientSecret).toString('base64');
  const r = await axios.post(CONFIG.quickbooks.tokenUrl,
    new URLSearchParams({ grant_type:'refresh_token', refresh_token:conn.refresh_token }),
    { headers:{ Authorization:'Basic '+creds, 'Content-Type':'application/x-www-form-urlencoded', Accept:'application/json' } }
  );
  db.prepare('UPDATE connections SET access_token=?,refresh_token=?,expires_at=? WHERE id=?')
    .run(r.data.access_token, r.data.refresh_token, Date.now()+r.data.expires_in*1000, conn.id);
  return r.data.access_token;
}

// ── FETCH DATA ────────────────────────────────────────────────────────
async function fetchXeroData(conn) {
  const token = await getValidXeroToken(conn);
  const headers = { Authorization:'Bearer '+token, 'Xero-tenant-id':conn.tenant_id, Accept:'application/json' };
  const toDate   = new Date().toISOString().split('T')[0];
  const fromDate = new Date(Date.now()-365*86400000).toISOString().split('T')[0];
  const [pl,bs,inv,bills] = await Promise.allSettled([
    axios.get(CONFIG.xero.apiBase+'/Reports/ProfitAndLoss', { headers, params:{ fromDate, toDate, periods:12, timeframe:'MONTH' } }),
    axios.get(CONFIG.xero.apiBase+'/Reports/BalanceSheet',  { headers, params:{ date:toDate } }),
    axios.get(CONFIG.xero.apiBase+'/Invoices', { headers, params:{ where:'Status=="AUTHORISED"&&Type=="ACCREC"', order:'DueDate ASC', pageSize:100 } }),
    axios.get(CONFIG.xero.apiBase+'/Invoices', { headers, params:{ where:'Status=="AUTHORISED"&&Type=="ACCPAY"', order:'DueDate ASC', pageSize:100 } }),
  ]);
  return {
    profitLoss:   pl.status==='fulfilled'    ? pl.value.data    : null,
    balanceSheet: bs.status==='fulfilled'    ? bs.value.data    : null,
    invoices:     inv.status==='fulfilled'   ? (inv.value.data?.Invoices||[])   : [],
    bills:        bills.status==='fulfilled' ? (bills.value.data?.Invoices||[]) : [],
  };
}

async function fetchMYOBData(conn) {
  const headers = { Authorization:'Bearer '+conn.access_token, 'x-myobapi-key':CONFIG.myob.clientId };
  const files = await axios.get(CONFIG.myob.apiBase+'/', { headers });
  const base = files.data?.Items?.[0]?.Uri;
  if (!base) throw new Error('No MYOB company file found');
  const [pl,inv,bills] = await Promise.allSettled([
    axios.get(base+'/GeneralLedger/ProfitAndLoss', { headers }),
    axios.get(base+'/Sale/Invoice',  { headers, params:{ '$top':100, '$filter':"Status eq 'Open'" } }),
    axios.get(base+'/Purchase/Bill', { headers, params:{ '$top':100, '$filter':"Status eq 'Open'" } }),
  ]);
  return {
    profitLoss: pl.status==='fulfilled'    ? pl.value.data    : null,
    invoices:   inv.status==='fulfilled'   ? inv.value.data   : null,
    bills:      bills.status==='fulfilled' ? bills.value.data : null,
  };
}

async function fetchQuickBooksData(conn) {
  const token   = await getValidQBToken(conn);
  const realmId = conn.realm_id || conn.tenant_id;
  const base    = CONFIG.quickbooks.apiBase+'/'+realmId;
  const headers = { Authorization:'Bearer '+token, Accept:'application/json' };
  const [pl,bs,inv,bills] = await Promise.allSettled([
    axios.get(base+'/reports/ProfitAndLoss', { headers, params:{ date_macro:'This Year-to-date', summarize_column_by:'Month' } }),
    axios.get(base+'/reports/BalanceSheet',  { headers, params:{ date_macro:'Today' } }),
    axios.get(base+'/query', { headers, params:{ query:"SELECT * FROM Invoice WHERE Balance > '0' MAXRESULTS 100" } }),
    axios.get(base+'/query', { headers, params:{ query:"SELECT * FROM Bill WHERE Balance > '0' MAXRESULTS 100" } }),
  ]);
  return {
    profitLoss:   pl.status==='fulfilled'    ? pl.value.data    : null,
    balanceSheet: bs.status==='fulfilled'    ? bs.value.data    : null,
    invoices:     inv.status==='fulfilled'   ? (inv.value.data?.QueryResponse?.Invoice||[])   : [],
    bills:        bills.status==='fulfilled' ? (bills.value.data?.QueryResponse?.Bill||[]) : [],
  };
}

app.get('/api/data', auth, async (req, res) => {
  const conn = db.prepare('SELECT * FROM connections WHERE user_id=? ORDER BY created_at DESC LIMIT 1').get(req.user.id);
  if (!conn) return res.status(404).json({ error:'No accounting software connected' });
  try {
    const data =
      conn.provider==='xero'        ? await fetchXeroData(conn) :
      conn.provider==='myob'        ? await fetchMYOBData(conn) :
      conn.provider==='quickbooks'  ? await fetchQuickBooksData(conn) :
      (() => { throw new Error('Unknown provider: '+conn.provider); })();
    res.json({ ok:true, provider:conn.provider, company:conn.tenant_name, data });
  } catch(err) {
    console.error('Data error:', err.response?.data||err.message);
    res.status(500).json({ error:'Failed to fetch data: '+err.message });
  }
});

// ── AI ANALYSIS ───────────────────────────────────────────────────────
function buildSummary(data, provider) {
  const L = [];
  if (provider==='xero') {
    if (data.profitLoss?.Reports?.[0]) {
      L.push('## Profit & Loss (Last 12 months)');
      data.profitLoss.Reports[0].Rows?.forEach(row => {
        if (['Section','Row','SummaryRow'].includes(row.RowType)) {
          const c = row.Cells?.map(c=>c.Value).join(' | ');
          if (c) L.push(c);
          row.Rows?.forEach(r => { const rc=r.Cells?.map(c=>c.Value).join(' | '); if(rc) L.push('  '+rc); });
        }
      });
      L.push('');
    }
    if (data.invoices?.length) {
      const total = data.invoices.reduce((s,i)=>s+(i.AmountDue||0),0);
      const overdue = data.invoices.filter(i=>i.DueDate&&new Date(i.DueDate)<new Date());
      L.push('## Accounts Receivable');
      L.push('Total: $'+total.toFixed(2)+' | Overdue: '+overdue.length+' invoices, $'+overdue.reduce((s,i)=>s+(i.AmountDue||0),0).toFixed(2));
      overdue.slice(0,10).forEach(i => L.push('  - '+(i.Contact?.Name||'?')+': $'+(i.AmountDue||0).toFixed(2)+' ('+Math.floor((Date.now()-new Date(i.DueDate))/86400000)+'d overdue)'));
      L.push('');
    }
    if (data.bills?.length) {
      L.push('## Accounts Payable — Total: $'+data.bills.reduce((s,b)=>s+(b.AmountDue||0),0).toFixed(2));
      data.bills.slice(0,10).forEach(b=>L.push('  - '+(b.Contact?.Name||'?')+': $'+(b.AmountDue||0).toFixed(2)));
      L.push('');
    }
  } else if (provider==='quickbooks') {
    if (data.profitLoss) L.push('## P&L\n'+JSON.stringify(data.profitLoss).slice(0,4000));
    if (data.invoices?.length) {
      const total=data.invoices.reduce((s,i)=>s+(i.Balance||0),0);
      const overdue=data.invoices.filter(i=>i.DueDate&&new Date(i.DueDate)<new Date());
      L.push('\n## AR — Total: $'+total.toFixed(2)+' | Overdue: '+overdue.length);
      overdue.slice(0,10).forEach(i=>L.push('  - '+(i.CustomerRef?.name||'?')+': $'+(i.Balance||0).toFixed(2)+' ('+Math.floor((Date.now()-new Date(i.DueDate))/86400000)+'d)'));
    }
    if (data.bills?.length) {
      L.push('\n## AP — Total: $'+data.bills.reduce((s,b)=>s+(b.Balance||0),0).toFixed(2));
      data.bills.slice(0,10).forEach(b=>L.push('  - '+(b.VendorRef?.name||'?')+': $'+(b.Balance||0).toFixed(2)));
    }
  } else {
    if (data.profitLoss) L.push('## P&L\n'+JSON.stringify(data.profitLoss).slice(0,4000));
    if (data.invoices)   L.push('## Invoices\n'+JSON.stringify(data.invoices).slice(0,2000));
    if (data.bills)      L.push('## Bills\n'+JSON.stringify(data.bills).slice(0,2000));
  }
  return L.join('\n') || 'No financial data available.';
}

app.post('/api/analyse', auth, async (req, res) => {
  if (!CONFIG.anthropicKey) return res.status(400).json({ error:'AI not configured' });
  const conn = db.prepare('SELECT * FROM connections WHERE user_id=? ORDER BY created_at DESC LIMIT 1').get(req.user.id);
  if (!conn) return res.status(404).json({ error:'No accounting software connected' });
  const { financialData, question } = req.body;
  if (!financialData) return res.status(400).json({ error:'No financial data provided' });

  const summary = buildSummary(financialData, conn.provider);
  const system = `You are FlowGuard AI — a sharp CFO-level analyst for ${conn.tenant_name||'this business'} (${conn.provider.toUpperCase()} data).

Find: 1) Profit leaks with dollar amounts 2) Cash flow risks 3) Cost trends 4) Top actions this week.
Rules: Real numbers only. Biggest impact first. Direct like a CFO. Use ## headers.`;

  const prompt = question
    ? `Financial data:\n\n${summary}\n\nQuestion: ${question}`
    : `Financial data:\n\n${summary}\n\nGive a complete profit leak analysis: dollar amounts, cash flow risks, top 3 actions this week ranked by impact.`;

  try {
    const r = await axios.post('https://api.anthropic.com/v1/messages',
      { model:'claude-sonnet-4-20250514', max_tokens:2500, system, messages:[{ role:'user', content:prompt }] },
      { headers:{ 'x-api-key':CONFIG.anthropicKey, 'anthropic-version':'2023-06-01', 'Content-Type':'application/json' } }
    );
    const analysis = r.data.content.map(c=>c.text||'').join('');
    db.prepare('INSERT INTO analyses (user_id,question,result) VALUES (?,?,?)').run(req.user.id, question||null, analysis);
    res.json({ ok:true, analysis });
  } catch(err) {
    console.error('AI error:', err.response?.data||err.message);
    res.status(500).json({ error:'AI analysis failed: '+err.message });
  }
});

app.get('/api/analyses', auth, (req, res) => {
  res.json({ analyses: db.prepare('SELECT id,question,result,created_at FROM analyses WHERE user_id=? ORDER BY created_at DESC LIMIT 20').all(req.user.id) });
});

// ── STRIPE ────────────────────────────────────────────────────────────
let stripe = null;
if (CONFIG.stripeSecret) stripe = require('stripe')(CONFIG.stripeSecret);

app.post('/api/billing/checkout', auth, async (req, res) => {
  if (!stripe) return res.status(400).json({ error:'Billing not configured' });
  try {
    const s = await stripe.checkout.sessions.create({
      payment_method_types:['card'], mode:'subscription',
      line_items:[{ price:CONFIG.stripePriceId, quantity:1 }],
      customer_email:req.user.email,
      success_url:APP_URL+'/app?billing=success',
      cancel_url:APP_URL+'/app?billing=cancelled',
      metadata:{ user_id:String(req.user.id) },
    });
    res.json({ url:s.url });
  } catch(err) { res.status(500).json({ error:err.message }); }
});

app.post('/webhook/stripe', (req, res) => {
  if (!stripe||!CONFIG.stripeWebhook) return res.json({ received:true });
  let event;
  try { event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], CONFIG.stripeWebhook); }
  catch(err) { return res.status(400).send('Webhook error: '+err.message); }
  if (event.type==='checkout.session.completed' && event.data.object.metadata?.user_id) {
    const s = event.data.object;
    db.prepare('UPDATE users SET plan=?,stripe_customer_id=?,stripe_subscription_id=? WHERE id=?')
      .run('paid', s.customer, s.subscription, parseInt(s.metadata.user_id));
  }
  if (event.type==='customer.subscription.deleted') {
    db.prepare('UPDATE users SET plan=? WHERE stripe_customer_id=?').run('cancelled', event.data.object.customer);
  }
  res.json({ received:true });
});

// ── SERVE APP ─────────────────────────────────────────────────────────
app.get('/app', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('*',    (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── START — bind 0.0.0.0 for Railway ─────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log('\n✅ FlowGuard v3 running on port ' + PORT);
  console.log('   Xero:        ' + (CONFIG.xero.clientId        ? '✅' : '⚠️  XERO_CLIENT_ID not set'));
  console.log('   MYOB:        ' + (CONFIG.myob.clientId         ? '✅' : '⚠️  MYOB_CLIENT_ID not set'));
  console.log('   QuickBooks:  ' + (CONFIG.quickbooks.clientId   ? '✅' : '⚠️  QB_CLIENT_ID not set'));
  console.log('   Anthropic:   ' + (CONFIG.anthropicKey          ? '✅' : '⚠️  ANTHROPIC_API_KEY not set'));
  console.log('   Stripe:      ' + (CONFIG.stripeSecret          ? '✅' : 'ℹ️  disabled'));
});
