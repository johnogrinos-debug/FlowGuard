/**
 * FlowGuard — Production Server v4
 * Postgres DB · Xero + MYOB + QuickBooks OAuth · AI analysis · FlowScore · Auth · Stripe
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
const { Pool }     = require('pg');

const app = express();
app.use(cors({ origin: process.env.APP_URL || 'http://localhost:3000', credentials: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/webhook/stripe', express.raw({ type: 'application/json' }));
app.use(express.json());

// ── DATABASE (Postgres) ───────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('railway') ? { rejectUnauthorized: false } : false,
});

async function query(sql, params = []) {
  const client = await pool.connect();
  try {
    const result = await client.query(sql, params);
    return result;
  } finally {
    client.release();
  }
}

async function initDB() {
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id            SERIAL PRIMARY KEY,
      email         TEXT    UNIQUE NOT NULL,
      password_hash TEXT    NOT NULL,
      name          TEXT,
      company       TEXT,
      industry      TEXT,
      plan          TEXT    DEFAULT 'trial',
      trial_ends_at BIGINT,
      stripe_customer_id    TEXT,
      stripe_subscription_id TEXT,
      created_at    BIGINT  DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
    );
    CREATE TABLE IF NOT EXISTS connections (
      id            SERIAL PRIMARY KEY,
      user_id       INTEGER NOT NULL REFERENCES users(id),
      provider      TEXT    NOT NULL,
      tenant_id     TEXT,
      tenant_name   TEXT,
      access_token  TEXT,
      refresh_token TEXT,
      expires_at    BIGINT,
      realm_id      TEXT,
      created_at    BIGINT  DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
    );
    CREATE TABLE IF NOT EXISTS analyses (
      id          SERIAL PRIMARY KEY,
      user_id     INTEGER NOT NULL REFERENCES users(id),
      question    TEXT,
      result      TEXT,
      flow_score  INTEGER,
      created_at  BIGINT  DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
    );
    CREATE TABLE IF NOT EXISTS oauth_states (
      state      TEXT PRIMARY KEY,
      user_id    INTEGER,
      provider   TEXT,
      created_at BIGINT  DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
    );
  `);
  console.log('✅ Database ready');
}

initDB().catch(e => console.error('DB init error:', e.message));

setInterval(() => {
  query('DELETE FROM oauth_states WHERE created_at < $1', [Math.floor(Date.now()/1000) - 3600]).catch(() => {});
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
    scopes:       'openid profile email accounting.invoices.read accounting.reports.profitandloss.read accounting.reports.balancesheet.read accounting.contacts accounting.settings offline_access',
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

// ── INDUSTRY BENCHMARKS ───────────────────────────────────────────────
const BENCHMARKS = {
  trades:       { netMargin: [8,14],  labour: [38,42], cogs: [30,40], debtorDays: [30,45] },
  retail:       { netMargin: [5,10],  labour: [12,18], cogs: [50,60], debtorDays: [14,30] },
  hospitality:  { netMargin: [6,9],   labour: [30,35], cogs: [28,32], debtorDays: [7,21]  },
  professional: { netMargin: [15,25], labour: [45,55], cogs: [5,15],  debtorDays: [30,45] },
  health:       { netMargin: [12,20], labour: [50,60], cogs: [10,20], debtorDays: [14,30] },
  ecommerce:    { netMargin: [8,15],  labour: [10,18], cogs: [45,60], debtorDays: [1,7]   },
  manufacturing:{ netMargin: [8,15],  labour: [25,35], cogs: [40,55], debtorDays: [30,60] },
  other:        { netMargin: [8,15],  labour: [30,45], cogs: [30,50], debtorDays: [30,45] },
};

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────
async function auth(req, res, next) {
  const token = req.cookies?.fg_token || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const result = await query('SELECT * FROM users WHERE id = $1', [payload.userId]);
    if (!result.rows[0]) return res.status(401).json({ error: 'User not found' });
    req.user = result.rows[0];
    next();
  } catch(e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ── HEALTH ────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ ok: true, version: '4.0.0' }));

// ── SIGNUP ────────────────────────────────────────────────────────────
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name, company, industry } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
    const existing = await query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existing.rows[0]) return res.status(400).json({ error: 'An account with this email already exists' });
    const hash = await bcrypt.hash(password, 12);
    const trialEnds = Math.floor(Date.now()/1000) + 14*24*60*60;
    const result = await query(
      'INSERT INTO users (email, password_hash, name, company, industry, plan, trial_ends_at) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
      [email.toLowerCase(), hash, name||'', company||'', industry||'other', 'trial', trialEnds]
    );
    const user = result.rows[0];
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
    res.cookie('fg_token', token, { httpOnly:true, secure: process.env.NODE_ENV==='production', maxAge:30*24*60*60*1000, sameSite:'lax' });
    const { password_hash, ...safeUser } = user;
    res.json({ ok: true, user: safeUser, token });
  } catch(e) {
    console.error('Signup error:', e.message);
    res.status(500).json({ error: 'Signup failed: ' + e.message });
  }
});

// ── LOGIN ─────────────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const result = await query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    const user = result.rows[0];
    if (!user || !await bcrypt.compare(password, user.password_hash))
      return res.status(401).json({ error: 'Invalid email or password' });
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
    res.cookie('fg_token', token, { httpOnly:true, secure: process.env.NODE_ENV==='production', maxAge:30*24*60*60*1000, sameSite:'lax' });
    const { password_hash, ...safeUser } = user;
    res.json({ ok: true, user: safeUser, token });
  } catch(e) {
    res.status(500).json({ error: 'Login failed: ' + e.message });
  }
});

app.post('/api/auth/logout', (req, res) => { res.clearCookie('fg_token'); res.json({ ok: true }); });

app.get('/api/auth/me', auth, async (req, res) => {
  const { password_hash, ...safeUser } = req.user;
  const conn = await query('SELECT provider,tenant_name,created_at FROM connections WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1', [req.user.id]);
  const analyses = await query('SELECT COUNT(*) as count FROM analyses WHERE user_id=$1', [req.user.id]);
  res.json({ user: safeUser, connection: conn.rows[0]||null, analysisCount: parseInt(analyses.rows[0].count) });
});

// ── XERO OAUTH ────────────────────────────────────────────────────────
app.get('/auth/xero', auth, async (req, res) => {
  if (!CONFIG.xero.clientId) return res.redirect('/app?error=xero_not_configured');
  const state = crypto.randomBytes(16).toString('hex');
  await query('INSERT INTO oauth_states (state,user_id,provider) VALUES ($1,$2,$3)', [state, req.user.id, 'xero']);
  const params = new URLSearchParams({ response_type:'code', client_id:CONFIG.xero.clientId, redirect_uri:CONFIG.xero.redirectUri, scope:CONFIG.xero.scopes, state });
  res.redirect(CONFIG.xero.authUrl + '?' + params);
});

app.get('/callback/xero', async (req, res) => {
  const { code, state } = req.query;
  const stateResult = await query('SELECT * FROM oauth_states WHERE state=$1', [state]);
  const stateRow = stateResult.rows[0];
  if (!stateRow) return res.redirect('/app?error=invalid_state');
  await query('DELETE FROM oauth_states WHERE state=$1', [state]);
  try {
    const creds = Buffer.from(CONFIG.xero.clientId+':'+CONFIG.xero.clientSecret).toString('base64');
    const t = await axios.post(CONFIG.xero.tokenUrl,
      new URLSearchParams({ grant_type:'authorization_code', code, redirect_uri:CONFIG.xero.redirectUri }),
      { headers:{ Authorization:'Basic '+creds, 'Content-Type':'application/x-www-form-urlencoded' } }
    );
    const { access_token, refresh_token, expires_in } = t.data;
    const tenants = await axios.get('https://api.xero.com/connections', { headers:{ Authorization:'Bearer '+access_token } });
    const tenant = tenants.data.find(t => t.tenantName?.toLowerCase().includes('demo')) || tenants.data[tenants.data.length-1] || tenants.data[0];
    const ex = await query('SELECT id FROM connections WHERE user_id=$1 AND provider=$2', [stateRow.user_id,'xero']);
    if (ex.rows[0]) {
      await query('UPDATE connections SET tenant_id=$1,tenant_name=$2,access_token=$3,refresh_token=$4,expires_at=$5 WHERE id=$6',
        [tenant?.tenantId, tenant?.tenantName, access_token, refresh_token, Date.now()+expires_in*1000, ex.rows[0].id]);
    } else {
      await query('INSERT INTO connections (user_id,provider,tenant_id,tenant_name,access_token,refresh_token,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)',
        [stateRow.user_id,'xero',tenant?.tenantId,tenant?.tenantName,access_token,refresh_token,Date.now()+expires_in*1000]);
    }
    res.redirect('/app?connected=xero');
  } catch(err) {
    console.error('Xero error:', err.response?.data||err.message);
    res.redirect('/app?error=xero_auth_failed');
  }
});

// ── MYOB OAUTH ────────────────────────────────────────────────────────
app.get('/auth/myob', auth, async (req, res) => {
  if (!CONFIG.myob.clientId) return res.redirect('/app?error=myob_not_configured');
  const state = crypto.randomBytes(16).toString('hex');
  await query('INSERT INTO oauth_states (state,user_id,provider) VALUES ($1,$2,$3)', [state, req.user.id, 'myob']);
  const params = new URLSearchParams({ client_id:CONFIG.myob.clientId, redirect_uri:CONFIG.myob.redirectUri, response_type:'code', scope:CONFIG.myob.scopes, state });
  res.redirect(CONFIG.myob.authUrl + '?' + params);
});

app.get('/callback/myob', async (req, res) => {
  const { code, state } = req.query;
  const stateResult = await query('SELECT * FROM oauth_states WHERE state=$1', [state]);
  const stateRow = stateResult.rows[0];
  if (!stateRow) return res.redirect('/app?error=invalid_state');
  await query('DELETE FROM oauth_states WHERE state=$1', [state]);
  try {
    const t = await axios.post(CONFIG.myob.tokenUrl,
      new URLSearchParams({ client_id:CONFIG.myob.clientId, client_secret:CONFIG.myob.clientSecret, redirect_uri:CONFIG.myob.redirectUri, grant_type:'authorization_code', code }),
      { headers:{ 'Content-Type':'application/x-www-form-urlencoded' } }
    );
    const { access_token, refresh_token, expires_in } = t.data;
    const files = await axios.get(CONFIG.myob.apiBase+'/', { headers:{ Authorization:'Bearer '+access_token } });
    const file = files.data?.Items?.[0];
    const ex = await query('SELECT id FROM connections WHERE user_id=$1 AND provider=$2', [stateRow.user_id,'myob']);
    if (ex.rows[0]) {
      await query('UPDATE connections SET tenant_name=$1,access_token=$2,refresh_token=$3,expires_at=$4 WHERE id=$5',
        [file?.Name, access_token, refresh_token, Date.now()+(expires_in||1800)*1000, ex.rows[0].id]);
    } else {
      await query('INSERT INTO connections (user_id,provider,tenant_name,access_token,refresh_token,expires_at) VALUES ($1,$2,$3,$4,$5,$6)',
        [stateRow.user_id,'myob',file?.Name,access_token,refresh_token,Date.now()+(expires_in||1800)*1000]);
    }
    res.redirect('/app?connected=myob');
  } catch(err) {
    console.error('MYOB error:', err.response?.data||err.message);
    res.redirect('/app?error=myob_auth_failed');
  }
});

// ── QUICKBOOKS OAUTH ──────────────────────────────────────────────────
app.get('/auth/quickbooks', auth, async (req, res) => {
  if (!CONFIG.quickbooks.clientId) return res.redirect('/app?error=quickbooks_not_configured');
  const state = crypto.randomBytes(16).toString('hex');
  await query('INSERT INTO oauth_states (state,user_id,provider) VALUES ($1,$2,$3)', [state, req.user.id, 'quickbooks']);
  const params = new URLSearchParams({ client_id:CONFIG.quickbooks.clientId, redirect_uri:CONFIG.quickbooks.redirectUri, response_type:'code', scope:CONFIG.quickbooks.scopes, state });
  res.redirect(CONFIG.quickbooks.authUrl + '?' + params);
});

app.get('/callback/quickbooks', async (req, res) => {
  const { code, state, realmId } = req.query;
  const stateResult = await query('SELECT * FROM oauth_states WHERE state=$1', [state]);
  const stateRow = stateResult.rows[0];
  if (!stateRow) return res.redirect('/app?error=invalid_state');
  await query('DELETE FROM oauth_states WHERE state=$1', [state]);
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
    const ex = await query('SELECT id FROM connections WHERE user_id=$1 AND provider=$2', [stateRow.user_id,'quickbooks']);
    if (ex.rows[0]) {
      await query('UPDATE connections SET tenant_id=$1,tenant_name=$2,access_token=$3,refresh_token=$4,expires_at=$5,realm_id=$6 WHERE id=$7',
        [realmId, companyName, access_token, refresh_token, Date.now()+expires_in*1000, realmId, ex.rows[0].id]);
    } else {
      await query('INSERT INTO connections (user_id,provider,tenant_id,tenant_name,access_token,refresh_token,expires_at,realm_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
        [stateRow.user_id,'quickbooks',realmId,companyName,access_token,refresh_token,Date.now()+expires_in*1000,realmId]);
    }
    res.redirect('/app?connected=quickbooks');
  } catch(err) {
    console.error('QuickBooks error:', err.response?.data||err.message);
    res.redirect('/app?error=quickbooks_auth_failed');
  }
});

app.delete('/api/connection', auth, async (req, res) => {
  await query('DELETE FROM connections WHERE user_id=$1', [req.user.id]);
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
  await query('UPDATE connections SET access_token=$1,refresh_token=$2,expires_at=$3 WHERE id=$4',
    [r.data.access_token, r.data.refresh_token, Date.now()+r.data.expires_in*1000, conn.id]);
  return r.data.access_token;
}

async function getValidQBToken(conn) {
  if (Date.now() < conn.expires_at - 60000) return conn.access_token;
  const creds = Buffer.from(CONFIG.quickbooks.clientId+':'+CONFIG.quickbooks.clientSecret).toString('base64');
  const r = await axios.post(CONFIG.quickbooks.tokenUrl,
    new URLSearchParams({ grant_type:'refresh_token', refresh_token:conn.refresh_token }),
    { headers:{ Authorization:'Basic '+creds, 'Content-Type':'application/x-www-form-urlencoded', Accept:'application/json' } }
  );
  await query('UPDATE connections SET access_token=$1,refresh_token=$2,expires_at=$3 WHERE id=$4',
    [r.data.access_token, r.data.refresh_token, Date.now()+r.data.expires_in*1000, conn.id]);
  return r.data.access_token;
}

// ── FETCH DATA ────────────────────────────────────────────────────────
async function fetchXeroData(conn) {
  const token = await getValidXeroToken(conn);
  const headers = { Authorization:'Bearer '+token, 'Xero-tenant-id':conn.tenant_id, Accept:'application/json' };
  const toDate   = new Date().toISOString().split('T')[0];
  const fromDate = new Date(Date.now()-365*86400000).toISOString().split('T')[0];
  const [pl,bs,inv,bills] = await Promise.allSettled([
    axios.get(CONFIG.xero.apiBase+'/Reports/ProfitAndLoss', { headers, params:{ fromDate, toDate } }),
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
  const conn = await query('SELECT * FROM connections WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1', [req.user.id]);
  if (!conn.rows[0]) return res.status(404).json({ error:'No accounting software connected' });
  const c = conn.rows[0];
  try {
    const data =
      c.provider==='xero'        ? await fetchXeroData(c) :
      c.provider==='myob'        ? await fetchMYOBData(c) :
      c.provider==='quickbooks'  ? await fetchQuickBooksData(c) :
      (() => { throw new Error('Unknown provider: '+c.provider); })();
    res.json({ ok:true, provider:c.provider, company:c.tenant_name, data });
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
      L.push('## Profit & Loss');
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
      const overdueBills = data.bills.filter(b=>b.DueDate&&new Date(b.DueDate)<new Date());
      L.push('## Accounts Payable — Total: $'+data.bills.reduce((s,b)=>s+(b.AmountDue||0),0).toFixed(2));
      if (overdueBills.length) L.push('OVERDUE BILLS: '+overdueBills.length);
      data.bills.slice(0,10).forEach(b=>L.push('  - '+(b.Contact?.Name||'?')+': $'+(b.AmountDue||0).toFixed(2)+(new Date(b.DueDate)<new Date()?' OVERDUE':'')));
      L.push('');
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
  const conn = await query('SELECT * FROM connections WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1', [req.user.id]);
  if (!conn.rows[0]) return res.status(404).json({ error:'No accounting software connected' });
  const c = conn.rows[0];
  const { financialData, question } = req.body;
  if (!financialData) return res.status(400).json({ error:'No financial data provided' });

  const summary = buildSummary(financialData, c.provider);
  const industry = req.user.industry || 'other';
  const bench = BENCHMARKS[industry] || BENCHMARKS.other;

  const system = `You are FlowGuard AI — a senior CFO and business advisor for ${c.tenant_name||'this business'} using live ${c.provider.toUpperCase()} data.

Your job: Find every profit leak, give specific recommendations, and tell the owner exactly what to do and how to save money.

INDUSTRY BENCHMARKS for ${industry}:
- Net margin benchmark: ${bench.netMargin[0]}–${bench.netMargin[1]}%
- Labour/wages benchmark: ${bench.labour[0]}–${bench.labour[1]}% of revenue
- COGS benchmark: ${bench.cogs[0]}–${bench.cogs[1]}% of revenue
- Debtor days benchmark: ${bench.debtorDays[0]}–${bench.debtorDays[1]} days

ANALYSIS STRUCTURE — use these exact ## headers:

## 🔍 Profit Leak Analysis
List every profit leak with: what it is, exact dollar amount, what benchmark should be, and how much is being lost vs benchmark.

## 💰 Cash Flow Assessment
Cash position, runway in weeks, overdue invoices with specific client names and amounts. Rate as: Critical / Warning / Healthy.

## 📊 Expense Breakdown
Top expenses as % of revenue. Flag anything above benchmark. Compare to industry standard.

## ✅ Recommendations — What To Do This Week
Exactly 5 specific actions ranked by dollar impact. Each must include:
- The specific action (name the client, invoice, supplier)
- The expected dollar saving or recovery
- How to do it (brief method or script)

## 🚀 90-Day Growth Plan
3 bigger moves to improve profitability over the next 3 months with estimated dollar impact each.

## 📈 FlowScore: [X]/100
Score out of 100 and the single most important thing to fix first.

RULES:
- Use real numbers only. Never say "significant" — say the dollar amount.
- Be direct. If the business is in trouble, say so clearly.
- Every recommendation must be actionable TODAY.
- Name specific clients, suppliers where visible in the data.`;

  const prompt = question
    ? `Financial data:\n\n${summary}\n\nQuestion: ${question}\n\nAnswer with specific dollar amounts and a concrete step-by-step recommendation.`
    : `Financial data:\n\n${summary}\n\nDeliver the complete FlowGuard analysis using all sections. Be specific with every number.`;

  try {
    const r = await axios.post('https://api.anthropic.com/v1/messages',
      { model:'claude-haiku-4-5-20251001', max_tokens:3000, system, messages:[{ role:'user', content:prompt }] },
      { headers:{ 'x-api-key':CONFIG.anthropicKey, 'anthropic-version':'2023-06-01', 'Content-Type':'application/json' } }
    );
    const analysis = r.data.content.map(c=>c.text||'').join('');
    const scoreMatch = analysis.match(/FlowScore[:\s]+(\d+)/i);
    const flowScore = scoreMatch ? parseInt(scoreMatch[1]) : null;
    await query('INSERT INTO analyses (user_id,question,result,flow_score) VALUES ($1,$2,$3,$4)',
      [req.user.id, question||null, analysis, flowScore]);
    res.json({ ok:true, analysis, flowScore });
  } catch(err) {
    console.error('AI error full:', JSON.stringify(err.response?.data||err.message));
    res.status(500).json({ error:'AI analysis failed: '+(err.response?.data?.error?.message||err.message) });
  }
});

app.get('/api/analyses', auth, async (req, res) => {
  const result = await query('SELECT id,question,result,flow_score,created_at FROM analyses WHERE user_id=$1 ORDER BY created_at DESC LIMIT 20', [req.user.id]);
  res.json({ analyses: result.rows });
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
    query('UPDATE users SET plan=$1,stripe_customer_id=$2,stripe_subscription_id=$3 WHERE id=$4',
      ['paid', s.customer, s.subscription, parseInt(s.metadata.user_id)]).catch(console.error);
  }
  if (event.type==='customer.subscription.deleted') {
    query('UPDATE users SET plan=$1 WHERE stripe_customer_id=$2', ['cancelled', event.data.object.customer]).catch(console.error);
  }
  res.json({ received:true });
});

// ── SERVE APP ─────────────────────────────────────────────────────────
app.get('/app', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('*',    (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── START ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log('\n✅ FlowGuard v4 running on port ' + PORT);
  console.log('   Database:    ' + (process.env.DATABASE_URL ? '✅ Postgres' : '⚠️  No DATABASE_URL'));
  console.log('   Xero:        ' + (CONFIG.xero.clientId        ? '✅' : '⚠️  not configured'));
  console.log('   Anthropic:   ' + (CONFIG.anthropicKey          ? '✅' : '⚠️  not configured'));
});
