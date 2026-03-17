/**
 * FlowGuard — Production Server
 * User auth, Xero/MYOB OAuth, AI analysis, Stripe billing
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

// Raw body for Stripe webhooks
app.use('/webhook/stripe', express.raw({ type: 'application/json' }));
app.use(express.json());

// ════════════════════════════════════════════════════
// DATABASE — SQLite (zero config, persists on Railway volume)
// ════════════════════════════════════════════════════
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

// Clean old oauth states every hour
setInterval(() => {
  db.prepare('DELETE FROM oauth_states WHERE created_at < ?').run(Math.floor(Date.now()/1000) - 3600);
}, 3600000);

// ════════════════════════════════════════════════════
// CONFIG
// ════════════════════════════════════════════════════
const APP_URL = process.env.APP_URL || 'http://localhost:3000';
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_in_production';

const CONFIG = {
  xero: {
    clientId:     process.env.XERO_CLIENT_ID     || '',
    clientSecret: process.env.XERO_CLIENT_SECRET || '',
    redirectUri:  APP_URL + '/callback/xero',
    authUrl:      'https://login.xero.com/identity/connect/authorize',
    tokenUrl:     'https://identity.xero.com/connect/token',
    apiBase:      'https://api.xero.com/api.xro/2.0',
    scopes:       'openid profile email accounting.reports.read accounting.transactions.read accounting.settings.read offline_access',
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
  anthropicKey:  process.env.ANTHROPIC_API_KEY  || '',
  stripeSecret:  process.env.STRIPE_SECRET_KEY  || '',
  stripeWebhook: process.env.STRIPE_WEBHOOK_SECRET || '',
  stripePriceId: process.env.STRIPE_PRICE_ID    || '',
};

// ════════════════════════════════════════════════════
// AUTH MIDDLEWARE
// ════════════════════════════════════════════════════
function authMiddleware(req, res, next) {
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

function optionalAuth(req, res, next) {
  const token = req.cookies?.fg_token || req.headers.authorization?.replace('Bearer ', '');
  if (token) {
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      req.user = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.userId);
    } catch(e) {}
  }
  next();
}

// ════════════════════════════════════════════════════
// HEALTH CHECK
// ════════════════════════════════════════════════════
app.get('/health', (req, res) => res.json({ ok: true, version: '2.0.0' }));

// ════════════════════════════════════════════════════
// AUTH ROUTES
// ════════════════════════════════════════════════════

// Sign up
app.post('/api/auth/signup', async (req, res) => {
  const { email, password, name, company } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
  if (existing) return res.status(400).json({ error: 'An account with this email already exists' });

  const hash = await bcrypt.hash(password, 12);
  const trialEnds = Math.floor(Date.now()/1000) + (14 * 24 * 60 * 60); // 14 days

  const result = db.prepare(
    'INSERT INTO users (email, password_hash, name, company, plan, trial_ends_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(email.toLowerCase(), hash, name || '', company || '', 'trial', trialEnds);

  const token = jwt.sign({ userId: result.lastInsertRowid }, JWT_SECRET, { expiresIn: '30d' });
  res.cookie('fg_token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });

  const user = db.prepare('SELECT id, email, name, company, plan, trial_ends_at FROM users WHERE id = ?').get(result.lastInsertRowid);
  res.json({ ok: true, user, token });
});

// Log in
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid email or password' });

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
  res.cookie('fg_token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });

  const { password_hash, ...safeUser } = user;
  res.json({ ok: true, user: safeUser, token });
});

// Log out
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('fg_token');
  res.json({ ok: true });
});

// Get current user
app.get('/api/auth/me', authMiddleware, (req, res) => {
  const { password_hash, ...safeUser } = req.user;
  const connection = db.prepare('SELECT provider, tenant_name, created_at FROM connections WHERE user_id = ? ORDER BY created_at DESC LIMIT 1').get(req.user.id);
  const analysisCount = db.prepare('SELECT COUNT(*) as count FROM analyses WHERE user_id = ?').get(req.user.id);
  res.json({ user: safeUser, connection: connection || null, analysisCount: analysisCount.count });
});

// ════════════════════════════════════════════════════
// XERO OAUTH
// ════════════════════════════════════════════════════
app.get('/auth/xero', authMiddleware, (req, res) => {
  if (!CONFIG.xero.clientId) return res.redirect('/app?error=xero_not_configured');
  const state = crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO oauth_states (state, user_id, provider) VALUES (?, ?, ?)').run(state, req.user.id, 'xero');
  const params = new URLSearchParams({ response_type: 'code', client_id: CONFIG.xero.clientId, redirect_uri: CONFIG.xero.redirectUri, scope: CONFIG.xero.scopes, state });
  res.redirect(CONFIG.xero.authUrl + '?' + params);
});

app.get('/callback/xero', async (req, res) => {
  const { code, state } = req.query;
  const stateRow = db.prepare('SELECT * FROM oauth_states WHERE state = ?').get(state);
  if (!stateRow) return res.redirect('/app?error=invalid_state');
  db.prepare('DELETE FROM oauth_states WHERE state = ?').run(state);

  try {
    const creds = Buffer.from(CONFIG.xero.clientId + ':' + CONFIG.xero.clientSecret).toString('base64');
    const tokenRes = await axios.post(CONFIG.xero.tokenUrl,
      new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: CONFIG.xero.redirectUri }),
      { headers: { Authorization: 'Basic ' + creds, 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    const { access_token, refresh_token, expires_in } = tokenRes.data;
    const tenantsRes = await axios.get('https://api.xero.com/connections', { headers: { Authorization: 'Bearer ' + access_token } });
    const tenant = tenantsRes.data[0];

    // Upsert connection
    const existing = db.prepare('SELECT id FROM connections WHERE user_id = ? AND provider = ?').get(stateRow.user_id, 'xero');
    if (existing) {
      db.prepare('UPDATE connections SET tenant_id=?, tenant_name=?, access_token=?, refresh_token=?, expires_at=? WHERE id=?')
        .run(tenant?.tenantId, tenant?.tenantName, access_token, refresh_token, Date.now() + expires_in * 1000, existing.id);
    } else {
      db.prepare('INSERT INTO connections (user_id, provider, tenant_id, tenant_name, access_token, refresh_token, expires_at) VALUES (?,?,?,?,?,?,?)')
        .run(stateRow.user_id, 'xero', tenant?.tenantId, tenant?.tenantName, access_token, refresh_token, Date.now() + expires_in * 1000);
    }
    res.redirect('/app?connected=xero');
  } catch (err) {
    console.error('Xero callback error:', err.response?.data || err.message);
    res.redirect('/app?error=xero_auth_failed');
  }
});

// ════════════════════════════════════════════════════
// MYOB OAUTH
// ════════════════════════════════════════════════════
app.get('/auth/myob', authMiddleware, (req, res) => {
  if (!CONFIG.myob.clientId) return res.redirect('/app?error=myob_not_configured');
  const state = crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO oauth_states (state, user_id, provider) VALUES (?, ?, ?)').run(state, req.user.id, 'myob');
  const params = new URLSearchParams({ client_id: CONFIG.myob.clientId, redirect_uri: CONFIG.myob.redirectUri, response_type: 'code', scope: CONFIG.myob.scopes, state });
  res.redirect(CONFIG.myob.authUrl + '?' + params);
});

app.get('/callback/myob', async (req, res) => {
  const { code, state } = req.query;
  const stateRow = db.prepare('SELECT * FROM oauth_states WHERE state = ?').get(state);
  if (!stateRow) return res.redirect('/app?error=invalid_state');
  db.prepare('DELETE FROM oauth_states WHERE state = ?').run(state);

  try {
    const tokenRes = await axios.post(CONFIG.myob.tokenUrl,
      new URLSearchParams({ client_id: CONFIG.myob.clientId, client_secret: CONFIG.myob.clientSecret, redirect_uri: CONFIG.myob.redirectUri, grant_type: 'authorization_code', code }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    const { access_token, refresh_token, expires_in } = tokenRes.data;
    const filesRes = await axios.get(CONFIG.myob.apiBase + '/', { headers: { Authorization: 'Bearer ' + access_token } });
    const file = filesRes.data?.Items?.[0];

    const existing = db.prepare('SELECT id FROM connections WHERE user_id = ? AND provider = ?').get(stateRow.user_id, 'myob');
    if (existing) {
      db.prepare('UPDATE connections SET tenant_name=?, access_token=?, refresh_token=?, expires_at=? WHERE id=?')
        .run(file?.Name, access_token, refresh_token, Date.now() + (expires_in || 1800) * 1000, existing.id);
    } else {
      db.prepare('INSERT INTO connections (user_id, provider, tenant_name, access_token, refresh_token, expires_at) VALUES (?,?,?,?,?,?)')
        .run(stateRow.user_id, 'myob', file?.Name, access_token, refresh_token, Date.now() + (expires_in || 1800) * 1000);
    }
    res.redirect('/app?connected=myob');
  } catch (err) {
    console.error('MYOB callback error:', err.response?.data || err.message);
    res.redirect('/app?error=myob_auth_failed');
  }
});

// Disconnect
app.delete('/api/connection', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM connections WHERE user_id = ?').run(req.user.id);
  res.json({ ok: true });
});

// ════════════════════════════════════════════════════
// TOKEN REFRESH
// ════════════════════════════════════════════════════
async function getValidXeroToken(conn) {
  if (Date.now() < conn.expires_at - 60000) return conn.access_token;
  const creds = Buffer.from(CONFIG.xero.clientId + ':' + CONFIG.xero.clientSecret).toString('base64');
  const res = await axios.post(CONFIG.xero.tokenUrl,
    new URLSearchParams({ grant_type: 'refresh_token', refresh_token: conn.refresh_token }),
    { headers: { Authorization: 'Basic ' + creds, 'Content-Type': 'application/x-www-form-urlencoded' } }
  );
  db.prepare('UPDATE connections SET access_token=?, refresh_token=?, expires_at=? WHERE id=?')
    .run(res.data.access_token, res.data.refresh_token, Date.now() + res.data.expires_in * 1000, conn.id);
  return res.data.access_token;
}

// ════════════════════════════════════════════════════
// FETCH FINANCIAL DATA
// ════════════════════════════════════════════════════
async function fetchXeroData(conn) {
  const token    = await getValidXeroToken(conn);
  const tenantId = conn.tenant_id;
  const headers  = { Authorization: 'Bearer ' + token, 'Xero-tenant-id': tenantId, Accept: 'application/json' };
  const toDate   = new Date().toISOString().split('T')[0];
  const fromDate = new Date(Date.now() - 365 * 86400000).toISOString().split('T')[0];

  const [plRes, bsRes, invoicesRes, billsRes] = await Promise.allSettled([
    axios.get(CONFIG.xero.apiBase + '/Reports/ProfitAndLoss', { headers, params: { fromDate, toDate, periods: 12, timeframe: 'MONTH' } }),
    axios.get(CONFIG.xero.apiBase + '/Reports/BalanceSheet',  { headers, params: { date: toDate } }),
    axios.get(CONFIG.xero.apiBase + '/Invoices', { headers, params: { where: 'Status=="AUTHORISED"&&Type=="ACCREC"', order: 'DueDate ASC', pageSize: 100 } }),
    axios.get(CONFIG.xero.apiBase + '/Invoices', { headers, params: { where: 'Status=="AUTHORISED"&&Type=="ACCPAY"', order: 'DueDate ASC', pageSize: 100 } }),
  ]);

  return {
    profitLoss:   plRes.status       === 'fulfilled' ? plRes.value.data                  : null,
    balanceSheet: bsRes.status       === 'fulfilled' ? bsRes.value.data                  : null,
    invoices:     invoicesRes.status === 'fulfilled' ? (invoicesRes.value.data?.Invoices || []) : [],
    bills:        billsRes.status    === 'fulfilled' ? (billsRes.value.data?.Invoices    || []) : [],
  };
}

async function fetchMYOBData(conn) {
  const token   = conn.access_token;
  const headers = { Authorization: 'Bearer ' + token, 'x-myobapi-key': CONFIG.myob.clientId };
  // Get company file URI
  const filesRes = await axios.get(CONFIG.myob.apiBase + '/', { headers });
  const base = filesRes.data?.Items?.[0]?.Uri;
  if (!base) throw new Error('No MYOB company file found');

  const [plRes, invRes, billRes] = await Promise.allSettled([
    axios.get(base + '/GeneralLedger/ProfitAndLoss', { headers }),
    axios.get(base + '/Sale/Invoice',   { headers, params: { '$top': 100, '$filter': "Status eq 'Open'" } }),
    axios.get(base + '/Purchase/Bill',  { headers, params: { '$top': 100, '$filter': "Status eq 'Open'" } }),
  ]);

  return {
    profitLoss: plRes.status  === 'fulfilled' ? plRes.value.data  : null,
    invoices:   invRes.status === 'fulfilled' ? invRes.value.data : null,
    bills:      billRes.status === 'fulfilled' ? billRes.value.data : null,
  };
}

// ════════════════════════════════════════════════════
// DATA API
// ════════════════════════════════════════════════════
app.get('/api/data', authMiddleware, async (req, res) => {
  const conn = db.prepare('SELECT * FROM connections WHERE user_id = ? ORDER BY created_at DESC LIMIT 1').get(req.user.id);
  if (!conn) return res.status(404).json({ error: 'No accounting software connected' });

  try {
    const data = conn.provider === 'xero' ? await fetchXeroData(conn) : await fetchMYOBData(conn);
    res.json({ ok: true, provider: conn.provider, company: conn.tenant_name, data });
  } catch (err) {
    console.error('Data fetch error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to fetch data: ' + err.message });
  }
});

// ════════════════════════════════════════════════════
// AI ANALYSIS
// ════════════════════════════════════════════════════
function buildFinancialSummary(data, provider) {
  const lines = [];

  if (provider === 'xero') {
    if (data.profitLoss?.Reports?.[0]) {
      lines.push('## Profit & Loss (Last 12 months by month)');
      data.profitLoss.Reports[0].Rows?.forEach(row => {
        if (['Section','Row','SummaryRow'].includes(row.RowType)) {
          const cells = row.Cells?.map(c => c.Value).join(' | ');
          if (cells) lines.push(cells);
          row.Rows?.forEach(r => {
            const rc = r.Cells?.map(c => c.Value).join(' | ');
            if (rc) lines.push('  ' + rc);
          });
        }
      });
      lines.push('');
    }
    if (data.balanceSheet?.Reports?.[0]) {
      lines.push('## Balance Sheet');
      data.balanceSheet.Reports[0].Rows?.forEach(row => {
        row.Rows?.forEach(r => {
          const rc = r.Cells?.map(c => c.Value).join(' | ');
          if (rc) lines.push('  ' + rc);
        });
      });
      lines.push('');
    }
    if (data.invoices?.length) {
      const total   = data.invoices.reduce((s, i) => s + (i.AmountDue || 0), 0);
      const overdue = data.invoices.filter(i => i.DueDate && new Date(i.DueDate) < new Date());
      lines.push('## Accounts Receivable (Outstanding Invoices)');
      lines.push('Total AR: $' + total.toFixed(2));
      lines.push('Overdue: ' + overdue.length + ' invoices, $' + overdue.reduce((s,i) => s+(i.AmountDue||0),0).toFixed(2));
      overdue.slice(0, 10).forEach(inv => {
        const d = Math.floor((Date.now() - new Date(inv.DueDate)) / 86400000);
        lines.push('  - ' + (inv.Contact?.Name||'Unknown') + ': $' + (inv.AmountDue||0).toFixed(2) + ' (' + d + ' days overdue)');
      });
      lines.push('');
    }
    if (data.bills?.length) {
      const total = data.bills.reduce((s, b) => s + (b.AmountDue || 0), 0);
      const overdue = data.bills.filter(b => b.DueDate && new Date(b.DueDate) < new Date());
      lines.push('## Accounts Payable (Outstanding Bills)');
      lines.push('Total AP: $' + total.toFixed(2));
      lines.push('Overdue: ' + overdue.length + ' bills');
      data.bills.slice(0, 10).forEach(b => lines.push('  - ' + (b.Contact?.Name||'Unknown') + ': $' + (b.AmountDue||0).toFixed(2) + ' due ' + (b.DueDate?.split('T')[0]||'?')));
      lines.push('');
    }
  } else {
    if (data.profitLoss) lines.push('## P&L\n' + JSON.stringify(data.profitLoss).slice(0, 4000));
    if (data.invoices)   lines.push('## Invoices\n' + JSON.stringify(data.invoices).slice(0, 2000));
    if (data.bills)      lines.push('## Bills\n' + JSON.stringify(data.bills).slice(0, 2000));
  }

  return lines.join('\n') || 'No financial data available.';
}

app.post('/api/analyse', authMiddleware, async (req, res) => {
  if (!CONFIG.anthropicKey) return res.status(400).json({ error: 'AI not configured — add ANTHROPIC_API_KEY' });

  const conn = db.prepare('SELECT * FROM connections WHERE user_id = ? ORDER BY created_at DESC LIMIT 1').get(req.user.id);
  if (!conn) return res.status(404).json({ error: 'No accounting software connected' });

  const { financialData, question } = req.body;
  if (!financialData) return res.status(400).json({ error: 'No financial data provided' });

  const summary = buildFinancialSummary(financialData, conn.provider);

  const system = `You are FlowGuard AI, a sharp financial analyst for small and medium businesses. You have been given REAL financial data from ${conn.tenant_name || 'a business'} via ${conn.provider.toUpperCase()}.

Analyse this data to identify:
1. Profit leaks — exactly where money is being lost or margin is eroding, with specific dollar amounts
2. Cash flow risks — overdue invoices, upcoming payment pressure, dangerous AR/AP ratios
3. Cost trends — which expense lines are growing faster than revenue
4. Quick wins — specific actions the business owner can take THIS WEEK to improve financial health

Rules:
- Use the actual numbers from the data. Be specific.
- Prioritise by impact — biggest problems first.
- Give actionable recommendations, not generic advice.
- Format with ## section headers.
- Be direct like a CFO, not soft like a consultant.
- If you spot something serious, say so clearly.`;

  const prompt = question
    ? `Financial data for ${conn.tenant_name}:\n\n${summary}\n\nBusiness owner's question: ${question}`
    : `Financial data for ${conn.tenant_name}:\n\n${summary}\n\nProvide a complete analysis: profit leaks with dollar amounts, cash flow risks, cost trends, and the top 3 actions to take this week.`;

  try {
    const aiRes = await axios.post('https://api.anthropic.com/v1/messages', {
      model:      'claude-sonnet-4-20250514',
      max_tokens: 2500,
      system,
      messages: [{ role: 'user', content: prompt }],
    }, {
      headers: { 'x-api-key': CONFIG.anthropicKey, 'anthropic-version': '2023-06-01', 'Content-Type': 'application/json' }
    });

    const analysis = aiRes.data.content.map(c => c.text || '').join('');

    // Save to history
    db.prepare('INSERT INTO analyses (user_id, question, result) VALUES (?, ?, ?)').run(req.user.id, question || null, analysis);

    res.json({ ok: true, analysis });
  } catch (err) {
    console.error('AI error:', err.response?.data || err.message);
    res.status(500).json({ error: 'AI analysis failed: ' + err.message });
  }
});

// Get analysis history
app.get('/api/analyses', authMiddleware, (req, res) => {
  const analyses = db.prepare('SELECT id, question, result, created_at FROM analyses WHERE user_id = ? ORDER BY created_at DESC LIMIT 20').all(req.user.id);
  res.json({ analyses });
});

// ════════════════════════════════════════════════════
// STRIPE BILLING
// ════════════════════════════════════════════════════
let stripe = null;
if (CONFIG.stripeSecret) {
  stripe = require('stripe')(CONFIG.stripeSecret);
}

// Create checkout session
app.post('/api/billing/checkout', authMiddleware, async (req, res) => {
  if (!stripe) return res.status(400).json({ error: 'Billing not configured' });
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'subscription',
      line_items: [{ price: CONFIG.stripePriceId, quantity: 1 }],
      customer_email: req.user.email,
      success_url: APP_URL + '/app?billing=success',
      cancel_url:  APP_URL + '/app?billing=cancelled',
      metadata: { user_id: String(req.user.id) },
    });
    res.json({ url: session.url });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Customer portal
app.post('/api/billing/portal', authMiddleware, async (req, res) => {
  if (!stripe || !req.user.stripe_customer_id) return res.status(400).json({ error: 'No billing account found' });
  try {
    const session = await stripe.billingPortal.sessions.create({
      customer: req.user.stripe_customer_id,
      return_url: APP_URL + '/app',
    });
    res.json({ url: session.url });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Stripe webhook
app.post('/webhook/stripe', (req, res) => {
  if (!stripe || !CONFIG.stripeWebhook) return res.json({ received: true });
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], CONFIG.stripeWebhook);
  } catch (err) {
    return res.status(400).send('Webhook error: ' + err.message);
  }

  if (event.type === 'checkout.session.completed') {
    const s = event.data.object;
    if (s.metadata?.user_id) {
      db.prepare('UPDATE users SET plan=?, stripe_customer_id=?, stripe_subscription_id=? WHERE id=?')
        .run('paid', s.customer, s.subscription, parseInt(s.metadata.user_id));
    }
  }
  if (event.type === 'customer.subscription.deleted') {
    const s = event.data.object;
    db.prepare('UPDATE users SET plan=? WHERE stripe_customer_id=?').run('cancelled', s.customer);
  }

  res.json({ received: true });
});

// ════════════════════════════════════════════════════
// SERVE APP — all routes go to index.html
// ════════════════════════════════════════════════════
app.get('/app', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ════════════════════════════════════════════════════
// START
// ════════════════════════════════════════════════════
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('\n✅ FlowGuard running at http://localhost:' + PORT);
  if (!CONFIG.xero.clientId)   console.log('⚠️  XERO_CLIENT_ID not set');
  if (!CONFIG.anthropicKey)    console.log('⚠️  ANTHROPIC_API_KEY not set');
  if (!CONFIG.stripeSecret)    console.log('ℹ️  STRIPE_SECRET_KEY not set — billing disabled');
});
