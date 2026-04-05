// ═══════════════════════════════════════════════════════════════
// UPI FRAUD DETECTION SERVER
// Node.js + Express + PostgreSQL
// ═══════════════════════════════════════════════════════════════

const express   = require('express');
const pool      = require('./db');
const bcrypt    = require('bcrypt');
const jwt       = require('jsonwebtoken');
const cors      = require('cors');
const path      = require('path');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// ── DATABASE CONNECTION ─────────────────────────────────────────
// const pool = new Pool({
//   connectionString: process.env.DATABASE_URL,
//     ssl: { rejectUnauthorized: false }
// });

const JWT_SECRET = process.env.JWT_SECRET || 'upi-fraud-secret-2024';

// ── AUTH MIDDLEWARE ─────────────────────────────────────────────
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// ════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ════════════════════════════════════════════════════════════════

// POST /auth/login  — mobile + 6-digit PIN
app.post('/auth/login', async (req, res) => {
  const { mobile, pin } = req.body;
  if (!mobile || !pin)
    return res.status(400).json({ error: 'Mobile and PIN required' });

  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE mobile_number = $1 AND is_active = true',
      [mobile.trim()]
    );
    if (result.rows.length === 0)
      return res.status(401).json({ error: 'Mobile number not registered' });

    const user = result.rows[0];
    const valid = await bcrypt.compare(pin.toString(), user.pin_hash);
    if (!valid)
      return res.status(401).json({ error: 'Incorrect PIN' });

    const token = jwt.sign(
      { userId: user.id, mobile: user.mobile_number },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: { id: user.id, name: user.name, mobile: user.mobile_number }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ════════════════════════════════════════════════════════════════
// ACCOUNT ROUTES  (requires login)
// ════════════════════════════════════════════════════════════════

// GET /accounts — returns all accounts for logged-in user
app.get('/accounts', auth, async (req, res) => {

  try {

    console.log("User from token:", req.user);

    const userId = req.user.userId || req.user.id;

    const personal = await pool.query(
      `SELECT id, account_number, bank_name, balance
       FROM personal_accounts
       WHERE user_id = $1`,
      [userId]
    );

    const merchant = await pool.query(
      `SELECT id, account_number, bank_name, balance
       FROM merchant_accounts
       WHERE user_id = $1`,
      [userId]
    );

    res.json({
      personal: personal.rows,
      merchant: merchant.rows
    });

  } catch (err) {

    console.error("Accounts API error:", err);
    res.status(500).json({ error: "Server error" });

  }

});

// GET /accounts/personal/:id — single personal account full details
app.get('/accounts/personal/:id', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT pa.*, u.name, u.mobile_number
       FROM personal_accounts pa
       JOIN users u ON pa.user_id = u.id
       WHERE pa.id = $1 AND pa.user_id = $2`,
      [req.params.id, req.user.userId]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ error: 'Account not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch account' });
  }
});

// GET /accounts/merchant/:id — single merchant account full details
app.get('/accounts/merchant/:id', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT ma.*, u.name, u.mobile_number
       FROM merchant_accounts ma
       JOIN users u ON ma.user_id = u.id
       WHERE ma.id = $1 AND ma.user_id = $2`,
      [req.params.id, req.user.userId]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ error: 'Account not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch account' });
  }
});

// GET /transactions/:accountId?type=personal|merchant&limit=50
app.get('/transactions/:accountId', auth, async (req, res) => {
  const { accountId } = req.params;
  const { type = 'personal', limit = 50 } = req.query;
  try {
    const result = await pool.query(
      `SELECT * FROM transactions
       WHERE account_id = $1 AND account_table = $2
       ORDER BY created_at DESC
       LIMIT $3`,
      [accountId, type, parseInt(limit)]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

// ════════════════════════════════════════════════════════════════
// VPA FRAUD ANALYSIS
// ════════════════════════════════════════════════════════════════
app.get('/vpa/analyse', auth, async (req, res) => {
  const { vpa, amount = 0 } = req.query;
  if (!vpa) return res.status(400).json({ error: 'VPA required' });

  try {
    const handle = vpa.split('@')[1]?.toLowerCase() || '';
    const vpaPart = vpa.split('@')[0]?.toLowerCase() || '';

    // Check personal accounts
    let profile = null, accountType = null;
    const personal = await pool.query(
      `SELECT pa.*, u.name as holder_name FROM personal_accounts pa
       JOIN users u ON pa.user_id = u.id
       WHERE pa.vpa_address = $1`, [vpa]
    );
    if (personal.rows.length > 0) {
      profile = personal.rows[0]; accountType = 'personal';
    } else {
      const merchant = await pool.query(
        `SELECT ma.*, u.name as holder_name FROM merchant_accounts ma
         JOIN users u ON ma.user_id = u.id
         WHERE ma.vpa_address = $1`, [vpa]
      );
      if (merchant.rows.length > 0) {
        profile = merchant.rows[0]; accountType = 'merchant';
      }
    }

    // Check bank handle validity
    const handleCheck = await pool.query(
      'SELECT * FROM bank_handles WHERE handle = $1', [handle]
    );
    const bankInfo = handleCheck.rows[0];

    if (!profile) {
      // Unknown VPA — analyse string only
      const score = scoreUnknownVpa(vpaPart, handle, bankInfo, parseFloat(amount));
      return res.json({ found: false, vpa, ...score });
    }

    // Known VPA — full analysis
    const result = scoreKnownVpa(profile, accountType, bankInfo, parseFloat(amount));
    res.json({
      found: true, vpa, accountType,
      profile: {
        name: profile.holder_name || profile.business_name,
        bank: profile.bank_name,
        handle: profile.bank_handle,
        kyc: profile.kyc_status,
        accountAge: Math.floor((Date.now() - new Date(profile.created_at)) / 86400000),
        totalTxns: profile.total_transactions,
        reportCount: profile.report_count,
        confirmedFraud: profile.confirmed_fraud,
      },
      ...result
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Analysis failed' });
  }
});

function scoreUnknownVpa(vpaPart, handle, bankInfo, amount) {
  let score = 20; // Base unknown penalty
  const factors = [];

  if (!bankInfo) {
    score += 15;
    factors.push({ label: 'Unknown Bank Handle', level: 'danger', impact: 15, reason: `@${handle} is not a registered UPI bank handle` });
  } else {
    score -= 5;
    factors.push({ label: 'Valid Bank Handle', level: 'positive', impact: -5, reason: `${bankInfo.bank_name} is a registered bank` });
  }

  const impersonateKW = ['amazon','flipkart','sbi','hdfc','icici','rbi','npci','google','police','government'];
  const suspiciousKW  = ['prize','win','claim','refund','helpdesk','loan','earn','profit','quick','fund','reward','lucky','lottery','kyc','urgent'];
  const foundImp  = impersonateKW.filter(k => vpaPart.includes(k));
  const foundSusp = suspiciousKW.filter(k => vpaPart.includes(k));

  if (foundImp.length > 0) {
    score += 25;
    factors.push({ label: 'Impersonation Keyword', level: 'danger', impact: 25, reason: `VPA contains "${foundImp[0]}" — fraudsters impersonate banks/brands` });
  }
  if (foundSusp.length > 1) {
    score += 15;
    factors.push({ label: 'Multiple Fraud Keywords', level: 'danger', impact: 15, reason: `VPA contains: ${foundSusp.join(', ')}` });
  } else if (foundSusp.length === 1) {
    score += 8;
    factors.push({ label: 'Suspicious Keyword', level: 'warn', impact: 8, reason: `VPA contains "${foundSusp[0]}"` });
  }

  factors.push({ label: 'Not in Platform Database', level: 'warn', impact: 20, reason: 'No transaction history or community data available for this VPA' });

  const finalScore = Math.max(0, Math.min(100, score));
  return {
    score: finalScore,
    verdict: finalScore >= 60 ? 'BLOCK' : finalScore >= 35 ? 'CAUTION' : 'LOW_RISK',
    confidence: 'VERY_LOW',
    factors,
    actionMessage: 'VPA not found in database. Limited analysis only.'
  };
}

function scoreKnownVpa(p) {

  let score = 0;
  const factors = [];

  // 1️⃣ Confirmed fraud
  if (p.confirmed_fraud) {
    score += 90;
    factors.push({
      label: "Confirmed Fraud",
      level: "danger",
      impact: 90,
      reason: "Account marked as confirmed fraud in database"
    });
  }

  // 2️⃣ Account age
  const ageDays =
    Math.floor((Date.now() - new Date(p.created_at)) / 86400000);

  if (ageDays < 30) {
    score += 12;
    factors.push({
      label: "New Account",
      level: "warn",
      impact: 12,
      reason: `Account only ${ageDays} days old`
    });
  }

  if (ageDays > 730) {
    score -= 5;
    factors.push({
      label: "Old Account",
      level: "positive",
      impact: -5,
      reason: "Account older than 2 years"
    });
  }

  // 3️⃣ KYC
  if (p.kyc_status === "none") {
    score += 15;
  }

  if (p.kyc_status === "full") {
    score -= 5;
  }

  // 4️⃣ Transaction history
  if (p.total_transactions < 5) {
    score += 10;
  }

  if (p.total_transactions > 100) {
    score -= 5;
  }

  // 5️⃣ Fraud reports
  if (p.report_count > 5) {
    score += 25;
  } else if (p.report_count > 0) {
    score += 15;
  }

  // 6️⃣ Disputes
  if (p.dispute_count > 3) {
    score += 10;
  }

  // normalize
  const finalScore = Math.max(0, Math.min(100, score));

  let verdict;

  if (finalScore >= 80) verdict = "BLOCK";
  else if (finalScore >= 60) verdict = "HIGH_RISK";
  else if (finalScore >= 30) verdict = "CAUTION";
  else verdict = "SAFE";

  return {
    score: finalScore,
    verdict,
    factors
  };
}

// ════════════════════════════════════════════════════════════════
// ADMIN ROUTES  (no auth for prototype — add auth in production)
// ════════════════════════════════════════════════════════════════

// Create user
app.post('/admin/create-user', async (req, res) => {
  const { name, mobile, pin, email } = req.body;
  if (!name || !mobile || !pin) return res.status(400).json({ error: 'name, mobile, pin required' });
  if (pin.toString().length !== 6) return res.status(400).json({ error: 'PIN must be exactly 6 digits' });
  try {
    const pin_hash = await bcrypt.hash(pin.toString(), 10);
    const result = await pool.query(
      'INSERT INTO users (name, mobile_number, pin_hash, email) VALUES ($1,$2,$3,$4) RETURNING id, name, mobile_number, created_at',
      [name.trim(), mobile.trim(), pin_hash, email || null]
    );
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Mobile number already registered' });
    res.status(500).json({ error: err.message });
  }
});

// Create personal account
app.post('/admin/create-personal-account', async (req, res) => {
  const {
    user_id, account_number, account_type, bank_name, bank_handle,
    vpa_address, ifsc_code, balance, kyc_status,
    aadhaar_linked, pan_linked, total_transactions, report_count,
    dispute_count, confirmed_fraud
  } = req.body;

  if (!user_id || !account_number) return res.status(400).json({ error: 'user_id and account_number required' });
  try {
    const result = await pool.query(
      `INSERT INTO personal_accounts
       (user_id, account_number, account_type, bank_name, bank_handle,
        vpa_address, ifsc_code, balance, kyc_status,
        aadhaar_linked, pan_linked, total_transactions,
        report_count, dispute_count, confirmed_fraud)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
       RETURNING *`,
      [
        user_id, account_number.trim(), account_type || 'savings',
        bank_name, bank_handle, vpa_address?.trim() || null, ifsc_code,
        balance || 0, kyc_status || 'none',
        aadhaar_linked || false, pan_linked || false,
        total_transactions || 0, report_count || 0,
        dispute_count || 0, confirmed_fraud || false
      ]
    );
    res.json({ success: true, account: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Account number or VPA already exists' });
    res.status(500).json({ error: err.message });
  }
});

// Create merchant account
app.post('/admin/create-merchant-account', async (req, res) => {
  const {
    user_id, account_number, business_name, merchant_id, merchant_category,
    merchant_category_name, business_type, gst_number, bank_name, bank_handle,
    vpa_address, ifsc_code, balance, kyc_status, pan_linked, gst_verified,
    total_transactions, report_count, dispute_count, confirmed_fraud,geohash
  } = req.body;

  if (!user_id || !account_number) return res.status(400).json({ error: 'user_id and account_number required' });
  try {
    const result = await pool.query(
      `INSERT INTO merchant_accounts
       (user_id, account_number, business_name, merchant_id, merchant_category,
        merchant_category_name, business_type, gst_number, bank_name, bank_handle,
        vpa_address, ifsc_code, balance, kyc_status, pan_linked, gst_verified,
        total_transactions, report_count, dispute_count, confirmed_fraud,geohash)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
       RETURNING *`,
      [
        user_id, account_number.trim(), business_name, merchant_id || null,
        merchant_category || null, merchant_category_name || null,
        business_type || 'sole_proprietor', gst_number || null,
        bank_name, bank_handle, vpa_address?.trim() || null, ifsc_code,
        balance || 0, kyc_status || 'none', pan_linked || false, gst_verified || false,
        total_transactions || 0, report_count || 0, dispute_count || 0,
        confirmed_fraud || false, geohash || null
      ]
    );
    res.json({ success: true, account: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Account number, VPA, or merchant ID already exists' });
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────
// UPDATE MERCHANT GEOHASH
// ─────────────────────────────────────────
app.put("/admin/update-merchant-geohash/:id", async (req, res) => {

  const { id } = req.params;
  const { geohash } = req.body;

  try {

    if (geohash && geohash.length !== 10) {
      return res.status(400).json({
        error: "Geohash must be exactly 10 characters"
      });
    }

    const result = await pool.query(
      `UPDATE merchant_accounts
       SET geohash = $1
       WHERE id = $2
       RETURNING id, business_name, geohash`,
      [geohash || null, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "Merchant not found"
      });
    }

    res.json({
      success: true,
      merchant: result.rows[0]
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: "Failed to update geohash"
    });

  }

});
// Add transaction
app.post('/admin/add-transaction', async (req, res) => {
  const {
    account_id, account_table, txn_type, amount,
    counterparty_name, counterparty_vpa, counterparty_bank,
    note, status, is_collect_request, category, balance_after
  } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO transactions
       (account_id, account_table, txn_type, amount, counterparty_name,
        counterparty_vpa, counterparty_bank, note, status,
        is_collect_request, category, balance_after)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       RETURNING *`,
      [
        account_id, account_table || 'personal', txn_type, amount,
        counterparty_name, counterparty_vpa, counterparty_bank || null,
        note || null, status || 'SUCCESS',
        is_collect_request || false, category || 'transfer', balance_after || null
      ]
    );
    res.json({ success: true, transaction: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET all users
app.get('/admin/users', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, mobile_number, email, is_active, created_at FROM users ORDER BY created_at DESC'
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET all personal accounts (with user info joined)
app.get('/admin/personal-accounts', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT pa.*, u.name as user_name, u.mobile_number
       FROM personal_accounts pa
       JOIN users u ON pa.user_id = u.id
       ORDER BY pa.created_at DESC`
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET all merchant accounts
app.get('/admin/merchant-accounts', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT ma.*, u.name as user_name, u.mobile_number
       FROM merchant_accounts ma
       JOIN users u ON ma.user_id = u.id
       ORDER BY ma.created_at DESC`
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET all transactions
app.get('/admin/transactions', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM transactions ORDER BY created_at DESC LIMIT 100'
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// DELETE user
app.delete('/admin/users/:id', async (req, res) => {
  try {
    await pool.query('UPDATE users SET is_active = false WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Health check
app.get('/health', (req, res) => res.json({ status: 'ok', timestamp: new Date() }));


// ===============================
// SEARCH ACCOUNT BY VPA
// ===============================

app.get("/api/search-vpa/:vpa", async (req, res) => {

  const { vpa } = req.params;

  try {

    // Check personal accounts
    const personal = await pool.query(
      `SELECT 
        pa.id,
        pa.account_number,
        pa.balance,
        pa.bank_name,
        pa.bank_handle,
        pa.vpa_address,
        pa.kyc_status,
        pa.report_count,
        pa.confirmed_fraud,
        u.name AS user_name,
        u.mobile_number
       FROM personal_accounts pa
       JOIN users u ON pa.user_id = u.id
       WHERE pa.vpa_address = $1`,
      [vpa]
    );

    if (personal.rows.length > 0) {
      return res.json({
        type: "personal",
        ...personal.rows[0]
      });
    }

    // Check merchant accounts
    const merchant = await pool.query(
      `SELECT 
        ma.id,
        ma.account_number,
        ma.balance,
        ma.bank_name,
        ma.bank_handle,
        ma.vpa_address,
        ma.kyc_status,
        ma.report_count,
        ma.confirmed_fraud,
        ma.created_at,
        ma.geohash,
        ma.business_name AS name,
        u.mobile_number
       FROM merchant_accounts ma
       JOIN users u ON ma.user_id = u.id
       WHERE ma.vpa_address = $1`,
      [vpa]
    );

    if (merchant.rows.length > 0) {
      return res.json({
        type: "merchant",
        ...merchant.rows[0]
      });
    }

    return res.status(404).json({ error: "VPA not found" });

  } catch (err) {

    console.error(err);

    res.status(500).json({ error: "Search failed" });

  }

});




// ─────────────────────────────────────────
// NEW VPA TRANSFER API
// ─────────────────────────────────────────

app.post("/api/vpa-transfer", async (req, res) => {
  const { from_vpa, to_vpa, amount, note } = req.body;

  if (!from_vpa || !to_vpa || !amount) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const client = await pool.connect();

  try {

    await client.query("BEGIN");

    // Find sender from vpa_directory
    const sender = await client.query(
      `SELECT account_id, account_table
       FROM vpa_directory
       WHERE vpa = $1`,
      [from_vpa]
    );

    // Find receiver from vpa_directory
    const receiver = await client.query(
      `SELECT account_id, account_table
       FROM vpa_directory
       WHERE vpa = $1`,
      [to_vpa]
    );

    if (sender.rows.length === 0 || receiver.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Invalid VPA" });
    }

    const s = sender.rows[0];
    const r = receiver.rows[0];

    let senderBalance;

    // Get sender balance
    if (s.account_table === "personal_accounts") {

      const bal = await client.query(
        `SELECT balance FROM personal_accounts WHERE id = $1`,
        [s.account_id]
      );

      senderBalance = bal.rows[0].balance;

    } else {

      const bal = await client.query(
        `SELECT balance FROM merchant_accounts WHERE id = $1`,
        [s.account_id]
      );

      senderBalance = bal.rows[0].balance;
    }

    // Check sufficient balance
    if (senderBalance < amount) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Insufficient balance" });
    }

    // Deduct sender balance
    if (s.account_table === "personal_accounts") {

      await client.query(
        `UPDATE personal_accounts
         SET balance = balance - $1
         WHERE id = $2`,
        [amount, s.account_id]
      );

    } else {

      await client.query(
        `UPDATE merchant_accounts
         SET balance = balance - $1
         WHERE id = $2`,
        [amount, s.account_id]
      );
    }

    // Add receiver balance
    if (r.account_table === "personal_accounts") {

      await client.query(
        `UPDATE personal_accounts
         SET balance = balance + $1
         WHERE id = $2`,
        [amount, r.account_id]
      );

    } else {

      await client.query(
        `UPDATE merchant_accounts
         SET balance = balance + $1
         WHERE id = $2`,
        [amount, r.account_id]
      );
    }

    // Sender transaction record
    await client.query(
      `INSERT INTO transactions
       (account_id, account_table, txn_type, amount, from_vpa, to_vpa, note)
       VALUES ($1,$2,'DEBIT',$3,$4,$5,$6)`,
      [s.account_id, s.account_table, amount, from_vpa, to_vpa, note || null]
    );

    // Receiver transaction record
    await client.query(
      `INSERT INTO transactions
       (account_id, account_table, txn_type, amount, from_vpa, to_vpa, note)
       VALUES ($1,$2,'CREDIT',$3,$4,$5,$6)`,
      [r.account_id, r.account_table, amount, from_vpa, to_vpa, note || null]
    );

    await client.query("COMMIT");

    res.json({
      success: true,
      message: "Transaction successful"
    });

  } catch (err) {

    await client.query("ROLLBACK");

    console.error(err);

    res.status(500).json({
      error: "Transaction failed"
    });

  } finally {

    client.release();

  }
});

// app.post("/api/vpa-transfer", async (req, res) => {
//   const { from_vpa, to_vpa, amount, note, is_request } = req.body;

//   if (!from_vpa || !to_vpa || !amount)
//     return res.status(400).json({ error: "Missing required fields" });

//   try {

//     const sender = await pool.query(
//       `SELECT * FROM vpa_directory WHERE vpa=$1`,
//       [from_vpa]
//     );

//     const receiver = await pool.query(
//       `SELECT * FROM vpa_directory WHERE vpa=$1`,
//       [to_vpa]
//     );

//     if (sender.rows.length === 0 || receiver.rows.length === 0)
//       return res.status(404).json({ error: "Invalid VPA" });

//     const s = sender.rows[0];
//     const r = receiver.rows[0];

//     if (s.account_table === "personal") {
//       await pool.query(
//         `UPDATE personal_accounts SET balance = balance - $1 WHERE id=$2`,
//         [amount, s.account_id]
//       );
//     } else {
//       await pool.query(
//         `UPDATE merchant_accounts SET balance = balance - $1 WHERE id=$2`,
//         [amount, s.account_id]
//       );
//     }

//     if (r.account_table === "personal") {
//       await pool.query(
//         `UPDATE personal_accounts SET balance = balance + $1 WHERE id=$2`,
//         [amount, r.account_id]
//       );
//     } else {
//       await pool.query(
//         `UPDATE merchant_accounts SET balance = balance + $1 WHERE id=$2`,
//         [amount, r.account_id]
//       );
//     }

//     await pool.query(
//       `INSERT INTO transactions
//        (account_id, account_table, txn_type, amount, from_vpa, to_vpa, note, is_request)
//        VALUES ($1,$2,'DEBIT',$3,$4,$5,$6,$7)`,
//       [s.account_id, s.account_table, amount, from_vpa, to_vpa, note || null, is_request || false]
//     );

//     await pool.query(
//       `INSERT INTO transactions
//        (account_id, account_table, txn_type, amount, from_vpa, to_vpa, note, is_request)
//        VALUES ($1,$2,'CREDIT',$3,$4,$5,$6,$7)`,
//       [r.account_id, r.account_table, amount, from_vpa, to_vpa, note || null, is_request || false]
//     );

//     res.json({ success: true, message: "Transaction successful" });

//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ error: "Transaction failed" });
//   }
// });

// ─────────────────────────────────────────
// FETCH ACCOUNT TRANSACTION HISTORY
// ─────────────────────────────────────────

app.get("/api/account-transactions/:id", async (req, res) => {

  const { id } = req.params;
  const { type } = req.query;

  try {
    const result = await pool.query(
      `SELECT *
       FROM transactions
       WHERE account_id=$1
       AND account_table=$2
       ORDER BY created_at DESC`,
      [id, type]
    );

    res.json(result.rows);

  } catch (err) {
    res.status(500).json({ error: "Failed to fetch transactions" });
  }
});

// Serve admin panel for any unmatched route
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ UPI Fraud Server running on port ${PORT}`);
});