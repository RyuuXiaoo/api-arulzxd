const express = require('express');
const router = express.Router();

const BASE_URL = 'https://xs-pedia-payment.vercel.app';
const USER_AGENT = 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Mobile Safari/537.36';

// Browser-like headers karena endpoint sumber berada di Vercel dan dapat
// menolak request server-to-server yang terlalu minimal.
const DEFAULT_HEADERS = {
  'User-Agent': USER_AGENT,
  'Accept': 'application/json, text/plain, */*',
  'Accept-Language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7',
  'Origin': BASE_URL,
  'Referer': `${BASE_URL}/`,
  'Sec-CH-UA': '"Chromium";v="139", "Not;A=Brand";v="99"',
  'Sec-CH-UA-Mobile': '?1',
  'Sec-CH-UA-Platform': '"Android"',
  'Sec-Fetch-Dest': 'empty',
  'Sec-Fetch-Mode': 'cors',
  'Sec-Fetch-Site': 'same-origin'
};

function clean(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function sendError(res, status, message, extra = {}) {
  return res.status(status).json({ success: false, message, ...extra });
}

async function requestSource(pathname, query, res) {
  try {
    const url = new URL(pathname, BASE_URL);
    for (const [key, value] of Object.entries(query || {})) {
      if (value !== undefined && value !== null && String(value) !== '') {
        url.searchParams.set(key, String(value));
      }
    }

    const response = await fetch(url, {
      method: 'GET',
      headers: DEFAULT_HEADERS,
      redirect: 'manual'
    });

    const text = await response.text();
    const contentType = response.headers.get('content-type') || '';

    if (contentType.includes('application/json')) {
      try {
        return res.status(response.status).json(JSON.parse(text));
      } catch (_) {}
    }

    return res.status(response.status).send(text);
  } catch (error) {
    console.error('[XS-PEDIA SCRAPE]', error);
    return sendError(res, 502, 'Gagal menghubungi XS-PEDIA Payment.', {
      error: error.message
    });
  }
}

function requireParams(res, values) {
  for (const [name, value] of Object.entries(values)) {
    if (!clean(value)) {
      sendError(res, 400, `Parameter "${name}" diperlukan.`);
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Endpoint asli XS-PEDIA yang diproxy apa adanya
// ---------------------------------------------------------------------------
router.get('/otp', async (req, res) => {
  const phone = clean(req.query.phone);
  if (!requireParams(res, { phone })) return;
  return requestSource('/auth/otp', { phone }, res);
});

router.get('/verify', async (req, res) => {
  const otp = clean(req.query.otp);
  const otp_token = clean(req.query.otp_token);
  if (!requireParams(res, { otp, otp_token })) return;
  return requestSource('/auth/verify', { otp, otp_token }, res);
});

router.get('/qris/create', async (req, res) => {
  const amount = clean(req.query.amount);
  const static_qr = clean(req.query.static_qr);
  if (!requireParams(res, { amount, static_qr })) return;
  if (!/^\d+(?:\.\d+)?$/.test(amount) || Number(amount) <= 0) {
    return sendError(res, 400, 'Parameter "amount" harus berupa angka lebih dari 0.');
  }
  return requestSource('/api/qris/create', { amount, static_qr }, res);
});

router.get('/history', async (req, res) => {
  const token = clean(req.query.token);
  if (!requireParams(res, { token })) return;
  return requestSource('/api/history', { token }, res);
});

router.get('/validate', async (req, res) => {
  const token = clean(req.query.token);
  if (!requireParams(res, { token })) return;
  return requestSource('/auth/check/token', { token }, res);
});

router.get('/refresh', async (req, res) => {
  const refresh_token = clean(req.query.refresh_token);
  if (!requireParams(res, { refresh_token })) return;
  return requestSource('/auth/refresh/token', { refresh_token }, res);
});

// ---------------------------------------------------------------------------
// ROOT ROUTE — wajib ada karena loader ArulzXD menampilkan 1 file sebagai
// endpoint utama: /api/xs-pedia/xs-pedia-scrape
// ---------------------------------------------------------------------------
router.get('/', async (req, res) => {
  const q = req.query || {};
  const action = clean(q.action || q.endpoint).toLowerCase();

  // Bisa dipanggil eksplisit dengan ?action=otp|verify|qris|history|validate|refresh
  if (action === 'otp') {
    const phone = clean(q.phone);
    if (!requireParams(res, { phone })) return;
    return requestSource('/auth/otp', { phone }, res);
  }

  if (action === 'verify') {
    const otp = clean(q.otp);
    const otp_token = clean(q.otp_token);
    if (!requireParams(res, { otp, otp_token })) return;
    return requestSource('/auth/verify', { otp, otp_token }, res);
  }

  if (action === 'qris' || action === 'qris_create' || action === 'create_qris') {
    const amount = clean(q.amount);
    const static_qr = clean(q.static_qr);
    if (!requireParams(res, { amount, static_qr })) return;
    if (!/^\d+(?:\.\d+)?$/.test(amount) || Number(amount) <= 0) {
      return sendError(res, 400, 'Parameter "amount" harus berupa angka lebih dari 0.');
    }
    return requestSource('/api/qris/create', { amount, static_qr }, res);
  }

  if (action === 'history') {
    const token = clean(q.token);
    if (!requireParams(res, { token })) return;
    return requestSource('/api/history', { token }, res);
  }

  if (action === 'validate' || action === 'check_token') {
    const token = clean(q.token);
    if (!requireParams(res, { token })) return;
    return requestSource('/auth/check/token', { token }, res);
  }

  if (action === 'refresh' || action === 'refresh_token') {
    const refresh_token = clean(q.refresh_token);
    if (!requireParams(res, { refresh_token })) return;
    return requestSource('/auth/refresh/token', { refresh_token }, res);
  }

  // Auto-detect supaya request seperti screenshot tetap langsung jalan:
  // ?phone=...  => OTP
  if (clean(q.phone) && !clean(q.otp) && !clean(q.otp_token) && !clean(q.amount) && !clean(q.token) && !clean(q.refresh_token)) {
    return requestSource('/auth/otp', { phone: clean(q.phone) }, res);
  }

  if (clean(q.otp) && clean(q.otp_token)) {
    return requestSource('/auth/verify', {
      otp: clean(q.otp),
      otp_token: clean(q.otp_token)
    }, res);
  }

  if (clean(q.amount) && clean(q.static_qr)) {
    const amount = clean(q.amount);
    if (!/^\d+(?:\.\d+)?$/.test(amount) || Number(amount) <= 0) {
      return sendError(res, 400, 'Parameter "amount" harus berupa angka lebih dari 0.');
    }
    return requestSource('/api/qris/create', {
      amount,
      static_qr: clean(q.static_qr)
    }, res);
  }

  if (clean(q.refresh_token)) {
    return requestSource('/auth/refresh/token', {
      refresh_token: clean(q.refresh_token)
    }, res);
  }

  if (clean(q.token)) {
    const type = clean(q.type).toLowerCase();
    if (type === 'validate' || type === 'check_token') {
      return requestSource('/auth/check/token', { token: clean(q.token) }, res);
    }
    return requestSource('/api/history', { token: clean(q.token) }, res);
  }

  return sendError(res, 400, 'Parameter tidak sesuai.', {
    usage: {
      otp: '?phone=628xxxxxxxxxx',
      verify: '?otp=1234&otp_token=xxxx',
      qris_create: '?amount=100&static_qr=xxxx',
      history: '?token=xxxx',
      validate: '?token=xxxx&type=validate',
      refresh: '?refresh_token=xxxx'
    }
  });
});

router.title = 'XS Pedia Scrape';
router.desc = 'Proxy XS-PEDIA Payment API dan mengembalikan response asli sesuai request.';
router.status = 'ready';
router.type = 'free';
router.paramsConfig = {
  phone: '628xxxxxxxxxx'
};

module.exports = router;
