const express = require('express');
const axios = require('axios');
const router = express.Router();

const BASE_URL = 'https://xs-pedia-payment.vercel.app';
const USER_AGENT = 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Mobile Safari/537.36';

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
  headers: {
    'User-Agent': USER_AGENT,
    'Accept': 'application/json, text/plain, */*'
  },
  validateStatus: () => true
});

async function proxyGet(res, target, params) {
  try {
    const r = await api.get(target, { params });
    const contentType = r.headers?.['content-type'] || '';

    // Teruskan response XS-PEDIA apa adanya.
    if (contentType.includes('application/json') || typeof r.data === 'object') {
      return res.status(r.status).json(r.data);
    }

    return res.status(r.status).send(r.data);
  } catch (err) {
    const status = err.response?.status || 502;
    const data = err.response?.data;
    return res.status(status).json(
      data && typeof data === 'object'
        ? data
        : { success: false, message: err.message || 'Gagal menghubungi XS-PEDIA.' }
    );
  }
}

// GET /otp?phone=628xxxxxxxxxx
router.get('/otp', async (req, res) => {
  const phone = String(req.query.phone || '').trim();
  if (!phone) return res.status(400).json({ success: false, message: 'Parameter "phone" diperlukan.' });
  return proxyGet(res, '/auth/otp', { phone });
});

// GET /verify?otp=1234&otp_token=xxxx
router.get('/verify', async (req, res) => {
  const otp = String(req.query.otp || '').trim();
  const otpToken = String(req.query.otp_token || '').trim();
  if (!otp || !otpToken) {
    return res.status(400).json({ success: false, message: 'Parameter "otp" dan "otp_token" diperlukan.' });
  }
  return proxyGet(res, '/auth/verify', { otp, otp_token: otpToken });
});

// GET /qris/create?amount=100&static_qr=xxxx
router.get('/qris/create', async (req, res) => {
  const amount = String(req.query.amount || '').trim();
  const staticQr = String(req.query.static_qr || '').trim();
  if (!amount || !staticQr) {
    return res.status(400).json({ success: false, message: 'Parameter "amount" dan "static_qr" diperlukan.' });
  }
  if (!/^\d+(?:\.\d+)?$/.test(amount) || Number(amount) <= 0) {
    return res.status(400).json({ success: false, message: 'Parameter "amount" harus berupa angka lebih dari 0.' });
  }
  return proxyGet(res, '/api/qris/create', { amount, static_qr: staticQr });
});

// GET /history?token=xxxx
router.get('/history', async (req, res) => {
  const token = String(req.query.token || '').trim();
  if (!token) return res.status(400).json({ success: false, message: 'Parameter "token" diperlukan.' });
  return proxyGet(res, '/api/history', { token });
});

// GET /validate?token=xxxx
router.get('/validate', async (req, res) => {
  const token = String(req.query.token || '').trim();
  if (!token) return res.status(400).json({ success: false, message: 'Parameter "token" diperlukan.' });
  return proxyGet(res, '/auth/check/token', { token });
});

// GET /refresh?refresh_token=xxxx
router.get('/refresh', async (req, res) => {
  const refreshToken = String(req.query.refresh_token || '').trim();
  if (!refreshToken) {
    return res.status(400).json({ success: false, message: 'Parameter "refresh_token" diperlukan.' });
  }
  return proxyGet(res, '/auth/refresh/token', { refresh_token: refreshToken });
});

// Jangan buat GET / berisi dokumentasi.
// Sistem frontend akan hanya melihat endpoint yang benar-benar melakukan scrape.
router.desc = 'Scrape/proxy XS-PEDIA Payment API. Response dikembalikan sesuai endpoint yang diminta.';
router.status = 'ready';
router.type = 'free';

module.exports = router;
