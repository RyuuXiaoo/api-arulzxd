const express = require('express');
const router = express.Router();
const axios = require('axios');

const CONFIG = {
    baseUrl: 'https://xs-pedia-payment.vercel.app',
    userAgent: 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Mobile Safari/537.36'
};

const api = axios.create({
    baseURL: CONFIG.baseUrl,
    timeout: 30000,
    headers: {
        'User-Agent': CONFIG.userAgent,
        'Accept': 'application/json, text/plain, */*'
    },
    validateStatus: () => true
});

function sendError(res, err) {
    const status = err?.response?.status || 500;
    const data = err?.response?.data;
    const message =
        data?.message ||
        data?.error ||
        err?.message ||
        'Terjadi kesalahan saat menghubungi XS-PEDIA.';

    return res.status(status).json({
        success: false,
        message,
        ...(data && typeof data === 'object' ? { data: data.data ?? data } : {})
    });
}

async function proxyGet(res, path, params = {}) {
    try {
        const response = await api.get(path, { params });

        if (response.status < 200 || response.status >= 300) {
            return res.status(response.status).json(
                response.data ?? { success: false, message: 'Request gagal.' }
            );
        }

        return res.json(response.data);
    } catch (err) {
        return sendError(res, err);
    }
}

// ======================================================
// GET OTP
// GET /otp?phone=628xxxxxxxxxx
// ======================================================
router.get('/otp', async (req, res) => {
    const phone = String(req.query.phone || '').trim();

    if (!phone) {
        return res.status(400).json({
            success: false,
            message: 'Parameter "phone" diperlukan.'
        });
    }

    return proxyGet(res, '/auth/otp', { phone });
});

// ======================================================
// VERIFY OTP
// GET /verify?otp=1234&otp_token=xxxx
// ======================================================
router.get('/verify', async (req, res) => {
    const otp = String(req.query.otp || '').trim();
    const otpToken = String(req.query.otp_token || '').trim();

    if (!otp || !otpToken) {
        return res.status(400).json({
            success: false,
            message: 'Parameter "otp" dan "otp_token" diperlukan.'
        });
    }

    return proxyGet(res, '/auth/verify', {
        otp,
        otp_token: otpToken
    });
});

// ======================================================
// CREATE QRIS
// GET /qris/create?amount=100&static_qr=xxxx
// ======================================================
router.get('/qris/create', async (req, res) => {
    const amount = String(req.query.amount || '').trim();
    const staticQr = String(req.query.static_qr || '').trim();

    if (!amount || !staticQr) {
        return res.status(400).json({
            success: false,
            message: 'Parameter "amount" dan "static_qr" diperlukan.'
        });
    }

    if (!/^\d+(?:\.\d+)?$/.test(amount) || Number(amount) <= 0) {
        return res.status(400).json({
            success: false,
            message: 'Parameter "amount" harus berupa angka lebih dari 0.'
        });
    }

    return proxyGet(res, '/api/qris/create', {
        amount,
        static_qr: staticQr
    });
});

// ======================================================
// HISTORY
// GET /history?token=xxxx
// ======================================================
router.get('/history', async (req, res) => {
    const token = String(req.query.token || '').trim();

    if (!token) {
        return res.status(400).json({
            success: false,
            message: 'Parameter "token" diperlukan.'
        });
    }

    return proxyGet(res, '/api/history', { token });
});

// ======================================================
// VALIDATE TOKEN
// GET /validate?token=xxxx
// ======================================================
router.get('/validate', async (req, res) => {
    const token = String(req.query.token || '').trim();

    if (!token) {
        return res.status(400).json({
            success: false,
            message: 'Parameter "token" diperlukan.'
        });
    }

    // Sesuai format endpoint yang dipakai backend sumber.
    return proxyGet(res, '/auth/check/token', { token });
});

// ======================================================
// REFRESH TOKEN
// GET /refresh?refresh_token=xxxx
// ======================================================
router.get('/refresh', async (req, res) => {
    const refreshToken = String(req.query.refresh_token || '').trim();

    if (!refreshToken) {
        return res.status(400).json({
            success: false,
            message: 'Parameter "refresh_token" diperlukan.'
        });
    }

    return proxyGet(res, '/auth/refresh/token', {
        refresh_token: refreshToken
    });
});

// ======================================================
// INFO / DOCS SINGKAT
// GET /
// ======================================================
router.get('/', (req, res) => {
    res.json({
        success: true,
        name: 'XS-PEDIA Payment Scrape API',
        base_url: CONFIG.baseUrl,
        endpoints: {
            otp: '/otp?phone=628xxxxxxxxxx',
            verify: '/verify?otp=1234&otp_token=xxxx',
            qris_create: '/qris/create?amount=100&static_qr=xxxx',
            history: '/history?token=xxxx',
            validate: '/validate?token=xxxx',
            refresh: '/refresh?refresh_token=xxxx'
        }
    });
});

router.desc = 'Scrape/proxy XS-PEDIA Payment API dalam satu router.';
router.status = 'ready';
router.type = 'free';

module.exports = router;
