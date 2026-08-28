const express = require('express');
const axios = require('axios');
const router = express.Router();

const BASE_URL = 'https://xs-pedia-payment.vercel.app';

router.get('/', async (req, res) => {
  try {
    const refresh_token = String(req.query.refresh_token || '').trim();
    if (!refresh_token) return res.status(400).json({ success: false, message: 'Parameter refresh_token wajib diisi.' });

    const response = await axios.get(`${BASE_URL}/auth/refresh/token`, {
      params: { refresh_token },
      timeout: 30000,
      headers: { Accept: 'application/json', 'User-Agent': 'Mozilla/5.0' }
    });

    return res.status(response.status).json(response.data);
  } catch (error) {
    const status = error.response?.status || 500;
    return res.status(status).json(error.response?.data || { success: false, message: error.message });
  }
});

router.title = 'XS Pedia - Refresh Token';
router.name = 'XS Pedia - Refresh Token';
router.desc = 'Mendapatkan access token baru menggunakan refresh token.';
router.status = 'ready';
router.type = 'free';
router.paramsConfig = { refresh_token: 'xxxx' };

module.exports = router;
