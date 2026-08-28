const express = require('express');
const axios = require('axios');
const router = express.Router();

const BASE_URL = 'https://xs-pedia-payment.vercel.app';

router.get('/', async (req, res) => {
  try {
    const otp = String(req.query.otp || '').trim();
    const otp_token = String(req.query.otp_token || '').trim();
    if (!otp || !otp_token) {
      return res.status(400).json({ success: false, message: 'Parameter otp dan otp_token wajib diisi.' });
    }

    const response = await axios.get(`${BASE_URL}/auth/verify`, {
      params: { otp, otp_token },
      timeout: 30000,
      headers: { Accept: 'application/json', 'User-Agent': 'Mozilla/5.0' }
    });

    return res.status(response.status).json(response.data);
  } catch (error) {
    const status = error.response?.status || 500;
    return res.status(status).json(error.response?.data || { success: false, message: error.message });
  }
});

router.title = 'XS Pedia - Verify OTP';
router.name = 'XS Pedia - Verify OTP';
router.desc = 'Memverifikasi kode OTP menggunakan otp_token.';
router.status = 'ready';
router.type = 'free';
router.paramsConfig = { otp: '1234', otp_token: 'xxxx' };

module.exports = router;
