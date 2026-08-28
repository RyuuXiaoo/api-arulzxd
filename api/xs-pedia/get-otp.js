const express = require('express');
const axios = require('axios');
const router = express.Router();

const BASE_URL = 'https://xs-pedia-payment.vercel.app';

router.get('/', async (req, res) => {
  try {
    const phone = String(req.query.phone || '').trim();
    if (!phone) return res.status(400).json({ success: false, message: 'Parameter phone wajib diisi.' });

    const response = await axios.get(`${BASE_URL}/auth/otp`, {
      params: { phone },
      timeout: 30000,
      headers: { Accept: 'application/json', 'User-Agent': 'Mozilla/5.0' }
    });

    return res.status(response.status).json(response.data);
  } catch (error) {
    const status = error.response?.status || 500;
    return res.status(status).json(error.response?.data || { success: false, message: error.message });
  }
});

router.title = 'XS Pedia - Get OTP';
router.name = 'XS Pedia - Get OTP';
router.desc = 'Mengirim kode OTP ke nomor telepon.';
router.status = 'ready';
router.type = 'free';
router.paramsConfig = { phone: '628xxxxxxxxxx' };

module.exports = router;
