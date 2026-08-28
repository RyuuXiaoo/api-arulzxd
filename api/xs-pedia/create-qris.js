const express = require('express');
const axios = require('axios');
const router = express.Router();

const BASE_URL = 'https://xs-pedia-payment.vercel.app';

router.get('/', async (req, res) => {
  try {
    const amount = String(req.query.amount || '').trim();
    const static_qr = String(req.query.static_qr || '').trim();
    if (!amount || !static_qr) {
      return res.status(400).json({ success: false, message: 'Parameter amount dan static_qr wajib diisi.' });
    }

    const response = await axios.get(`${BASE_URL}/api/qris/create`, {
      params: { amount, static_qr },
      timeout: 30000,
      headers: { Accept: 'application/json', 'User-Agent': 'Mozilla/5.0' }
    });

    return res.status(response.status).json(response.data);
  } catch (error) {
    const status = error.response?.status || 500;
    return res.status(status).json(error.response?.data || { success: false, message: error.message });
  }
});

router.title = 'XS Pedia - Create QRIS';
router.name = 'XS Pedia - Create QRIS';
router.desc = 'Membuat QRIS dinamis dari nominal dan static QR.';
router.status = 'ready';
router.type = 'free';
router.paramsConfig = { amount: '100', static_qr: '000201010211....' };

module.exports = router;
