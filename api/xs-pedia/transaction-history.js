const express = require('express');
const axios = require('axios');
const router = express.Router();

const BASE_URL = 'https://xs-pedia-payment.vercel.app';

router.get('/', async (req, res) => {
  try {
    const token = String(req.query.token || '').trim();
    if (!token) return res.status(400).json({ success: false, message: 'Parameter token wajib diisi.' });

    const response = await axios.get(`${BASE_URL}/api/history`, {
      params: { token },
      timeout: 30000,
      headers: { Accept: 'application/json', 'User-Agent': 'Mozilla/5.0' }
    });

    return res.status(response.status).json(response.data);
  } catch (error) {
    const status = error.response?.status || 500;
    return res.status(status).json(error.response?.data || { success: false, message: error.message });
  }
});

router.title = 'XS Pedia - Transaction History';
router.name = 'XS Pedia - Transaction History';
router.desc = 'Mengambil riwayat transaksi akun XS Pedia.';
router.status = 'ready';
router.type = 'free';
router.paramsConfig = { token: 'xxxx' };

module.exports = router;
