const express = require('express');
const fileUpload = require('express-fileupload');
const session = require('express-session');
const mongoose = require('mongoose');
const cron = require('node-cron');
const { MongoStore } = require('connect-mongo');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const mime = require('mime-types');
const multer = require("multer");
const nodemailer = require('nodemailer');
const https = require('https');
const http = require('http');
const crypto = require('crypto');
const compression = require('compression');
const os = require('os');

const app = express();
app.use(compression());
app.set('etag', false);
const PORT = process.env.PORT || 3000;
app.use(express.static(path.join(__dirname)));
app.use(express.json({
    verify: (req, res, buf) => {
        req.rawBody = buf.toString('utf8');
    }
}));
app.use(cookieParser());
app.set('trust proxy', 1);

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://arulz-xd-owner:Haqqi0213@cluster0.fgxhxqm.mongodb.net/?appName=Cluster0'; 

mongoose.connect(MONGODB_URI)
    .then(() => console.log('📦 Berhasil terhubung ke MongoDB!'))
    .catch(err => console.error('❌ Gagal koneksi ke MongoDB:', err));

const JWT_SECRET = process.env.JWT_SECRET || 'xs-pedia-super-secret-jwt-key-999';

// ====================================================
// HELPER GENERATOR API KEY SESUAI ATURAN
// ====================================================
function generateFreeApiKey() {
    return 'xs-pedia' + crypto.randomBytes(3).toString('hex').slice(0, 5);
}

function generatePremiumApiKey(username) {
    const cleanUsername = (username || 'user').toLowerCase().trim().replace(/[^a-z0-9]/g, '');
    return `${cleanUsername}prem-` + crypto.randomBytes(3).toString('hex').slice(0, 6);
}

// ====================================================
// MONGOOSE SCHEMA & USER MODEL
// ====================================================
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, trim: true, lowercase: true },
    password: { type: String, default: null },
    provider: { type: String, default: 'local' },
    providerId: { type: String, default: null },
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    apikey: { type: String, required: true, unique: true },
    role: { type: String, default: 'Free User' }, // 'Free User', 'Premium User', 'VIP User'
    roleExpiresAt: { type: Date, default: null }, // MASA BERLAKU ROLE
    limit: { type: Number, default: 0 },
    lastLimitReset: { type: Date, default: Date.now },
    avatar: { type: String, default: 'https://arulz-xd.my.id/files/X1F0Cn.png' }, 
    createdAt: { type: Date, default: Date.now }
});

// Middleware Otomatis Update API Key saat Role Berubah jika tidak ditentukan khusus
userSchema.pre('save', function() {
    if (this.isModified('role')) {
        const roleLower = (this.role || '').toLowerCase();

        if (roleLower.includes('vip')) {
            if (!this.apikey) {
                this.apikey = `${this.username.toLowerCase()}-custom-vip`;
            }
        } else if (roleLower.includes('premium')) {
            if (!this.apikey || !this.apikey.includes('prem-')) {
                this.apikey = generatePremiumApiKey(this.username);
            }
        } else {
            if (!this.apikey || !this.apikey.startsWith('xs-pedia')) {
                this.apikey = generateFreeApiKey();
            }
        }
    }
});


const User = mongoose.models.User || mongoose.model('User', userSchema);

app.use(session({
    secret: 'arulzxd_secret_session_key_99', 
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: MONGODB_URI,
        dbName: 'sessions',
        ttl: 24 * 60 * 60
    }),
    cookie: { maxAge: 24 * 60 * 60 * 1000 } 
}));

const checkAuthSession = (req, res, next) => {
    const token = req.cookies.auth_session;
    if (!token) {
        req.user = null;
        return next();
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = {
            ...decoded,
            apikey: decoded.apikey
        }; 
        next();
    } catch (err) {
        res.clearCookie('auth_session');
        req.user = null;
        next();
    }
};

app.use(checkAuthSession);

// CRON JOB: Cek & Reset Role ke 'Free User' jika masa aktif paket telah kadaluwarsa
cron.schedule('0 * * * *', async () => {
    try {
        const expiredUsers = await User.find({
            role: { $ne: 'Free User' },
            roleExpiresAt: { $lte: new Date() }
        });

        for (const user of expiredUsers) {
            user.role = 'Free User';
            user.roleExpiresAt = null;
            user.apikey = generateFreeApiKey(); // Reset API Key ke Format Free
            await user.save();
            console.log(`📉 [EXPIRED] Role pengguna ${user.username} dikembalikan ke Free User.`);
        }
    } catch (err) {
        console.error('❌ [CRON] Gagal memproses ekspirasi role:', err.message);
    }
}, {
    scheduled: true,
    timezone: "Asia/Jakarta"
});

const uploadavatar = multer({ 
    limits: { fileSize: 4 * 1024 * 1024 }, // Limit 4MB
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('File harus berupa gambar!'));
        }
    }
});

// Endpoint Upload Avatar
app.post('/api/user/update-avatar', checkAuthSession, (req, res) => {
    uploadavatar.single('avatar')(req, res, async (err) => {
        if (err) {
            return res.status(400).json({ status: false, message: err.message || 'Gagal mengunggah gambar.' });
        }

        try {
            if (!req.user) {
                return res.status(401).json({ status: false, message: 'Anda belum login!' });
            }

            if (!req.file) {
                return res.status(400).json({ status: false, message: 'Silakan pilih gambar terlebih dahulu!' });
            }

            const mimeType = req.file.mimetype || mime.lookup(req.file.originalname) || 'image/png';
            if (!mimeType.startsWith('image/')) {
                return res.status(400).json({ status: false, message: 'File harus berupa gambar (JPG, PNG, GIF, WebP)!' });
            }

            const base64 = req.file.buffer.toString("base64");
            const avatarDataUrl = `data:${mimeType};base64,${base64}`;

            const userIdToUpdate = req.user.id || req.user._id;
            const updatedUser = await User.findByIdAndUpdate(
                userIdToUpdate,
                { $set: { avatar: avatarDataUrl } },
                { new: true, runValidators: true }
            );

            if (!updatedUser) {
                return res.status(404).json({ status: false, message: 'User tidak ditemukan.' });
            }

            const userPayload = {
                id: updatedUser._id,
                username: updatedUser.username,
                email: updatedUser.email,
                name: updatedUser.username,
                avatar: updatedUser.avatar?.startsWith('data:') ? null : updatedUser.avatar,
                role: updatedUser.role,
                apikey: updatedUser.apikey
            };

            const token = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '7d' });
            res.cookie('auth_session', token, {
                maxAge: 7 * 24 * 60 * 60 * 1000,
                httpOnly: true,
                secure: true,
                sameSite: 'lax'
            });

            return res.json({
                status: true,
                message: 'Avatar berhasil diperbarui!',
                avatar: updatedUser.avatar
            });

        } catch (error) {
            console.error("Gagal update avatar:", error);
            return res.status(500).json({ status: false, message: 'Terjadi kesalahan pada server saat memperbarui avatar.' });
        }
    });
});

// ====================================================
// ENDPOINT CUSTOM APIKEY KHUSUS VIP USER
// ====================================================
app.post('/api/user/custom-apikey', checkAuthSession, async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ status: false, message: 'Anda harus login terlebih dahulu!' });
        }

        const userId = req.user.id || req.user._id;
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ status: false, message: 'User tidak ditemukan!' });
        }

        const roleLower = (user.role || '').toLowerCase();
        if (!roleLower.includes('vip')) {
            return res.status(403).json({ status: false, message: 'Fitur Custom API Key hanya diperuntukkan untuk VIP User!' });
        }

        const { customKey } = req.body;
        if (!customKey || !customKey.trim()) {
            return res.status(400).json({ status: false, message: 'API Key kustom tidak boleh kosong!' });
        }

        const cleanKey = customKey.trim();

        if (cleanKey.length < 4 || cleanKey.length > 30) {
            return res.status(400).json({ status: false, message: 'API Key kustom harus memiliki panjang 4 - 30 karakter!' });
        }

        // Cek apakah API Key sudah dipakai oleh pengguna lain
        const existingKey = await User.findOne({ apikey: cleanKey, _id: { $ne: userId } });
        if (existingKey) {
            return res.status(400).json({ status: false, message: 'API Key tersebut sudah digunakan oleh user lain! Silakan pilih nama lain.' });
        }

        user.apikey = cleanKey;
        await user.save();

        // Update Token JWT
        const userPayload = {
            id: user._id,
            username: user.username,
            email: user.email,
            name: user.username,
            avatar: user.avatar?.startsWith('data:') ? null : user.avatar,
            role: user.role,
            apikey: user.apikey
        };

        const token = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '7d' });
        res.cookie('auth_session', token, {
            maxAge: 7 * 24 * 60 * 60 * 1000,
            httpOnly: true,
            secure: true,
            sameSite: 'lax'
        });

        return res.json({
            status: true,
            message: 'API Key berhasil diperbarui!',
            apikey: user.apikey
        });

    } catch (error) {
        console.error("Gagal custom apikey:", error);
        return res.status(500).json({ status: false, message: 'Terjadi kesalahan server saat memperbarui API Key.' });
    }
});

// ----------------------------------------------------
// MONGOOSE SCHEMA & MODEL PENILAIAN / REVIEW
// ----------------------------------------------------
const reviewSchema = new mongoose.Schema({
    productId: { type: String, required: true, index: true },
    userId: { type: String, default: null, index: true },
    username: { type: String, required: true },
    userAvatar: { type: String, default: 'https://arulz-xd.my.id/files/X1F0Cn.png' },
    rating: { type: Number, required: true, min: 1, max: 5 },
    comment: { type: String, required: true, trim: true },
    media: [{
        type: { type: String, enum: ['image', 'video'] },
        url: String
    }],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

reviewSchema.index({ productId: 1, userId: 1 }, { unique: true, sparse: true });
const Review = mongoose.models.Review || mongoose.model('Review', reviewSchema);

const uploadReviewMedia = multer({
    limits: { fileSize: 10 * 1024 * 1024 }, 
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/')) {
            cb(null, true);
        } else {
            cb(new Error('File harus berupa gambar atau video!'));
        }
    }
});

app.post('/api/reviews', checkAuthSession, (req, res) => {
    uploadReviewMedia.array('mediaFiles', 5)(req, res, async (err) => {
        if (err) {
            return res.status(400).json({ status: false, message: err.message || 'Gagal mengunggah berkas.' });
        }

        try {
            const { productId, rating, comment } = req.body;

            if (!productId) {
                return res.status(400).json({ status: false, message: 'Product ID wajib diisi!' });
            }

            if (!rating || Number(rating) < 1 || Number(rating) > 5) {
                return res.status(400).json({ status: false, message: 'Rating bintang wajib diisi (1-5)!' });
            }

            if (!comment || !comment.trim()) {
                return res.status(400).json({ status: false, message: 'Anda diwajibkan menuliskan ulasan/penilaian!' });
            }

            let username = 'Anonim';
            let userAvatar = 'https://arulz-xd.my.id/files/X1F0Cn.png';
            let userId = getUserIdentifier(req);

            if (req.user) {
                username = req.user.username || req.user.name;
                userAvatar = req.user.avatar || userAvatar;
                userId = (req.user.id || req.user._id || req.user.email || req.user.username).toString();
            }

            const product = await Product.findOne({
                $or: [{ Id: productId }, { _id: mongoose.Types.ObjectId.isValid(productId) ? productId : null }]
            });

            if (product && product.purchasedBy) {
                const userClean = userId.toLowerCase().trim();
                const isBuyer = product.purchasedBy.some(p => p.toLowerCase().trim() === userClean);

                if (!isBuyer && process.env.NODE_ENV === 'production') {
                    return res.status(403).json({
                        status: false,
                        message: 'Anda belum pernah membeli produk ini, tidak dapat memberikan penilaian!'
                    });
                }
            }

            const mediaList = [];
            if (req.files && req.files.length > 0) {
                for (const file of req.files) {
                    const mimeType = file.mimetype || mime.lookup(file.originalname) || '';
                    const isVideo = mimeType.startsWith('video/');
                    const base64 = file.buffer.toString('base64');
                    const dataUrl = `data:${mimeType};base64,${base64}`;

                    mediaList.push({
                        type: isVideo ? 'video' : 'image',
                        url: dataUrl
                    });
                }
            }

            let existingReview = await Review.findOne({ productId, userId });

            if (existingReview) {
                existingReview.rating = Number(rating);
                existingReview.comment = comment.trim();
                if (mediaList.length > 0) {
                    existingReview.media = mediaList; 
                }
                existingReview.updatedAt = new Date();
                await existingReview.save();

                return res.json({
                    status: true,
                    message: 'Penilaian produk Anda berhasil diperbarui!',
                    data: existingReview
                });
            } else {
                const newReview = new Review({
                    productId,
                    userId,
                    username,
                    userAvatar,
                    rating: Number(rating),
                    comment: comment.trim(),
                    media: mediaList
                });

                await newReview.save();

                return res.json({
                    status: true,
                    message: 'Penilaian produk berhasil dikirim!',
                    data: newReview
                });
            }

        } catch (error) {
            console.error("Error submit review:", error);
            return res.status(500).json({ status: false, message: 'Terjadi kesalahan server saat menyimpan ulasan.' });
        }
    });
});

app.get('/api/reviews/:productId', async (req, res) => {
    try {
        const { productId } = req.params;
        const reviews = await Review.find({ productId }).sort({ createdAt: -1 });

        let averageRating = 0;
        if (reviews.length > 0) {
            const totalRating = reviews.reduce((sum, item) => sum + item.rating, 0);
            averageRating = Number((totalRating / reviews.length).toFixed(1));
        }

        return res.json({
            status: true,
            totalReviews: reviews.length,
            averageRating: averageRating,
            reviews: reviews
        });
    } catch (error) {
        console.error("Error fetch reviews:", error);
        return res.status(500).json({ status: false, message: 'Gagal mengambil ulasan produk.' });
    }
});

// ====================================================
// ENDPOINT DELETE REVIEWS (HAPUS ULASAN/RATING)
// ====================================================
app.delete('/api/reviews/:reviewId', checkAuthSession, async (req, res) => {
    try {
        const { reviewId } = req.params;

        if (!mongoose.Types.ObjectId.isValid(reviewId)) {
            return res.status(400).json({ 
                status: false, 
                message: 'ID ulasan tidak valid!' 
            });
        }

        const review = await Review.findById(reviewId);

        if (!review) {
            return res.status(404).json({ 
                status: false, 
                message: 'Ulasan tidak ditemukan!' 
            });
        }

        // Dapatkan identitas pengguna yang sedang melakukan request
        let currentUserId = getUserIdentifier(req);
        if (req.user) {
            currentUserId = (req.user.id || req.user._id || req.user.email || req.user.username).toString();
        }

        const currentUsername = req.user ? req.user.username : null;

        // Validasi: Pastikan pengguna hanya bisa menghapus ulasannya sendiri (atau admin jika ada)
        const isOwner = (review.userId && review.userId.toString() === currentUserId.toString()) ||
                        (currentUsername && review.username.toLowerCase() === currentUsername.toLowerCase());

        if (!isOwner) {
            return res.status(403).json({ 
                status: false, 
                message: 'Anda tidak memiliki hak akses untuk menghapus ulasan ini!' 
            });
        }

        await Review.findByIdAndDelete(reviewId);

        return res.json({
            status: true,
            message: 'Ulasan berhasil dihapus!'
        });

    } catch (error) {
        console.error("Error delete review:", error);
        return res.status(500).json({ 
            status: false, 
            message: 'Terjadi kesalahan server saat menghapus ulasan.' 
        });
    }
});

const PAYWUZ_API_KEY = process.env.PAYWUZ_API_KEY || "pk_live_f1429e9285d76999cc3f8bb6c3df552f";
const PAYWUZ_BASE_URL = "https://api.paywuz.id/v1";
const PAYWUZ_HEADERS = {
    "Authorization": `Bearer ${PAYWUZ_API_KEY}`,
    "Content-Type": "application/json"
};

async function axiosPaywuzWithRetry(config, maxRetries = 3, delayMs = 1500) {
    for (let i = 0; i < maxRetries; i++) {
        try {
            return await axios(config);
        } catch (error) {
            const isRateLimited = error.response && error.response.status === 429;
            const isLastAttempt = i === maxRetries - 1;

            if (isRateLimited && !isLastAttempt) {
                console.warn(`⚠️ Menerima 429 dari PayWuz. Retry ke-${i + 1} dalam ${delayMs}ms...`);
                await new Promise(resolve => setTimeout(resolve, delayMs));
                delayMs *= 1.5; 
            } else {
                throw error;
            }
        }
    }
}

const cacheSchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true },
    data: { type: mongoose.Schema.Types.Mixed, required: true },
    createdAt: { type: Date, default: Date.now, expires: 60 } 
});

const CacheModel = mongoose.models.Cache || mongoose.model('Cache', cacheSchema);

const voucherSchema = new mongoose.Schema({
    code: { type: String, required: true, unique: true, uppercase: true },
    discount: { type: Number, required: true },
    type: { type: String, enum: ['percentage', 'fixed'], default: 'percentage' },
    expiredAt: { type: Date, required: true },
    usageLimit: { type: Number, default: 20 },
    usedCount: { type: Number, default: 0 },
    usedBy: [{ type: String }],
    createdAt: { type: Date, default: Date.now }
});

const Voucher = mongoose.models.Voucher || mongoose.model('Voucher', voucherSchema);

const productSchema = new mongoose.Schema({
    Id: { type: String, required: true, unique: true, trim: true },
    nama: { type: String, required: true, trim: true },
    harga: { type: Number, required: true },
    harga_diskon: { type: Number, default: null },
    kategori: { type: String, required: true },
    badge: { type: String, default: "" },
    terjual: { type: Number, default: 0 },
    stok: { type: Number, default: 0 },
    gambar: { 
        type: [String], 
        default: ["https://arulz-xd.my.id/files/X1F0Cn.png"] 
    },    
    deskripsi: { type: String, default: "" },
    link: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const Product = mongoose.models.Product || mongoose.model('Product', productSchema);

function getUserIdentifier(req) {
    if (req.user) {
        return (req.user.email || req.user.username || req.user._id || "").toString().toLowerCase().trim();
    }
    const bodyIdentifier = req.body?.username || req.body?.email || req.body?.userIdentifier;
    if (bodyIdentifier) {
        return bodyIdentifier.toString().toLowerCase().trim();
    }
    return req.ip; 
}

app.post('/api/vouchers/claim', async (req, res) => {
    try {
        const code = req.body.code;
        if (!code) {
            return res.status(400).json({ status: false, message: 'Kode voucher wajib diisi!' });
        }

        const cleanCode = code.trim().toUpperCase();
        const userIdentifier = getUserIdentifier(req);

        const voucher = await Voucher.findOne({ code: cleanCode });

        if (!voucher) {
            return res.status(404).json({ status: false, message: 'Kode voucher tidak ditemukan!' });
        }

        if (voucher.usageLimit <= 0) {
            return res.status(400).json({ 
                status: false, 
                reason: 'limit_reached',
                message: 'Kuota penggunaan voucher ini sudah habis!' 
            });
        }

        if (voucher.usedBy && voucher.usedBy.includes(userIdentifier)) {
            return res.status(400).json({
                status: false,
                reason: 'already_used',
                message: 'Anda sudah pernah menggunakan voucher ini sebelumnya!'
            });
        }

        if (new Date() > new Date(voucher.expiredAt)) {
            return res.status(400).json({ 
                status: false, 
                reason: 'expired',
                message: 'Voucher telah kedaluwarsa!' 
            });
        }

        voucher.usedCount += 1;
        voucher.usageLimit = Math.max(0, voucher.usageLimit - 1); 

        if (!voucher.usedBy) voucher.usedBy = [];
        voucher.usedBy.push(userIdentifier);

        await voucher.save();

        return res.json({
            status: true,
            message: 'Voucher berhasil diklaim!',
            voucher: {
                code: voucher.code,
                discount: voucher.discount,
                type: voucher.type
            },
            data: {
                code: voucher.code,
                discount: voucher.discount,
                type: voucher.type
            }
        });
    } catch (err) {
        console.error("Error Claim Voucher:", err);
        return res.status(500).json({ status: false, message: 'Terjadi kesalahan pada server.' });
    }
});

app.get('/api/vouchers/:code', async (req, res) => {
    try {
        const code = req.query.code || req.params.code;
        if (!code) {
            return res.status(400).json({ status: false, message: 'Kode voucher wajib diisi!' });
        }

        const userIdentifier = getUserIdentifier(req);
        const voucher = await Voucher.findOne({ code: code.trim().toUpperCase() });
        if (!voucher) {
            return res.status(404).json({ status: false, message: 'Kode voucher tidak ditemukan!' });
        }

        if (voucher.usageLimit <= 0) {
            return res.status(400).json({ 
                status: false, 
                reason: 'limit_reached',
                message: 'Kuota penggunaan voucher ini sudah habis!' 
            });
        }

        if (voucher.usedBy && voucher.usedBy.includes(userIdentifier)) {
            return res.status(400).json({
                status: false,
                reason: 'already_used',
                message: 'Anda sudah pernah menggunakan voucher ini sebelumnya!'
            });
        }

        if (new Date() > new Date(voucher.expiredAt)) {
            return res.status(400).json({ 
                status: false, 
                reason: 'expired',
                message: 'Voucher telah kedaluwarsa!' 
            });
        }

        return res.json({
            status: true,
            message: 'Voucher berhasil ditemukan!',
            data: {
                code: voucher.code,
                discount: voucher.discount,
                type: voucher.type
            }
        });
    } catch (err) {
        return res.status(500).json({ status: false, message: 'Terjadi kesalahan pada server.' });
    }
});

async function recordProductBuyer(productName, userIdentifier) {
    if (!productName || !userIdentifier) return;
    try {
        await Product.findOneAndUpdate(
            { nama: { $regex: new RegExp(`^${productName.trim()}$`, 'i') } },
            { $addToSet: { purchasedBy: userIdentifier.toString().toLowerCase().trim() } }
        );
    } catch (err) {
        console.error("❌ Gagal mencatat pembeli produk:", err.message);
    }
}

async function updateProductStockAndSold(productName, qtyChange = 1, isRollback = false) {
    try {
        if (!productName) return null;

        const product = await Product.findOne({ 
            nama: { $regex: new RegExp(`^${productName.trim()}$`, 'i') } 
        });

        if (product) {
            if (isRollback) {
                product.stok = (product.stok || 0) + qtyChange;
                product.terjual = Math.max(0, (product.terjual || 0) - qtyChange);
                console.log(`🔄 [STOK RESTORED] Produk "${product.nama}": Stok (${product.stok}), Terjual (${product.terjual})`);
            } else {
                product.stok = Math.max(0, (product.stok || 0) - qtyChange);
                product.terjual = (product.terjual || 0) + qtyChange;
                console.log(`📦 [STOK UPDATED] Produk "${product.nama}": Stok (${product.stok}), Terjual (${product.terjual})`);
            }

            await product.save();
            return product;
        }
    } catch (err) {
        console.error("❌ Gagal meng-update stok produk:", err.message);
    }
    return null;
}

async function setCache(key, data) {
    try {
        await CacheModel.findOneAndUpdate(
            { key },
            { data, createdAt: new Date() },
            { upsert: true, new: true }
        );
    } catch (e) {
        console.error("Gagal simpan cache MongoDB:", e.message);
    }
}

async function getCache(key) {
    try {
        const cached = await CacheModel.findOne({ key });
        return cached ? cached.data : null;
    } catch (e) {
        return null;
    }
}

async function deleteCache(key) {
    try {
        await CacheModel.deleteOne({ key });
    } catch (e) {}
}

function scheduleTransactionDeletion(orderId) {
    setTimeout(async () => {
        try {
            await Transaction.deleteOne({ orderId });
            await deleteCache(`trx_${orderId}`);
            console.log(`🗑️ Transaksi ${orderId} berhasil dihapus dari database.`);
        } catch (err) {
            console.error(`❌ Gagal menghapus transaksi ${orderId}:`, err.message);
        }
    }, 60 * 1000);
}

mongoose.connection.once('open', async () => {
    try {
        await mongoose.connection.db.collection('transactions').dropIndex('transactionId_1');
        console.log('🧹 Berhasil menghapus index lama transactionId_1');
    } catch (e) {}
});

const transactionSchema = new mongoose.Schema({
    orderId: { type: String, required: true, unique: true },
    amount: { type: Number, required: true },
    paymentNumber: { type: String, default: null }, 
    paymentMethod: { type: String, default: "QRIS" },
    status: { type: String, default: "pending" }, 
    itemDetails: {
        nama: String,
        harga: Number,
        harga_diskon: Number,
        kategori: String,
        gambar: String,
        link: String
    },
    productLink: { type: String, default: null },
    createdAt: { type: Date, default: Date.now },
    expiredAt: { type: Date, required: true },
    updatedAt: { type: Date, default: Date.now }
});

const Transaction = mongoose.models.Transaction || mongoose.model('Transaction', transactionSchema);

function verifyPaywuzSignature(rawBody, receivedSignature, apikey) {
    if (!receivedSignature) return false;

    const computedSignature = "sha256=" + crypto
        .createHmac("sha256", apikey)
        .update(typeof rawBody === 'string' ? rawBody : JSON.stringify(rawBody))
        .digest("hex");

    try {
        return crypto.timingSafeEqual(
            Buffer.from(receivedSignature),
            Buffer.from(computedSignature)
        );
    } catch (err) {
        return false;
    }
}

app.post('/transactions', async (req, res) => {
    try {
        const { orderId, amount, itemDetails, qty } = req.body;
        const buyQty = Number(qty) || 1;

        if (!orderId || !amount) {
            return res.status(400).json({ 
                status: false,
                error: "INVALID_PAYLOAD", 
                message: "orderId dan amount wajib diisi!" 
            });
        }

        const existingTrx = await Transaction.findOne({ orderId });
        if (existingTrx) {
            return res.json({ status: true, data: existingTrx });
        }

        const inputAmount = Number(amount);

        const paywuzRes = await axiosPaywuzWithRetry({
            method: 'post',
            url: `${PAYWUZ_BASE_URL}/transactions`,
            data: {
                orderId,
                amount: inputAmount,
                paymentMethod: "QRIS",
                feeByMerchant: false
            },
            headers: PAYWUZ_HEADERS
        });

        const transactionData = paywuzRes.data?.data || paywuzRes.data;
        const qrisNumber = transactionData.paymentNumber || transactionData.qrString || transactionData.qrUrl;

        const safeNum = (val) => {
            const num = Number(val);
            return (!isNaN(num) && num > 0) ? num : null;
        };

        const feeFlatIdr = Number(transactionData.feeFlatIdr) || 290;
        const feePercentBps = Number(transactionData.feePercentBps) || 70;
        const calculatedFee = feeFlatIdr + Math.ceil((inputAmount * feePercentBps) / 10000);

        let finalAmount = safeNum(transactionData.grossAmount) || 
                          safeNum(transactionData.totalAmount) || 
                          safeNum(transactionData.total);

        if (!finalAmount) {
            const feeVal = safeNum(transactionData.fee) || safeNum(transactionData.feeAdmin) || calculatedFee;
            finalAmount = inputAmount + feeVal;
        }

        let pLink = itemDetails?.link || null;
        if (!pLink && itemDetails?.nama) {
            const dbProduct = await Product.findOne({ 
                nama: { $regex: new RegExp(`^${itemDetails.nama.trim()}$`, 'i') }
            }).lean();
            if (dbProduct) pLink = dbProduct.link;
        }

        const expiredAt = new Date(Date.now() + 15 * 60 * 1000);

        const newTransaction = new Transaction({
            orderId,
            amount: finalAmount,
            paymentNumber: qrisNumber,
            paymentMethod: "QRIS",
            status: (transactionData.status || "pending").toLowerCase(),
            itemDetails: {
                ...itemDetails,
                qty: buyQty
            },
            productLink: pLink,
            expiredAt: expiredAt
        });

        await newTransaction.save();

        return res.json({
            status: true,
            data: newTransaction
        });

    } catch (error) {
        console.error("Error Create TRX:", error.response?.data || error.message);
        return res.status(500).json({
            status: false,
            error: "CREATE_TRANSACTION_FAILED",
            message: error.response?.data?.message || error.message || "Gagal membuat transaksi QRIS"
        });
    }
});

app.get('/transactions/:orderId', async (req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    try {
        const { orderId } = req.params;

        const cachedData = await getCache(`trx_${orderId}`);
        if (cachedData) {
            return res.json({ data: cachedData });
        }

        let localTrx = await Transaction.findOne({ orderId });

        if (!localTrx) {
            return res.status(404).json({ 
                error: "TRANSACTION_NOT_FOUND", 
                message: "Transaksi tidak ditemukan" 
            });
        }

        if (localTrx.status.toLowerCase() === "pending" && new Date() > new Date(localTrx.expiredAt)) {
            localTrx.status = "cancelled";
            localTrx.updatedAt = new Date();
            await localTrx.save();
            scheduleTransactionDeletion(orderId);

            const resultData = {
                orderId: localTrx.orderId,
                status: "cancelled",
                amount: localTrx.amount,
                paymentNumber: localTrx.paymentNumber,
                expiredAt: localTrx.expiredAt,
                productLink: null
            };

            await setCache(`trx_${orderId}`, resultData);
            return res.json({ data: resultData });
        }

        const currentStatus = localTrx.status.toLowerCase();
        const isSuccess = ["settlement", "success", "paid", "settled"].includes(currentStatus);

        if (isSuccess && !localTrx.productLink && localTrx.itemDetails?.nama) {
            const pathProduk = path.join(__dirname, 'database', 'produk.json');
            if (fs.existsSync(pathProduk)) {
                try {
                    const products = JSON.parse(fs.readFileSync(pathProduk, 'utf8'));
                    const targetNama = localTrx.itemDetails.nama.trim().toLowerCase();
                    const matchedProduct = products.find(p => p.nama && p.nama.trim().toLowerCase() === targetNama);
                    if (matchedProduct && matchedProduct.link) {
                        localTrx.productLink = matchedProduct.link;
                        await localTrx.save();
                    }
                } catch (parseErr) {}
            }
        }

        const responseData = {
            orderId: localTrx.orderId,
            status: currentStatus,
            amount: localTrx.amount,
            paymentNumber: localTrx.paymentNumber,
            expiredAt: localTrx.expiredAt,
            productLink: isSuccess ? localTrx.productLink : null
        };

        await setCache(`trx_${orderId}`, responseData);

        res.json({
            data: responseData
        });

    } catch (error) {
        console.error("Error Status TRX:", error.message);
        const localTrx = await Transaction.findOne({ orderId: req.params.orderId });
        if (localTrx) {
            return res.json({ data: localTrx });
        }
        res.status(500).json({ 
            error: "TRANSACTION_FETCH_FAILED", 
            message: "Gagal mengambil status transaksi" 
        });
    }
});

app.post('/transactions/:orderId/cancel', async (req, res) => {
    try {
        const { orderId } = req.params;
        const localTrx = await Transaction.findOne({ orderId });

        if (!localTrx) {
            return res.status(404).json({ status: false, message: "Transaksi tidak ditemukan" });
        }

        const prevStatus = localTrx.status.toLowerCase();

        try {
            await axiosPaywuzWithRetry({
                method: 'post',
                url: `${PAYWUZ_BASE_URL}/transactions/${orderId}/cancel`,
                headers: PAYWUZ_HEADERS
            });
        } catch (err) {
            console.warn(`Paywuz cancel notice for ${orderId}:`, err.message);
        }

        if (["paid", "settlement", "success"].includes(prevStatus)) {
            if (localTrx.itemDetails && localTrx.itemDetails.nama) {
                const qtyPurchased = localTrx.itemDetails.qty || 1;
                await updateProductStockAndSold(localTrx.itemDetails.nama, qtyPurchased, true);
            }
        }

        localTrx.status = "cancelled";
        localTrx.updatedAt = new Date();
        await localTrx.save();

        await deleteCache(`trx_${orderId}`);
        scheduleTransactionDeletion(orderId);

        return res.json({
            status: true,
            data: { orderId, status: "cancelled" }
        });

    } catch (error) {
        console.error("Error Cancel TRX:", error.message);
        res.status(500).json({
            error: "CANCEL_TRANSACTION_FAILED",
            message: error.message || "Gagal membatalkan transaksi"
        });
    }
});

app.post('/webhook', async (req, res) => {
    try {
        const signature = req.headers['x-paywuz-signature'];
        const payloadToVerify = req.rawBody || req.body;

        const isValid = verifyPaywuzSignature(payloadToVerify, signature, PAYWUZ_API_KEY);

        if (!isValid && process.env.NODE_ENV === 'production') {
            return res.status(401).json({ 
                error: "INVALID_SIGNATURE", 
                message: "Signature webhook tidak valid!" 
            });
        }

        const payload = req.body;
        const eventName = payload?.event || payload?.type; 
        const payloadData = payload?.data || payload;
        const orderId = payloadData?.orderId;
        const status = payloadData?.status ? payloadData.status.toLowerCase() : null;

        if (!orderId) {
            return res.status(400).json({ error: "MISSING_ORDER_ID", message: "orderId tidak ada!" });
        }

        if (orderId && status) {
            let localTrx = await Transaction.findOne({ orderId });

            if (localTrx) {
                const prevStatus = localTrx.status.toLowerCase();
                localTrx.status = status;
                localTrx.updatedAt = new Date();

                const isPaidEvent = eventName === "transaction.paid" || ["paid", "settlement", "success"].includes(status);
                const isCancelEvent = ["cancelled", "failed", "expire"].includes(status);

                if (isPaidEvent && !["paid", "settlement", "success"].includes(prevStatus)) {
                    console.log(`⚡ [TRANSACTION.PAID] Order ID ${orderId} Lunas!`);

                    // 1. LOGIKA UNTUK PEMBELIAN PRODUK STORE
                    if (localTrx.itemDetails && localTrx.itemDetails.nama) {
                        const qtyPurchased = localTrx.itemDetails.qty || 1;

                        // Jika transaksi BUKAN upgrade role API Key, update stok toko biasa
                        if (!localTrx.itemDetails.nama.includes("Upgrade Role")) {
                            await updateProductStockAndSold(localTrx.itemDetails.nama, qtyPurchased, false);

                            const buyerIdentifier = getUserIdentifier(req) || localTrx.paymentNumber;
                            await recordProductBuyer(localTrx.itemDetails.nama, buyerIdentifier);
                        }
                    }

                    // 2. LOGIKA OTOMATISASI UPGRADE ROLE & API KEY USER
                    if (localTrx.itemDetails && localTrx.itemDetails.nama && localTrx.itemDetails.nama.includes("Upgrade Role")) {
                        try {
                            // Identifikasi user dari email/username/IP
                            const buyerIdentifier = getUserIdentifier(req);
                            const daysToAdd = Number(localTrx.itemDetails.qty) || 3;
                            const isVip = localTrx.itemDetails.nama.toLowerCase().includes("vip");
                            const targetRole = isVip ? "VIP User" : "Premium User";

                            let targetUser = null;

                            // Cari user berdasarkan email, username, atau ID
                            if (buyerIdentifier) {
                                targetUser = await User.findOne({
                                    $or: [
                                        { email: buyerIdentifier.toLowerCase() },
                                        { username: buyerIdentifier.toLowerCase() }
                                    ]
                                });
                            }

                            // Fallback: Jika tidak ditemukan via req, cari via session/IP jika ada
                            if (!targetUser && req.user) {
                                targetUser = await User.findById(req.user.id || req.user._id);
                            }

                            if (targetUser) {
                                // Hitung tanggal ekspirasi baru (akumulasi jika masa aktif masih berjalan)
                                let currentExpiry = (targetUser.roleExpiresAt && new Date(targetUser.roleExpiresAt) > new Date())
                                    ? new Date(targetUser.roleExpiresAt)
                                    : new Date();

                                currentExpiry.setDate(currentExpiry.getDate() + daysToAdd);

                                targetUser.role = targetRole;
                                targetUser.roleExpiresAt = currentExpiry;

                                // Generate Apikey otomatis jika belum berkesesuaian
                                if (targetRole === "Premium User") {
                                    targetUser.apikey = generatePremiumApiKey(targetUser.username);
                                } else if (targetRole === "VIP User") {
                                    if (!targetUser.apikey || targetUser.apikey.startsWith('xs-pedia')) {
                                        targetUser.apikey = `${targetUser.username.toLowerCase()}-custom-vip`;
                                    }
                                }

                                await targetUser.save();
                                console.log(`🎉 [UPGRADE SUCCESS] User ${targetUser.username} berhasil di-upgrade ke ${targetRole} hingga ${currentExpiry.toISOString()}`);
                            } else {
                                console.warn(`⚠️ [UPGRADE WARNING] Tidak dapat menemukan akun user untuk transaksi ${orderId}`);
                            }
                        } catch (upgradeErr) {
                            console.error("❌ Gagal memproses upgrade role user di webhook:", upgradeErr.message);
                        }
                    }

                    // Auto-fill link produk jika belum terisi
                    if (!localTrx.productLink && localTrx.itemDetails?.nama) {
                        const dbProduct = await Product.findOne({ 
                            nama: { $regex: new RegExp(`^${localTrx.itemDetails.nama.trim()}$`, 'i') } 
                        }).lean();
                        if (dbProduct) localTrx.productLink = dbProduct.link;
                    }
                } 
                else if (isCancelEvent && ["paid", "settlement", "success"].includes(prevStatus)) {
                    // Rollback stok jika transaksi toko biasa dibatalkan setelah lunas
                    if (localTrx.itemDetails && localTrx.itemDetails.nama && !localTrx.itemDetails.nama.includes("Upgrade Role")) {
                        const qtyPurchased = localTrx.itemDetails.qty || 1;
                        await updateProductStockAndSold(localTrx.itemDetails.nama, qtyPurchased, true);
                    }
                }

                await localTrx.save();
                await deleteCache(`trx_${orderId}`);

                if (["settlement", "success", "paid", "settled", "failed", "cancelled"].includes(status)) {
                    scheduleTransactionDeletion(orderId);
                }
            }
        }

        return res.status(200).json({ data: { message: "Webhook diproses dengan sukses", orderId } });

    } catch (err) {
        console.error("Webhook Error:", err);
        return res.status(500).json({ error: "WEBHOOK_PROCESSING_ERROR", message: "Error internal webhook" });
    }
});

app.post('/api/store/manual-order', async (req, res) => {
    try {
        const productName = req.body.productName;
        const qty = req.body.qty;
        const buyQty = Number(qty) || 1;

        if (!productName) {
            return res.status(400).json({ status: false, message: "Nama produk wajib diisi!" });
        }

        const updatedProduct = await updateProductStockAndSold(productName, buyQty);

        if (!updatedProduct) {
            return res.status(404).json({ status: false, message: "Produk tidak ditemukan di database." });
        }

        return res.json({
            status: true,
            message: "Stok dan jumlah terjual berhasil diperbarui secara otomatis!",
            data: updatedProduct
        });
    } catch (err) {
        console.error("Manual Order Error:", err);
        return res.status(500).json({ status: false, message: "Terjadi kesalahan server." });
    }
});

app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});

passport.use(new LocalStrategy({ usernameField: 'username', passwordField: 'password' }, 
    async (usernameOrEmail, password, done) => {
        try {
            const user = await User.findOne({
                $or: [
                    { username: usernameOrEmail }, 
                    { email: usernameOrEmail.toLowerCase() }
                ]
            });

            if (!user) return done(null, false, { message: 'Username atau Email tidak ditemukan.' });

            if (!user.password || user.provider !== 'local') {
                return done(null, false, { 
                    message: `Akun ini terdaftar via ${user.provider.toUpperCase()}. Silakan masuk dengan tombol ${user.provider.toUpperCase()}.` 
                });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) return done(null, false, { message: 'Kata sandi salah.' });

            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }
));

function sendSweetAlert(res, icon, title, text, redirectUrl) {
    return res.send(`
        <!DOCTYPE html>
        <html lang="id">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Notification</title>
            <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
            <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
            <style>
                body {
                    background-color: #0b0f19;
                    font-family: 'Plus Jakarta Sans', sans-serif;
                }
                .swal2-popup {
                    background: #111827 !important;
                    border: 1px solid rgba(255, 255, 255, 0.08) !important;
                    border-radius: 16px !important;
                    box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3) !important;
                }
                .swal2-title {
                    color: #ffffff !important;
                    font-weight: 700 !important;
                }
                .swal2-html-container {
                    color: #9ca3af !important;
                }
                .swal2-confirm {
                    background: linear-gradient(to right, #0891b2, #06b6d4) !important;
                    color: #0f172a !important;
                    font-weight: 700 !important;
                    border-radius: 12px !important;
                    padding: 10px 24px !important;
                }
            </style>
        </head>
        <body>
            <script>
                Swal.fire({
                    icon: '${icon}',
                    title: '${title}',
                    text: '${text}',
                    confirmButtonText: 'OKE',
                    scrollbarPadding: false
                }).then(() => {
                    window.location = '${redirectUrl}';
                });
            </script>
        </body>
        </html>
    `);
}

// --- LOGIN ROUTE (MUREN MONGODB) ---
app.post('/auth/login', (req, res, next) => {
    passport.authenticate('local', async (err, user, info) => { 
        if (err) return next(err);

        if (!user) {
            const pesanGagal = info && info.message ? info.message : 'Username atau password salah.';
            return sendSweetAlert(res, 'error', 'Gagal Masuk', pesanGagal, '/login');
        }

        req.logIn(user, async (err) => { 
            if (err) return next(err);

            try {
                // Pastikan apikey sesuai dengan format role milik dokumen Mongo
                let needSave = false;
                const roleLower = (user.role || '').toLowerCase();

                if (roleLower.includes('vip')) {
                    if (!user.apikey) {
                        user.apikey = `${user.username.toLowerCase()}-custom-vip`;
                        needSave = true;
                    }
                } else if (roleLower.includes('premium')) {
                    if (!user.apikey || !user.apikey.includes('prem-')) {
                        user.apikey = generatePremiumApiKey(user.username);
                        needSave = true;
                    }
                } else {
                    if (!user.apikey || !user.apikey.startsWith('xs-pedia')) {
                        user.apikey = generateFreeApiKey();
                        needSave = true;
                    }
                }

                if (needSave) {
                    await user.save();
                }

                const userPayload = {
                    id: user._id,
                    username: user.username,
                    email: user.email,
                    name: user.username,
                    avatar: user.avatar?.startsWith('data:') ? null : (user.avatar || 'https://arulz-xd.my.id/files/X1F0Cn.png'),
                    role: user.role,     
                    apikey: user.apikey   
                };

                const token = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '7d' });

                res.cookie('auth_session', token, {
                    maxAge: 7 * 24 * 60 * 60 * 1000, 
                    httpOnly: true,
                    secure: true, 
                    sameSite: 'lax'
                });

                return res.redirect('/docs');

            } catch (error) {
                console.error("Gagal sinkronisasi data saat login:", error);
                return next(error);
            }
        });
    })(req, res, next);
});

// --- REGISTER ROUTE (MUREN MONGODB) ---
app.post('/auth/register', async (req, res) => {
    try {
        const username = req.body.username;
        const email = req.body.email;
        const password = req.body.password;

        if (!username || !email || !password) {
            return sendSweetAlert(res, 'error', 'Pendaftaran Gagal', 'Semua data wajib diisi!', '/login');
        }

        const cleanUsername = username.trim();
        const cleanEmail = email.toLowerCase().trim();

        const existingUser = await User.findOne({ 
            $or: [{ username: cleanUsername }, { email: cleanEmail }] 
        });

        if (existingUser) {
            return sendSweetAlert(res, 'warning', 'Sudah Terdaftar', 'Username atau Email sudah terdaftar!', '/login');
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const userRole = 'Free User';
        const userApiKey = generateFreeApiKey();

        const defaultAvatar = 'https://arulz-xd.my.id/files/X1F0Cn.png';

        const newUser = new User({
            username: cleanUsername,
            email: cleanEmail,
            password: hashedPassword,
            provider: 'local',
            role: userRole,
            apikey: userApiKey,
            avatar: defaultAvatar
        });
        await newUser.save();

        const userPayload = {
            id: newUser._id,
            username: newUser.username,
            name: newUser.username,
            avatar: defaultAvatar,
            role: newUser.role,
            apikey: newUser.apikey
        };

        const token = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '7d' });

        res.cookie('auth_session', token, {
            maxAge: 7 * 24 * 60 * 60 * 1000, 
            httpOnly: true,
            secure: true, 
            sameSite: 'lax'
        });

        req.logIn(newUser, (err) => {
            if (err) return res.redirect('/login');
            return sendSweetAlert(res, 'success', 'Berhasil!', 'Pendaftaran berhasil! Selamat datang.', '/docs');
        });

    } catch (error) {
        console.error(error);
        res.status(500).send('Terjadi error internal saat pendaftaran.');
    }
});

app.post('/auth/forgot-password', async (req, res) => {
    try {
        const email = req.body.email;
        if (!email) {
            return sendSweetAlert(res, 'error', 'Wajib Diisi', 'Email wajib diisi!', '/login');
        }

        const user = await User.findOne({ email: email.toLowerCase().trim() });
        if (!user) {
            return sendSweetAlert(res, 'error', 'Tidak Ditemukan', 'Email tersebut tidak terdaftar di sistem kami.', '/login');
        }

        if (user.provider !== 'local') {
            return sendSweetAlert(res, 'error', 'Metode Login OAuth', `Akun ini mendaftar via ${user.provider.toUpperCase()}, tidak memerlukan reset password.`, '/login');
        }

        const resetToken = crypto.randomBytes(20).toString('hex');

        user.resetPasswordToken = resetToken;
        user.resetPasswordExpires = Date.now() + 3600000; 
        await user.save();

        const transporter = nodemailer.createTransport({
            host: 'smtp.gmail.com',
            port: 465,
            secure: true, 
            auth: {
                user: 'supportarulzxd@gmail.com',
                pass: 'matsgyapivykobdv'
            },
            tls: { rejectUnauthorized: false }
        });

        const host = req.get('host');
        const protocol = req.secure || req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
        const resetUrl = `${protocol}://${host}/reset-password/${resetToken}`;

        const mailOptions = {
            from: '"Support XS-Pedia" <supportarulzxd@gmail.com>',
            to: user.email,
            subject: 'Permintaan Reset Kata Sandi',
            html: `
<div style="background-color: #0b0f19; padding: 40px 20px; font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; min-height: 100%;">
    <table align="center" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 550px; background-color: #111827; border-radius: 16px; border: 1px solid rgba(255, 255, 255, 0.08); box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);">
        <tr>
            <td style="padding: 32px 32px 24px 32px; text-align: center;">
                <h1 style="margin: 0; color: #ffffff; font-size: 24px; font-weight: 800; tracking-tight: -0.025em;">
                    XS-Pedia API
                </h1>
            </td>
        </tr>
        <tr>
            <td style="padding: 0 32px 24px 32px;">
                <div style="height: 1px; background: linear-gradient(to right, transparent, rgba(6, 182, 212, 0.2), transparent);"></div>
            </td>
        </tr>
        <tr>
            <td style="padding: 0 32px 32px 32px; color: #9ca3af; font-size: 14px; line-height: 24px;">
                <p style="margin: 0 0 16px 0; color: #ffffff; font-size: 16px; font-weight: 600;">Halo ${user.username},</p>
                <p style="margin: 0 0 16px 0;">Kami menerima permintaan untuk mengatur ulang kata sandi akun XS-Pedia API Anda.</p>
                <p style="margin: 0 0 24px 0;">Silakan klik tombol di bawah ini untuk membuat kata sandi baru:</p>
                
                <table align="center" border="0" cellpadding="0" cellspacing="0" style="margin: 0 auto;">
                    <tr>
                        <td align="center" bgcolor="#06b6d4" style="border-radius: 12px;">
                            <a href="${resetUrl}" target="_blank" style="display: inline-block; padding: 14px 28px; font-size: 14px; font-weight: 700; color: #0f172a; text-decoration: none; text-transform: uppercase; letter-spacing: 0.05em;">Reset Kata Sandi</a>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
        <tr>
            <td style="padding: 0 32px 32px 32px; color: #6b7280; font-size: 12px; line-height: 20px;">
                <p style="margin: 0 0 12px 0; padding-top: 16px; border-top: 1px solid rgba(255, 255, 255, 0.05);">
                    <strong style="color: #ef4444;">Penting:</strong> Link ini hanya berlaku selama <span style="color: #9ca3af; font-weight: 600;">1 jam</span> demi keamanan akun Anda.
                </p>
                <p style="margin: 0;">Jika Anda tidak merasa meminta reset password ini, Anda dapat mengabaikan email ini dengan aman.</p>
            </td>
        </tr>
    </table>
</div>
`
        };

        await transporter.sendMail(mailOptions);
        return sendSweetAlert(res, 'success', 'Sukses!', 'Link reset password telah dikirim ke email Anda.', '/login');

    } catch (error) {
        console.error(error);
        res.status(500).send('Gagal memproses lupa password.');
    }
});

app.get('/reset-password/:token', async (req, res) => {
    try {
        const user = await User.findOne({ 
            resetPasswordToken: req.params.token, 
            resetPasswordExpires: { $gt: Date.now() } 
        });

        if (!user) {
            return sendSweetAlert(res, 'error', 'Link Kadaluwarsa', 'Link reset password tidak valid atau sudah kedaluwarsa. Silakan minta link baru.', '/login');
        }

        res.send(`
    <!DOCTYPE html>
    <html lang="id">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Buat Password Baru - XS-Pedia REST API</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
        <style>
            body { background-color: #0b0f19; }
            .solid-card { background: #111827; border: 1px solid rgba(255, 255, 255, 0.08); }
        </style>
    </head>
    <body class="flex flex-col items-center justify-center min-h-screen p-4 antialiased text-gray-200">
        <div class="solid-card p-8 rounded-2xl shadow-lg w-full max-w-md relative overflow-hidden">
            <div class="text-center mb-6 relative z-10">
                <h1 class="text-xl font-extrabold tracking-tight text-white mb-1">
                    Atur Ulang <span class="text-cyan-400">Kata Sandi</span>
                </h1>
                <p class="text-xs text-gray-400">Silakan masukkan kata sandi baru Anda yang aman.</p>
            </div>

            <form action="/reset-password/${req.params.token}" method="POST" class="space-y-4 relative z-10">
                <div>
                    <label class="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-1.5">Password Baru</label>
                    <input id="new-password" type="password" name="password" required placeholder="••••••••" 
                        class="w-full bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 font-medium transition">
                </div>

                <div>
                    <label class="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-1.5">Konfirmasi Password Baru</label>
                    <input id="confirm-password" type="password" name="confirmPassword" required placeholder="••••••••" 
                        class="w-full bg-slate-900/60 border border-white/10 rounded-xl px-4 py-3 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 font-medium transition">
                </div>

                <button type="submit" class="w-full mt-2 bg-gradient-to-r from-cyan-600 to-cyan-500 text-slate-950 font-bold py-3 rounded-xl text-sm tracking-wide uppercase">Simpan Password Baru</button>
            </form>
        </div>
    </body>
    </html>
`);

    } catch (err) {
        res.status(500).send("Error server.");
    }
});

app.post('/reset-password/:token', async (req, res) => {
    try {
        const { password, confirmPassword } = req.body;

        if (password !== confirmPassword) {
            return sendSweetAlert(res, 'warning', 'Tidak Cocok', 'Password dan konfirmasi password tidak cocok!', '/login');
        }

        const user = await User.findOne({ 
            resetPasswordToken: req.params.token, 
            resetPasswordExpires: { $gt: Date.now() } 
        });

        if (!user) {
            return sendSweetAlert(res, 'error', 'Gagal', 'Link reset password tidak valid atau sudah kedaluwarsa.', '/login');
        }

        user.password = await bcrypt.hash(password, 10);
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        return sendSweetAlert(res, 'success', 'Berhasil!', 'Password berhasil diubah! Silakan login dengan password baru Anda.', '/login');
    } catch (err) {
        res.status(500).send("Gagal menyimpan password baru.");
    }
});

app.get('/login', (req, res) => {
    if (req.user) {
        return res.redirect('/docs'); 
    }
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

const GITHUB_CLIENT_ID = 'Ov23linJtLUZuyJVXpXZ';
const GITHUB_CLIENT_SECRET = '99834867b22a9f173a64b492e55d4e8f5ef9e9eb';
const GITHUB_CALLBACK_URL = process.env.GITHUB_CALLBACK_URL || "https://arulz-xd.my.id/auth/github/callback";

const d = "613783942158";
const e = "-63q31341ivgrlulq8";
const f = "ha0m4uqmnoa6kq0";
const cl = ".apps.";
const id = "googleusercontent.com";

const GOOGLE_CLIENT_ID = `${d}${e}${f}${cl}${id}`;
const GOOGLE_CLIENT_SECRET = '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';
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || "https://arulz-xd.my.id/auth/google/callback";

/* ==================== ENDPOINT AUTH GITHUB ==================== */
app.get('/auth/github', (req, res) => {
    const url = `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}&redirect_uri=${GITHUB_CALLBACK_URL}&scope=user:email`;
    res.redirect(url);
});

app.get('/auth/github/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) return res.send('Authentication failed: No code provided');

    try {
        const tokenResponse = await axios.post('https://github.com/login/oauth/access_token', {
            client_id: GITHUB_CLIENT_ID,
            client_secret: GITHUB_CLIENT_SECRET,
            code: code
        }, { headers: { accept: 'application/json' } });

        const accessToken = tokenResponse.data.access_token;
        if (!accessToken) return res.send('Authentication failed: Invalid access token');

        const userResponse = await axios.get('https://api.github.com/user', {
            headers: { Authorization: `token ${accessToken}` }
        });

        const userData = userResponse.data;
        let userEmail = userData.email;

        if (!userEmail) {
            try {
                const emailsResponse = await axios.get('https://api.github.com/user/emails', {
                    headers: { Authorization: `token ${accessToken}` }
                });
                const primaryEmailObj = emailsResponse.data.find(e => e.primary && e.verified) || emailsResponse.data[0];
                if (primaryEmailObj) {
                    userEmail = primaryEmailObj.email;
                }
            } catch (emailErr) {
                console.error('Gagal mengambil private email:', emailErr.message);
            }
        }

        const finalEmail = (userEmail || `${userData.login}@github.com`).toLowerCase().trim();
        const currentUsername = (userData.login || finalEmail.split('@')[0]).toLowerCase().trim();

        let dbUser = await User.findOne({ email: finalEmail });

        if (!dbUser) {
            dbUser = new User({
                username: currentUsername,
                email: finalEmail,
                provider: 'github',
                providerId: String(userData.id),
                apikey: generateFreeApiKey(),
                role: 'Free User',
                avatar: userData.avatar_url || 'https://arulz-xd.my.id/files/X1F0Cn.png'
            });

            await dbUser.save();
        } else {
            if (userData.avatar_url && dbUser.avatar !== userData.avatar_url) {
                dbUser.avatar = userData.avatar_url;
                await dbUser.save();
            }
        }

        const userPayload = {
            id: dbUser._id,
            username: dbUser.username,
            email: dbUser.email,
            name: userData.name || dbUser.username,
            avatar: dbUser.avatar?.startsWith('data:') ? null : dbUser.avatar,
            role: dbUser.role,
            apikey: dbUser.apikey
        };

        const token = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '7d' });

        res.cookie('auth_session', token, {
            maxAge: 7 * 24 * 60 * 60 * 1000, 
            httpOnly: true,
            secure: true, 
            sameSite: 'lax'
        });

        res.redirect('/docs?showProfile=true');
    } catch (error) {
        console.error(error);
        res.send('Login Error: ' + error.message);
    }
});

/* ==================== ENDPOINT AUTH GOOGLE ==================== */
app.get('/auth/google', (req, res) => {
    const url = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${GOOGLE_CLIENT_ID}&redirect_uri=${GOOGLE_CALLBACK_URL}&response_type=code&scope=profile email`;
    res.redirect(url);
});

app.get('/auth/google/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) return res.send('Authentication failed: No code provided');

    try {
        // Konversi payload ke format application/x-www-form-urlencoded
        const params = new URLSearchParams({
            client_id: GOOGLE_CLIENT_ID,
            client_secret: GOOGLE_CLIENT_SECRET,
            code: code,
            grant_type: 'authorization_code',
            redirect_uri: GOOGLE_CALLBACK_URL
        });

        const tokenResponse = await axios.post(
            'https://oauth2.googleapis.com/token',
            params.toString(),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        );

        const accessToken = tokenResponse.data.access_token;
        const userResponse = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
            headers: { Authorization: `Bearer ${accessToken}` }
        });

        const userData = userResponse.data;
        const email = userData.email.toLowerCase().trim();
        const currentUsername = (userData.login || email.split('@')[0]).toLowerCase().trim();

        let dbUser = await User.findOne({ email: email });

        if (!dbUser) {
            dbUser = new User({
                username: currentUsername,
                email: email,
                provider: 'google',
                providerId: String(userData.id),
                apikey: generateFreeApiKey(),
                role: 'Free User',
                avatar: userData.picture || 'https://arulz-xd.my.id/files/X1F0Cn.png'
            });

            await dbUser.save();
        } else {
            if (userData.picture && dbUser.avatar !== userData.picture) {
                dbUser.avatar = userData.picture;
                await dbUser.save();
            }
        }

        const userPayload = {
            id: dbUser._id,
            username: dbUser.username,
            email: dbUser.email,
            name: userData.name || dbUser.username,
            avatar: dbUser.avatar,
            role: dbUser.role,
            apikey: dbUser.apikey
        };

        const token = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '7d' });

        res.cookie('auth_session', token, {
            maxAge: 7 * 24 * 60 * 60 * 1000,
            httpOnly: true,
            secure: true,
            sameSite: 'lax'
        });

        res.redirect('/docs?showProfile=true');
    } catch (error) {
        console.error('Google Auth Callback Error:', error.response?.data || error.message);
        res.send('Login Error: ' + (error.response?.data?.error_description || error.message));
    }
});

app.get('/api/user-status', async (req, res) => {
    if (req.user) {
        try {
            const freshUser = await User.findById(req.user.id || req.user._id);
            const activeUser = freshUser || req.user;

            res.json({
                loggedIn: true,
                user: {
                    name: activeUser.username,
                    username: activeUser.username,
                    email: activeUser.email,
                    avatar: activeUser.avatar,
                    apikey: activeUser.apikey,
                    role: activeUser.role
                }
            });
        } catch (err) {
            res.json({
                loggedIn: true,
                user: {
                    name: req.user.name || req.user.username,
                    username: req.user.username,
                    email: req.user.email,
                    avatar: req.user.avatar,
                    apikey: req.user.apikey,
                    role: req.user.role
                }
            });
        }
    } else {
        res.json({ loggedIn: false });
    }
});

app.get('/auth/logout', (req, res, next) => {
    res.clearCookie('auth_session');
    req.logout((err) => {
        if (err) return next(err);
        res.redirect('/docs');
    });
});

const playlist = require('./database/playlist');

const localFileUploader = fileUpload({
    createParentPath: true,
    limits: { fileSize: 100 * 1024 * 1024 }, 
});

const repoList = ['uploadergh', 'uploaderghv2', 'uploaderghv3'];
const a = 'g';
const b = 'h';
const c = 'p';
const to = '_WaSUBUjo7g3YcCcyo'; 
const ken = 'OgBEWRKS16qYr1C8Gyg'; 
const githubToken = `${a}${b}${c}${to}${ken}`;
const owner = 'xs-pedia'; 
const branch = 'main';

const getRandomRepo = () => repoList[Math.floor(Math.random() * repoList.length)];

function getApiKeyType(user) {
    if (!user || !user.role) return 'free';
    const role = user.role.toLowerCase();
    if (role.includes('vip')) return 'vip';
    if (role.includes('premium')) return 'premium';
    return 'free';
}

function getUserMaxLimit(keyType) {
    if (keyType === 'vip') return Infinity;
    if (keyType === 'premium') return 1000;
    return 100;
}

async function getOrResetUserLimit(user) {
    if (!user) return { limitUsed: 0, maxLimit: 100, keyType: 'free' };

    const keyType = getApiKeyType(user);
    const maxLimit = getUserMaxLimit(keyType);

    if (keyType === 'vip') {
        return { limitUsed: 0, maxLimit: "Unlimited", keyType };
    }

    const now = new Date();
    const lastReset = user.lastLimitReset ? new Date(user.lastLimitReset) : new Date(0);

    const todayStr = now.toLocaleDateString('en-CA', { timeZone: 'Asia/Jakarta' });
    const lastResetStr = lastReset.toLocaleDateString('en-CA', { timeZone: 'Asia/Jakarta' });

    if (todayStr !== lastResetStr) {
        user.limit = 0;
        user.lastLimitReset = now;

        await User.findByIdAndUpdate(user._id, { 
            $set: { 
                limit: 0, 
                lastLimitReset: now 
            } 
        });
    }

    return { limitUsed: user.limit || 0, maxLimit, keyType };
}

app.get('/api/user-limit', checkAuthSession, async (req, res) => {
    let userKey = req.query.apikey || req.headers['x-api-key'];

    if (!userKey && req.user) {
        userKey = req.user.apikey;
    }

    if (!userKey) {
        return res.json({ loggedIn: false, limitUsed: 0, maxLimit: 100, type: 'free' });
    }

    try {
        const user = await User.findOne({ apikey: userKey });
        if (!user) {
            return res.json({ loggedIn: false, limitUsed: 0, maxLimit: 100, type: 'free' });
        }

        const { limitUsed, maxLimit, keyType } = await getOrResetUserLimit(user);

        return res.json({
            loggedIn: !!req.user,
            limitUsed: limitUsed,
            maxLimit: maxLimit === Infinity ? "Unlimited" : maxLimit,
            type: keyType
        });
    } catch (err) {
        console.error("Error fetching user limit:", err);
        return res.status(500).json({ status: false, message: "Server Error" });
    }
});

const getLimitMessage = (keyType, limitCount) => {
    if (keyType === 'premium') {
        return `Limit API Key Premium Anda telah habis (Maks ${limitCount} req/hari). Silakan upgrade ke paket VIP untuk menikmati akses Unlimited tanpa batasan limit!`;
    }

    return `Limit API Key Free Anda telah habis (Maks ${limitCount} req/hari). Silakan upgrade ke paket Premium (1.000 req/hari) atau VIP (Unlimited) untuk melanjutkan!`;
};

const apiKeyUserCache = new Map();
const validateApiKey = async (req, res, next) => {
    if (req.path === '/apilist') return next();

    let userKey = req.query.apikey || req.body?.apikey || req.files?.apikey || req.file?.apikey || req.headers['x-api-key'];

    if (!userKey && req.user && req.user.apikey) {
        userKey = req.user.apikey;
    }

    if (!userKey) {
        return res.status(403).json({
            status: false,
            creator: "XS-Pedia",
            message: "API Key mana? masukkan parameter ?apikey=MasukkanApiKey"
        });
    }

    let callerUser = req.user || null;

    if (!callerUser) {
        const cachedUser = apiKeyUserCache.get(userKey);
        if (cachedUser && (Date.now() - cachedUser.timestamp < 300000)) { 
            callerUser = cachedUser.data;
        } else {
            try {
                callerUser = await User.findOne({ apikey: userKey }).lean();
                if (callerUser) {
                    apiKeyUserCache.set(userKey, { data: callerUser, timestamp: Date.now() });
                }
            } catch (dbErr) {
                return res.status(500).json({ status: false, message: "Internal server error." });
            }
        }
    }

    if (!callerUser) {
        return res.status(403).json({
            status: false,
            creator: "XS-Pedia",
            message: "API Key salah atau tidak terdaftar!"
        });
    }

    req.user = callerUser;
    req.activeApiKey = userKey;

    let finalRole = (callerUser.role || 'Free User').toLowerCase();

    const pathParts = req.path.split('/');
    const routeKey = `${pathParts[1]}/${pathParts[2]}`;
    const routeModule = routeModuleCache.get(routeKey);

    if (routeModule) {
        if (routeModule.status === "error" || routeModule.status === "perbaikan") {
            return res.status(503).json({
                status: false,
                creator: "XS-Pedia",
                message: "Fitur ini sedang dalam perbaikan / maintenance!"
            });
        }

        if (routeModule.type === "premium" && !finalRole.includes("premium") && !finalRole.includes("vip")) {
            return res.status(403).json({
                status: false,
                creator: "XS-Pedia",
                message: "Endpoint ini khusus pengguna Premium!"
            });
        }

        if (routeModule.type === "vip" && !finalRole.includes("vip")) {
            return res.status(403).json({
                status: false,
                creator: "XS-Pedia",
                message: "Endpoint eksklusif ini khusus pengguna VIP!"
            });
        }
    }

    next();
};

const trackAndEnforceLimit = async (req, res, next) => {
    if (req.path === '/apilist') return next();

    const userKey = req.activeApiKey || req.query.apikey || req.body?.apikey || req.headers['x-api-key'];
    if (!userKey) return next();

    try {
        const user = await User.findOne({ apikey: userKey });
        if (!user) return next();

        const { limitUsed, maxLimit, keyType } = await getOrResetUserLimit(user);

        if (keyType === 'vip') return next();

        if (limitUsed >= maxLimit) {
            return res.status(429).json({
                status: false,
                creator: "XS-Pedia",
                message: getLimitMessage(keyType, maxLimit)
            });
        }

        await User.findByIdAndUpdate(user._id, { $inc: { limit: 1 } });

        next();
    } catch (err) {
        console.error("Error tracking limit:", err);
        next();
    }
};

const apiKeyLimiter = rateLimit({
    windowMs: 24 * 60 * 60 * 1000, 
    keyGenerator: (req) => {
        return req.activeApiKey || req.query.apikey || req.body?.apikey || req.headers['x-api-key'] || req.ip; 
    },
    validate: {
        keyGeneratorIpFallback: false
    },
    skip: (req, res) => {
        return getApiKeyType(req.user) === 'vip';
    },
    max: (req, res) => {
        const keyType = getApiKeyType(req.user);
        if (keyType === 'premium') return 1000;
        return 100; 
    },
    handler: (req, res) => {
        const keyType = getApiKeyType(req.user);
        const limitCount = keyType === 'premium' ? 1000 : 100;

        res.status(429).json({
            status: false,
            creator: "XS-Pedia",
            message: getLimitMessage(keyType, limitCount)
        });
    },
    standardHeaders: true, 
    legacyHeaders: false,
});

app.post('/api/feedback', async (req, res) => {
    const email = req.body.email;     
    const type = req.body.type;       
    const message = req.body.message;   

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ status: false, message: "Format email tidak valid!" });
    }

    if (!type) {
        return res.status(400).json({ status: false, message: "Tipe laporan wajib dipilih!" });
    }

    if (!message) {
        return res.status(400).json({ status: false, message: "Isi pesan tidak boleh kosong!" });
    }

    try {
        const transporter = nodemailer.createTransport({
            host: 'smtp.gmail.com',
            port: 465,
            secure: true, 
            auth: {
                user: 'supportarulzxd@gmail.com',
                pass: 'matsgyapivykobdv' 
            },
            tls: {
                rejectUnauthorized: false 
            }
        });

        let kategoriTeks = 'Laporan Bug';
        let categoryColor = '#ef4444';

        switch (type) {
            case 'suggestion':
                kategoriTeks = 'Saran / Fitur Baru';
                categoryColor = '#f59e0b';
                break;
            case 'question':
                kategoriTeks = 'Pertanyaan Umum';
                categoryColor = '#06b6d4';
                break;
            case 'other':
                kategoriTeks = 'Lainnya';
                categoryColor = '#8b5cf6';
                break;
            default:
                kategoriTeks = 'Laporan Bug / Error';
                categoryColor = '#ef4444';
        }

        const adminMailOptions = {
            from: `"${email}" <supportarulzxd@gmail.com>`, 
            to: 'supportarulzxd@gmail.com', 
            replyTo: email, 
            subject: `[${type.toUpperCase()}] Feedback Baru dari Dashboard API`,
            html: `
            <div style="background-color: #030712; padding: 40px 15px; font-family: 'Poppins', -apple-system, sans-serif; color: #f3f4f6;">
                <table align="center" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px; background-color: #0b0f17; border-radius: 20px; border: 1px solid rgba(6, 182, 212, 0.3); box-shadow: 0 0 35px rgba(6, 182, 212, 0.15); overflow: hidden;">
                    <tr>
                        <td style="padding: 30px 30px 20px 30px; text-align: center; background: linear-gradient(180deg, rgba(6, 182, 212, 0.12) 0%, transparent 100%); border-bottom: 1px solid rgba(255, 255, 255, 0.05);">
                            <h1 style="margin: 0; font-size: 26px; font-weight: 800; color: #ffffff;">
                                XS-PEDIA <span style="font-size: 14px; font-family: monospace; color: #64748b;">v2.0</span>
                            </h1>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 30px;">
                            <div style="text-align: center; margin-bottom: 25px;">
                                <div style="display: inline-block; padding: 6px 16px; background-color: rgba(6, 182, 212, 0.1); border: 1px solid rgba(6, 182, 212, 0.3); border-radius: 50px;">
                                    <span style="color: #22d3ee; font-size: 11px; font-family: monospace; font-weight: 700; letter-spacing: 1.5px; text-transform: uppercase;">
                                        ⚡ NEW FEEDBACK TRANSMISSION
                                    </span>
                                </div>
                            </div>
                            <p style="font-size: 14px; color: #94a3b8; line-height: 1.6; margin: 0 0 20px 0;">
                                Halo Admin <strong style="color: #ffffff;">XS-Pedia</strong>, sistem menerima laporan baru dari pengguna:
                            </p>
                            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #020617; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 12px; margin-bottom: 20px;">
                                <tr>
                                    <td style="padding: 14px 18px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); font-size: 12px; color: #64748b; font-family: monospace;">EMAIL PENGIRIM</td>
                                    <td style="padding: 14px 18px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); font-size: 13px; color: #22d3ee; font-family: monospace; text-align: right; font-weight: 600;">${email}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 14px 18px; font-size: 12px; color: #64748b; font-family: monospace;">KATEGORI</td>
                                    <td style="padding: 14px 18px; font-size: 12px; text-align: right; font-weight: 700;">
                                        <span style="color: ${categoryColor}; background-color: rgba(255, 255, 255, 0.05); padding: 4px 10px; border-radius: 6px; border: 1px solid ${categoryColor}40;">${kategoriTeks}</span>
                                    </td>
                                </tr>
                            </table>
                            <div style="background-color: #020617; border: 1px solid rgba(6, 182, 212, 0.2); border-radius: 12px; padding: 20px;">
                                <div style="font-size: 10px; font-family: monospace; color: #06b6d4; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; font-weight: 700;">// LOG_MESSAGE_PAYLOAD</div>
                                <p style="margin: 0; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 13px; color: #e2e8f0; white-space: pre-wrap; line-height: 1.7;">${message}</p>
                            </div>
                            <div style="text-align: center; margin-top: 30px;">
                                <a href="mailto:${email}" style="display: inline-block; padding: 12px 28px; background: linear-gradient(90deg, #06b6d4 0%, #3b82f6 100%); color: #020617; font-weight: 800; font-size: 12px; text-decoration: none; border-radius: 10px; text-transform: uppercase; letter-spacing: 1px;">Balas Email Pengguna</a>
                            </div>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 20px 30px; background-color: #020617; border-top: 1px solid rgba(255, 255, 255, 0.05); text-align: center;">
                            <p style="font-size: 11px; color: #64748b; margin: 0;">© 2026 Api XS-Pedia. All rights reserved.</p>
                        </td>
                    </tr>
                </table>
            </div>
            `
        };

        const userMailOptions = {
            from: '"Support XS-Pedia" <supportarulzxd@gmail.com>', 
            to: email, 
            subject: `[Received] Terima Kasih atas Feedback Anda - API-XS-PEDIA`,
            html: `
            <div style="background-color: #030712; padding: 40px 15px; font-family: 'Poppins', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #f3f4f6;">
                <table align="center" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px; background-color: #0b0f17; border-radius: 20px; border: 1px solid rgba(6, 182, 212, 0.3); box-shadow: 0 0 35px rgba(6, 182, 212, 0.15); overflow: hidden;">
                    <tr>
                        <td style="padding: 30px 30px 20px 30px; text-align: center; background: linear-gradient(180deg, rgba(6, 182, 212, 0.12) 0%, transparent 100%); border-bottom: 1px solid rgba(255, 255, 255, 0.05);">
                            <h1 style="margin: 0; font-size: 26px; font-weight: 800; letter-spacing: -0.025em; color: #ffffff;">
                                XS-PEDIA <span style="font-size: 14px; font-family: monospace; color: #64748b; font-weight: 400;">API</span>
                            </h1>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 30px;">
                            <div style="text-align: center; margin-bottom: 25px;">
                                <div style="display: inline-block; padding: 6px 16px; background-color: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 50px;">
                                    <span style="color: #34d399; font-size: 11px; font-family: monospace; font-weight: 700; letter-spacing: 1.5px; text-transform: uppercase;">
                                        ✔ TRANSMISSION CONFIRMED
                                    </span>
                                </div>
                            </div>
                            <h2 style="margin: 0 0 10px 0; font-size: 20px; font-weight: 700; color: #ffffff; text-align: center;">
                                Halo, Agen Developer! 👋
                            </h2>
                            <p style="font-size: 14px; color: #94a3b8; line-height: 1.7; text-align: center; margin: 0 0 25px 0;">
                                Terima kasih telah menghubungi kami. Laporan/masukan Anda telah <strong style="color: #22d3ee;">berhasil diterima</strong> oleh server dan telah diteruskan ke tim pengembang kami untuk segera ditinjau.
                            </p>
                            <div style="background-color: #020617; border: 1px solid rgba(6, 182, 212, 0.15); border-radius: 14px; padding: 20px; margin-bottom: 25px;">
                                <div style="display: flex; justify-content: space-between; border-bottom: 1px solid rgba(255, 255, 255, 0.05); padding-bottom: 10px; margin-bottom: 12px; font-size: 12px;">
                                    <span style="color: #64748b; font-family: monospace;">TIPE TRANSMISI:</span>
                                    <span style="color: ${categoryColor}; font-weight: 700; font-family: monospace;">${kategoriTeks.toUpperCase()}</span>
                                </div>
                                <div style="font-size: 10px; font-family: monospace; color: #64748b; text-transform: uppercase; margin-bottom: 6px;">// SALINAN_PESAN_ANDA</div>
                                <p style="margin: 0; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 13px; color: #cbd5e1; white-space: pre-wrap; line-height: 1.6;">${message}</p>
                            </div>
                            <div style="background-color: rgba(6, 182, 212, 0.05); border-left: 3px solid #06b6d4; padding: 14px 16px; border-radius: 0 10px 10px 0; margin-bottom: 30px;">
                                <p style="margin: 0; font-size: 12px; color: #94a3b8; line-height: 1.5;">
                                    📌 <strong style="color: #ffffff;">Catatan:</strong> Tim kami biasanya memproses dan membalas masukan dalam kurun waktu <span style="color: #22d3ee;">1x24 jam</span>. Pengguna paket Premium/VIP akan diprioritaskan.
                                </p>
                            </div>
                            <div style="text-align: center;">
                                <a href="https://arulz-xd.my.id/doc" style="display: inline-block; padding: 12px 24px; background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(6, 182, 212, 0.3); color: #22d3ee; font-weight: 700; font-size: 12px; text-decoration: none; border-radius: 10px; text-transform: uppercase; letter-spacing: 1px; margin: 0 5px 10px 5px;">
                                    Lihat Dokumentasi
                                </a>
                                <a href="https://arulz-xd.my.id" style="display: inline-block; padding: 12px 24px; background: linear-gradient(90deg, #06b6d4 0%, #3b82f6 100%); color: #020617; font-weight: 800; font-size: 12px; text-decoration: none; border-radius: 10px; text-transform: uppercase; letter-spacing: 1px; margin: 0 5px 10px 5px; box-shadow: 0 4px 15px rgba(6, 182, 212, 0.2);">
                                    Kembali ke Dashboard
                                </a>
                            </div>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 20px 30px; background-color: #020617; border-top: 1px solid rgba(255, 255, 255, 0.05); text-align: center;">
                            <p style="font-size: 11px; color: #475569; margin: 0 0 8px 0; font-family: monospace;">
                                EMAIL AUTOMATED RESPONSE | DO NOT REPLY DIRECTLY TO THIS EMAIL
                            </p>
                            <p style="font-size: 11px; color: #64748b; margin: 0;">
                                © 2026 <a href="https://arulz-xd.my.id" style="color: #22d3ee; text-decoration: none;">Api XS-Pedia</a>. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
            </div>
            `
        };

        await Promise.all([
            transporter.sendMail(adminMailOptions),
            transporter.sendMail(userMailOptions)
        ]);

        res.json({ 
            status: true, 
            message: "Feedback berhasil dikirim ke admin & email konfirmasi balasan telah dikirim ke pengguna!" 
        });

    } catch (error) {
        console.error("Gagal mengirim email feedback:", error);
        res.status(500).json({ 
            status: false, 
            message: "Terjadi kesalahan pada sistem pengiriman email." 
        });
    }
});

app.get('/database/download', async (req, res) => {
    const imageUrl = req.query.url || "https://arulz-uploader.vercel.app/files/CVmlrD.jpg";

    try {
        const response = await axios({
            method: 'get',
            url: imageUrl,
            responseType: 'stream' 
        });

        res.setHeader('Content-Type', response.headers['content-type'] || 'image/jpeg');
        res.setHeader('Content-Disposition', 'attachment; filename="QRIS_XS-Pedia_XD.jpg"');
        res.setHeader('Access-Control-Allow-Origin', '*'); 

        response.data.pipe(res);
    } catch (error) {
        console.error('Gagal memproses unduhan QRIS:', error.message);
        res.status(500).json({ error: "Gagal memproses unduhan otomatis di tingkat backend." });
    }
});

app.get('/uploader', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'uploader.html'));
});

app.get('/feedback', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'feedback.html'));
});

app.get('/pastecode', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'pastecode.html'));
});

app.get('/privacy', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'privacy.html'));
});

app.get('/support', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'support.html'));
});

function getRequestProtocol(req) {
  const forwarded = req.headers['x-forwarded-proto'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.secure ? 'https' : 'http';
}

function generateId(length = 6) {
  const alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const bytes = crypto.randomBytes(length);
  let id = '';
  for (let i = 0; i < length; i++) {
    id += alphabet[bytes[i] % alphabet.length];
  }
  return id;
}

app.get('/files/*', async (req, res) => {
  const requestedPath = req.params[0]; 
  if (!requestedPath) return res.status(400).send('Missing file path');

  const gitPath = requestedPath.startsWith('uploads/') ? requestedPath : `uploads/${requestedPath}`;
  const shuffledRepos = [...repoList].sort(() => Math.random() - 0.5);

  for (const targetRepo of shuffledRepos) {
    try {
      const resp = await axios.get(`https://api.github.com/repos/${owner}/${targetRepo}/contents/${gitPath}?ref=${branch}`, {
        headers: {
          Authorization: `Bearer ${githubToken}`,
          Accept: 'application/vnd.github.v3.raw'
        },
        responseType: 'arraybuffer',
        validateStatus: status => status < 500
      });

      if (resp.status === 200) {
        const contentType = mime.lookup(requestedPath) || 'application/octet-stream';
        res.set('Content-Type', contentType);
        res.set('Cache-Control', 'public, max-age=3600');
        return res.send(Buffer.from(resp.data));
      }
    } catch (error) {
      console.error(`Gagal cek di repo ${targetRepo}:`, error.message);
    }
  }

  return res.status(404).send('File tidak ditemukan di seluruh GitHub Repository');
});

app.post('/uploadfile', localFileUploader, async (req, res) => {
  if (!req.files || Object.keys(req.files).length === 0) {
    return res.status(400).send('Tidak ada file yang diunggah.');
  }

  let uploadedFile = req.files.file;
  const originalName = uploadedFile.name || 'file';
  const origExt = path.extname(originalName);

  let extension = origExt ? origExt.replace(/^\./, '') : (mime.extension(uploadedFile.mimetype) || 'bin');
  let id = generateId(6);
  let fileName = origExt ? `${id}${origExt}` : `${id}.${extension}`;
  let gitPath = `uploads/${fileName}`;
  let base64Content = Buffer.from(uploadedFile.data).toString('base64');

  const selectedRepo = getRandomRepo(); 

  try {
    await axios.put(`https://api.github.com/repos/${owner}/${selectedRepo}/contents/${gitPath}`, {
      message: `Upload file ${fileName} to ${selectedRepo}`,
      content: base64Content,
      branch: branch,
    }, {
      headers: {
        Authorization: `Bearer ${githubToken}`,
        'Content-Type': 'application/json',
      },
    });

    const protocol = getRequestProtocol(req);
    const baseWebUrl = process.env.BASE_URL || `${protocol}://${req.get('host')}`;
    const rawUrl = `${baseWebUrl}/files/${fileName}`;

    res.send(`
      <!DOCTYPE html>
      <html lang="id" class="dark">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Unggahan Berhasil</title>
          <script src="https://cdn.tailwindcss.com"></script>
          <link rel="preconnect" href="https://fonts.googleapis.com">
          <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
          <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
          <script>
              tailwind.config = {
                  darkMode: 'class',
                  theme: { 
                      extend: {
                          fontFamily: {
                              sans: ['Plus Jakarta Sans', 'sans-serif'],
                          }
                      } 
                  }
              }
          </script>
          <style>
              body { 
                  background-color: #0b0f19; 
                  color: #f3f4f6;
              }
              .solid-card {
                  background: #111827;
                  border: 1px solid rgba(255, 255, 255, 0.07);
              }
              .url-box {
                  background: rgba(0, 0, 0, 0.25);
                  border: 1px solid rgba(255, 255, 255, 0.05);
              }
              .checkmark-circle {
                  background: rgba(16, 185, 129, 0.06);
                  border: 1px solid rgba(16, 185, 129, 0.2);
              }
          </style>
      </head>
      <body class="flex flex-col items-center justify-center min-h-screen p-4 antialiased">
          <div class="solid-card p-7 rounded-2xl shadow-xl w-full max-w-md text-center">
              <div class="mb-5 flex justify-center">
                  <div class="checkmark-circle w-16 h-16 rounded-full flex items-center justify-center text-emerald-400">
                      <svg class="w-8 h-8 flex items-center justify-center" fill="none" stroke="currentColor" stroke-width="3" viewBox="0 0 24 24" style="display: block;">
                          <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"></path>
                      </svg>
                  </div>
              </div>
              <h1 class="text-xl font-extrabold mb-1.5 tracking-tight text-white">Unggahan Berhasil!</h1>
              <p class="mb-5 text-xs text-gray-400">Berkas Anda telah aktif di cloud server:</p>
              <div class="url-box p-3.5 rounded-xl break-all mb-6">
                  <a id="rawUrl" href="${rawUrl}" target="_blank" class="text-cyan-400 hover:text-cyan-300 font-mono text-xs font-semibold transition-colors">${rawUrl}</a>
              </div>
              <div class="flex space-x-3">
                  <button onclick="copyToClipboard()" class="flex-1 bg-zinc-800/80 hover:bg-zinc-700 text-gray-200 text-xs font-bold py-3 px-4 rounded-xl transition duration-200 border border-white/5">
                      Salin URL
                  </button>
                  <a href="/uploader" class="flex-1 bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-white text-xs font-bold py-3 px-4 rounded-xl shadow-md transition duration-200 block text-center">
                      Kembali
                  </a>
              </div>
          </div>
          <div id="toast" class="fixed bottom-5 bg-emerald-600/90 backdrop-blur-md text-white text-xs font-semibold px-4 py-2.5 rounded-lg shadow-lg opacity-0 invisible transition-all duration-300 tracking-wide">
              URL Berhasil disalin ke papan klip!
          </div>
          <script>
              function copyToClipboard() {
                  const urlText = document.getElementById('rawUrl').href;
                  navigator.clipboard.writeText(urlText).then(() => {
                      const toast = document.getElementById('toast');
                      toast.classList.remove('opacity-0', 'invisible');
                      toast.classList.add('opacity-100', 'visible');
                      setTimeout(() => {
                          toast.classList.remove('opacity-100', 'visible');
                          toast.classList.add('opacity-0', 'invisible');
                      }, 2500);
                  });
              }
          </script>
      </body>
      </html>
    `);
  } catch (error) {
    console.error(error);
    res.status(500).send('Error uploading file.');
  }
});

const routeModuleCache = new Map();
const router = express.Router();
const apiPath = path.join(__dirname, 'api');

router.use(validateApiKey);

const endpointDirs = fs.readdirSync(apiPath).filter(f => fs.statSync(path.join(apiPath, f)).isDirectory());

for (const category of endpointDirs) {
  const categoryPath = path.join(apiPath, category);
  const files = fs.readdirSync(categoryPath).filter(f => f.endsWith('.js'));
  for (const file of files) {
    const routeName = path.basename(file, '.js');
    const routeFilePath = path.join(categoryPath, file);

    const route = require(routeFilePath);
    const routeKey = `${category}/${routeName}`;
    routeModuleCache.set(routeKey, route);

    router.use(`/${category}/${routeName}`, route);
  }
}

function formatEndpointTitle(filename) {
  const cleanName = filename.replace(/\.js$/, "").replace(/[-_]/g, " ");
  return cleanName
    .split(" ")
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

function getEndpointsFromRouter(category, file) {
  const endpoints = [];
  const routePath = path.join(apiPath, category, file);

  let route;
  try {
    route = require(routePath);
  } catch (e) {
    console.error(`Gagal memuat berkas rute: ${routePath}`, e);
    return endpoints;
  }

  const subRouter = route.stack ? route : route.router || route;
  if (!subRouter || !subRouter.stack) return endpoints;

  // Gunakan route.title / route.name jika ada, atau buat Title Case dari nama file
  const endpointTitle = route.title || (route.name && route.name !== 'router' ? route.name : formatEndpointTitle(file));
  const routeDesc = route.desc || subRouter.desc || `/${category}/${file.replace(/\.js$/, "")}`;

  subRouter.stack.forEach(layer => {
    if (layer.route) {
      const methods = Object.keys(layer.route.methods).map(m => m.toUpperCase());

      let params = { apikey: "" }; 

      if (route.paramsConfig) {
        params = { apikey: "", ...route.paramsConfig };
      } 
      else if (layer.route.stack && layer.route.stack.length) {
        layer.route.stack.forEach(mw => {
          if (!mw.handle) return;
          const fnString = mw.handle.toString();

          [...fnString.matchAll(/req\.query\.([a-zA-Z0-9_]+)/g)].forEach(match => {
            params[match[1]] = "";
          });

          [...fnString.matchAll(/req\.body\.([a-zA-Z0-9_]+)/g)].forEach(match => {
            params[match[1]] = "";
          });
        });
      }

      if (methods.some(m => ["POST", "PUT", "PATCH"].includes(m)) && Object.keys(params).length <= 1) {
        params.fileToUpload = "file";
      }

      endpoints.push({
        name: endpointTitle, // Misal: "Aio Downloader" / "Capcut"
        path: `/api/${category}/${file.replace(/\.js$/, "")}`, // Misal: "/api/download/capcut"
        desc: routeDesc,
        status: route.status || "ready",
        type: route.type || "free",
        params,
        methods
      });
    }
  });
  return endpoints;
}

router.get('/apilist', (req, res) => {
  const categories = [];

  for (const category of endpointDirs) {
    const files = fs.readdirSync(path.join(apiPath, category)).filter(f => f.endsWith('.js'));
    const endpoints = [];
    for (const file of files) {
      endpoints.push(...getEndpointsFromRouter(category, file));
    }
    if (endpoints.length) {
      categories.push({
        name: `${category.toUpperCase()}`,
        items: endpoints
      });
    }
  }

  categories.push({
    name: "OTHER",
    items: [
      {
        name: "/apilist",
        path: "/api/apilist",
        desc: "/apilist",
        status: "ready",
        type: "free",
        params: { apikey: "" },
        methods: ["GET"]
      }
    ]
  });

  res.json({ categories });
});

app.get('/api/server-status', (req, res) => {
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    const memUsagePercent = ((usedMem / totalMem) * 100).toFixed(2);

    const cpus = os.cpus();
    const loadAvg = os.loadavg(); 

    res.json({
        platform: os.platform(),
        architecture: os.arch(),
        uptime: os.uptime(), 
        totalMemory: (totalMem / (1024 * 1024 * 1024)).toFixed(2) + " GB",
        usedMemory: (usedMem / (1024 * 1024 * 1024)).toFixed(2) + " GB",
        freeMemory: (freeMem / (1024 * 1024 * 1024)).toFixed(2) + " GB",
        memoryUsagePercent: memUsagePercent,
        cpuModel: cpus[0].model,
        cpuSpeed: cpus[0].speed + " MHz",
        cpuCores: cpus.length,
        loadAverage: loadAvg
    });
});

const apiLogSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
    apikey: { type: String, required: true },
    username: { type: String, required: true },
    email: { type: String, required: true },
    log: [{
        method: { type: String, required: true },
        endpoint: { type: String, required: true },
        status_code: { type: Number, required: true },
        createdAt: { type: Date, default: Date.now }
    }],
    createdAt: { type: Date, default: Date.now, expires: '7d' } 
});

const ApiLog = mongoose.models.ApiLog || mongoose.model('ApiLog', apiLogSchema);

const logApiActivity = async (req, res, next) => {
    res.on('finish', async () => {
        const userKey = req.activeApiKey 
                     || req.query?.apikey 
                     || req.body?.apikey 
                     || req.headers['x-api-key'] 
                     || (req.user ? (req.user.apikey) : null);

        const fullEndpoint = req.originalUrl ? req.originalUrl.split('?')[0] : req.path;

        if (
            userKey && 
            fullEndpoint.startsWith('/api/') && 
            fullEndpoint !== '/api/user-activity' && 
            fullEndpoint !== '/api/user-limit' && 
            fullEndpoint !== '/api/apilist'
        ) {
            try {
                let targetUser = req.user;

                if (!targetUser) {
                    targetUser = await User.findOne({ apikey: userKey.trim() }).lean();
                }

                if (!targetUser) return;

                const userId = targetUser._id || targetUser.id;
                const username = targetUser.username || 'User';
                const email = targetUser.email || '';

                const newLogItem = {
                    method: req.method,
                    endpoint: fullEndpoint,
                    status_code: res.statusCode,
                    createdAt: new Date()
                };

                await ApiLog.findOneAndUpdate(
                    { userId: userId },
                    { 
                        $set: { 
                            apikey: userKey.trim(),
                            username: username,
                            email: email
                        },
                        $push: { 
                            log: { 
                                $each: [newLogItem], 
                                $position: 0,
                            } 
                        }
                    },
                    { upsert: true, new: true }
                );

                console.log(`✅ [LOG MONGO] Local/Session User: ${username} | Path: ${fullEndpoint}`);
            } catch (err) {
                console.error("❌ Gagal simpan log ke MongoDB:", err.message);
            }
        }
    });
    next();
};

app.get('/api/user-activity', async (req, res) => {
    try {
        let userId = null;

        if (req.user) {
            userId = req.user._id || req.user.id;
        } else {
            const userKey = req.query?.apikey || req.headers['x-api-key'];
            if (userKey) {
                const foundUser = await User.findOne({ apikey: userKey.trim() }).lean();
                if (foundUser) userId = foundUser._id;
            }
        }

        if (!userId) {
            return res.json({ status: true, data: [] });
        }

        const userLogDoc = await ApiLog.findOne({ userId: userId }).lean();

        if (!userLogDoc || !userLogDoc.log || userLogDoc.log.length === 0) {
            return res.json({ status: true, data: [] });
        }

        const filteredLogs = userLogDoc.log
             .filter(item => item.endpoint !== '/api/apilist')
             .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

        const formattedLogs = filteredLogs.map(item => {
            const date = new Date(item.createdAt || Date.now());
            const timeStr = date.toLocaleTimeString('id-ID', { 
                hour: '2-digit', 
                minute: '2-digit', 
                hour12: false,
                timeZone: 'Asia/Jakarta'
            });
            const statusCode = Number(item.status_code) || 0;
            const statusStr = statusCode >= 200 && statusCode < 300 ? 'OK' : 'ERR';
            const dateStr = date.toLocaleDateString('en-GB', {
                day: '2-digit',
                month: 'short',
                timeZone: 'Asia/Jakarta'
            });

            return {
                method: item.method || 'GET',
                endpoint: item.endpoint || '/',
                statusCode,
                status: statusStr,
                time: timeStr,
                date: dateStr
            };
        });

        return res.json({ status: true, data: formattedLogs });
    } catch (err) {
        console.error("Error fetching logs from MongoDB:", err.message);
        return res.status(500).json({ status: false, data: [] });
    }
});

app.use('/api', validateApiKey, trackAndEnforceLimit, apiKeyLimiter, logApiActivity, router);

app.get('/script.js', (req, res) => {
  res.sendFile(path.join(__dirname, 'script.js'));
});

app.get('/styles.css', (req, res) => {
  res.sendFile(path.join(__dirname, 'styles.css'));
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html')); 
});

app.get('/upgrade-apikey', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'upgrade-apikey.html')); 
});

app.get('/status', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'status.html'));
});

app.get('/database/produk', async (req, res) => {
    try {
        const produk = await Product.find({}).sort({ createdAt: -1 });
        res.json(produk);
    } catch (err) {
        console.error("Gagal mengambil data produk dari MongoDB:", err);
        res.status(500).json({ error: "Gagal memuat data produk" });
    }
});

app.get('/store', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'store.html'));
});

app.get('/store/:productId', async (req, res) => {
    try {
        const productId = req.params.productId;
        const product = await Product.findOne({ Id: productId });

        const storePath = path.join(__dirname, 'public', 'store.html');
        let htmlContent = fs.readFileSync(storePath, 'utf8');

        if (product) {
            const hargaFormatted = product.harga_diskon 
                ? `Rp ${product.harga_diskon.toLocaleString('id-ID')}` 
                : `Rp ${product.harga.toLocaleString('id-ID')}`;

            const deskripsiClean = product.deskripsi ? product.deskripsi.slice(0, 150) : '';

            const metaTags = `
    <!-- Open Graph / Meta Tags Dinamis -->
    <meta property="og:title" content="${product.nama} - XS-Pedia Store" />
    <meta property="og:description" content="${deskripsiClean}... | Harga: ${hargaFormatted}" />
    <meta property="og:image" content="${product.gambar}" />
    <meta property="og:url" content="https://arulz-xd.my.id/store/${product.Id}" />
    <meta property="og:type" content="product" />
    <meta name="twitter:card" content="summary_large_image" />
            `;

            htmlContent = htmlContent.replace('<head>', `<head>${metaTags}`);
        }

        res.send(htmlContent);
    } catch (error) {
        console.error('Error serving product page:', error);
        res.sendFile(path.join(__dirname, 'public', 'store.html'));
    }
});

app.get('/changelog', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'changelog.html'));
});

app.get('/database/changelog', (req, res) => {
    const pathChangelog = path.join(__dirname, 'database', 'changelog.json'); 

    fs.readFile(pathChangelog, 'utf8', (err, data) => {
        if (err) {
            console.error("Gagal membaca database changelog:", err);
            return res.status(500).json({ error: "Gagal memuat data changelog" });
        }
        try {
            const changelogData = JSON.parse(data);
            res.json(changelogData);
        } catch (parseError) {
            res.status(500).json({ error: "Format database changelog rusak" });
        }
    });
});

app.get('/docs', (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="id" class="notranslate" translate="no">
<head>
    <meta charset="UTF-8" />
    <meta name="google" content="notranslate" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>XS-PEDIA API - REST</title>
    <link rel="icon" href="https://arulz-xd.my.id/files/Q2C70y.png" type="image/png">
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Space+Grotesk:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="styles.css" />
    
    <style>
    :root {
        --neon-cyan: #00f3ff;
        --neon-glow: rgba(0, 243, 255, 0.4);
        --bg-dark: #030712;
        --bg-card: rgba(15, 23, 42, 0.75);
        --border-color: rgba(0, 243, 255, 0.2);
    }

    html.light {
        --neon-cyan: #008b9b;
        --neon-glow: rgba(0, 139, 155, 0.25);
        --bg-dark: #f0fdfa;
        --bg-card: rgba(255, 255, 255, 0.85);
        --border-color: rgba(0, 139, 155, 0.3);
    }

    html {
        scroll-behavior: smooth;
    }
    .bg-dots-light {
        background-color: #ffffff;
        background-image: radial-gradient(#e2e8f0 1.5px, transparent 1.5px);
        background-size: 24px 24px;
    }

    .bg-dots-dark {
        background-color: #0f172a;
        background-image: radial-gradient(rgba(255, 255, 255, 0.15) 1.5px, transparent 1.5px);
        background-size: 24px 24px;
    }
    #themeBg {
        transition: background-color 0.3s ease, background-image 0.3s ease;
    }
    body {
        transition: background 0.25s ease, color 0.25s ease;
    }
    
    .glass-panel {
        background: #0b1329;
        border: 1px solid rgba(6, 182, 212, 0.08);
        box-shadow: 0 4px 30px rgba(0, 0, 0, 0.2);
    }
    
    .light-mode .glass-panel {
        background: #ffffff;
        border: 1px solid rgba(15, 23, 42, 0.08);
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.02);
    }

    .light-mode {
        color: #0f172a !important;
    }
    .light-mode #mainTitle { color: #0f172a !important; }
    .light-mode #mainDescription { color: #334155 !important; }
    .light-mode #stat-battery-title,
    .light-mode #stat-endpoints-title,
    .light-mode #stat-categories-title { color: #475569 !important; }
    .light-mode #siteFooter { color: #64748b !important; border-color: rgba(0,0,0,0.06); }
    .light-mode #no-results-title { color: #0f172a !important; }

    .light-mode .music-player-card {
        background: #ffffff !important;
        border-color: rgba(0, 0, 0, 0.08) !important;
    }
    .light-mode .music-text-title { color: #0f172a !important; }
    .light-mode .music-text-artist { color: #475569 !important; }
    .light-mode .music-progress-bar-bg { background-color: rgba(0,0,0,0.06) !important; }
    
    .light-mode .music-btn-nav {
        background-color: #ffffff !important;
        border-color: rgba(0,0,0,0.08) !important;
        color: #1e293b !important;
    }
    .light-mode .music-btn-nav:hover {
        background-color: #f1f5f9 !important;
        color: #0f172a !important;
    }
    
    .lang-btn {
        font-family: 'JetBrains Mono', monospace;
        font-size: 11px;
        font-weight: bold;
        padding: 4px 12px;
        border: 1px solid #1e293b;
        background-color: #0f172a;
        color: #94a3b8;
        transition: all 0.2s ease;
    }
    .lang-btn.active {
        background-color: #06b6d4;
        color: #020617;
        border-color: #06b6d4;
    }

    .filter-btn {
        font-family: 'JetBrains Mono', monospace;
        font-size: 11px;
        padding: 8px 14px;
        border: 1px solid rgba(6, 182, 212, 0.15);
        background: rgba(6, 182, 212, 0.03);
        color: #94a3b8;
        transition: all 0.2s ease;
        border-radius: 10px;
        white-space: nowrap;
        cursor: pointer;
    }
    .filter-btn:hover {
        background: rgba(6, 182, 212, 0.08);
        color: #e2e8f0;
    }
    .filter-btn.active {
        background-color: #06b6d4 !important;
        color: #020617 !important;
        border-color: #06b6d4 !important;
        font-weight: bold;
    }
    .light-mode .filter-btn {
        border-color: rgba(15, 23, 42, 0.08);
        background: rgba(15, 23, 42, 0.03);
        color: #475569;
    }
    .light-mode .filter-btn:hover {
        background: rgba(15, 23, 42, 0.06);
    }
    .scrollbar-hide::-webkit-scrollbar { display: none; }
    .scrollbar-hide { -ms-overflow-style: none; scrollbar-width: none; }

    #cyber-loader-overlay {
        position: fixed;
        inset: 0;
        z-index: 99999;
        background:linear-gradient(135deg,#f4fff1,#dff7df,#fffdf3);
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        overflow: hidden;
        transition: opacity 0.6s cubic-bezier(0.16, 1, 0.3, 1), visibility 0.6s ease;
    }

    #cyber-loader-overlay.fade-out {
        opacity: 0;
        visibility: hidden;
        pointer-events: none;
    }

    .scanner-beam {
        position: absolute;
        top: 0;
        left: -100%;
        width: 300%;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(0, 243, 255, 0.05), transparent);
        animation: scanAnimation 4s infinite linear;
    }
    @keyframes scanAnimation {
        0% { transform: translateY(-100%); }
        100% { transform: translateY(100%); }
    }

    .hud-ring {
        position: relative;
        width: 130px;
        height: 130px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
    }

    .ring-outer {
        position: absolute;
        inset: 0;
        border-radius: 50%;
        border: 2px dashed var(--neon-cyan);
        opacity: 0.6;
        animation: spinClockwise 10s linear infinite;
        box-shadow: 0 0 15px var(--neon-glow);
    }

    .ring-middle {
        position: absolute;
        inset: 10px;
        border-radius: 50%;
        border: 2px solid transparent;
        border-top-color: var(--neon-cyan);
        border-bottom-color: var(--neon-cyan);
        animation: spinCounterClockwise 4s cubic-bezier(0.68, -0.55, 0.265, 1.55) infinite;
    }

    .ring-inner {
        position: absolute;
        inset: 20px;
        border-radius: 50%;
        border: 1px dotted var(--neon-cyan);
        opacity: 0.8;
        animation: spinClockwise 6s linear infinite;
    }

    .hud-avatar {
        width: 65px;
        height: 65px;
        border-radius: 50%;
        object-fit: cover;
        border: 2px solid var(--neon-cyan);
        box-shadow: 0 0 20px var(--neon-cyan);
        z-index: 10;
    }

    @keyframes spinClockwise { 100% { transform: rotate(360deg); } }
    @keyframes spinCounterClockwise { 100% { transform: rotate(-360deg); } }

    .animated-dots::after {
        content: '';
        display: inline-block;
        width: 1.5em;
        text-align: left;
        animation: dotsAnimation 1.5s steps(4, end) infinite;
    }
    @keyframes dotsAnimation {
        0% { content: ''; }
        25% { content: '.'; }
        50% { content: '..'; }
        75% { content: '...'; }
    }

    .neon-progress-bar {
        background: linear-gradient(90deg, #06b6d4, var(--neon-cyan));
        box-shadow: 0 0 12px var(--neon-cyan);
        transition: width 0.15s ease-out;
    }

.cyber-popup-bg {
  background-color: #010811;
  background-image: radial-gradient(circle at 50% 30%, #031e36 0%, #010811 80%);
}

.double-border-cyan {
  background: #010d18;
  border: 1.5px solid #00f3ff;
  outline: 1.5px solid #00f3ff;
  outline-offset: 2.5px;
  box-shadow: 0 0 12px rgba(0, 243, 255, 0.35);
}

.cyber-pill-capsule {
  background: #010a14;
  border: 1.5px solid #00f3ff;
  outline: 1.5px solid #00f3ff;
  outline-offset: 2px;
  border-radius: 9999px;
  box-shadow: inset 0 0 6px rgba(0, 243, 255, 0.3);
}

.gold-metallic-button {
  background: linear-gradient(180deg, #fef08a 0%, #f59e0b 35%, #b45309 70%, #78350f 100%);
  border: 1px solid #fef08a;
  color: #000000;
  font-weight: 900;
  letter-spacing: 1px;
  text-shadow: 0px 1px 1px rgba(255, 255, 255, 0.4);
  box-shadow: 0 0 14px rgba(245, 158, 11, 0.45);
}

.gold-metallic-button:hover {
  filter: brightness(1.15);
}

.cyan-solid-header {
  background-color: #00f3ff;
  color: #010811;
  font-weight: 900;
  box-shadow: 0 0 14px rgba(0, 243, 255, 0.8);
}
</style>
</head>
<body class="min-h-screen antialiased text-slate-900 relative">

<div id="cyber-loader-overlay">
    <div class="scanner-beam"></div>

    <div class="hud-ring mb-6">
        <div class="ring-outer"></div>
        <div class="ring-middle"></div>
        <div class="ring-inner"></div>
        <img src="https://arulz-xd.my.id/files/Q2C70y.png" alt="Logo" class="hud-avatar">
    </div>

    <div class="text-center px-4">
        <div id="loader-title-text" class="text-sm font-extrabold tracking-widest uppercase text-cyan-400 code-font mb-1">
            Memuat Halaman<span class="animated-dots"></span>
        </div>
        <div class="text-[10px] text-slate-400 font-mono tracking-wider opacity-80 uppercase">
            SYSTEM INITIALIZING // CORE GATEWAY
        </div>
    </div>

    <div class="w-64 sm:w-80 mt-6">
        <div class="flex items-center justify-between text-xs font-bold code-font mb-2">
            <span class="text-slate-400 text-[10px]">SYSTEM STATUS</span>
            <span id="loader-percentage" class="text-cyan-400 text-sm">0%</span>
        </div>
        <div class="w-full h-2 bg-slate-900/90 rounded-full border border-cyan-500/30 overflow-hidden p-0.5">
            <div id="loader-progress-fill" class="h-full rounded-full neon-progress-bar w-0"></div>
        </div>
    </div>

    <div class="absolute bottom-6 text-[10px] font-mono text-slate-500 uppercase tracking-widest">
        XS-PEDIA API v2.0
    </div>
</div>

<div id="themeBg" class="fixed inset-0 -z-10"></div>

    <!-- Welcome Popup -->
    <div id="welcomePopup" class="fixed inset-0 z-[99999] hidden">
      <div class="fixed inset-0 bg-black/80 backdrop-blur-sm"></div>
      <div class="fixed inset-0 flex items-center justify-center p-4">
        <div class="bg-slate-900/90 border border-white/10 rounded-2xl shadow-2xl w-full max-w-sm sm:max-w-md relative p-6 font-['Space_Grotesk'] text-slate-100 transition-all duration-300">
          
          <button id="closePopupBtn" class="absolute top-4 right-4 text-slate-400 hover:text-red-400 transition-colors bg-white/5 hover:bg-white/10 rounded-full p-1.5 focus:outline-none border border-white/5">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
            </svg>
          </button>
          
          <div class="text-center mb-4">
            <h1 class="text-xl sm:text-2xl font-extrabold text-white leading-tight tracking-wide">
              Welcome to<br><span class="text-cyan-400">XS-Pedia API</span>
            </h1>
          </div>
          
          <div class="mb-4 rounded-xl overflow-hidden border border-white/10 bg-black/40">
            <img src="https://arulz-xd.my.id/files/K4Sf61.png" alt="Welcome Banner" class="w-full h-auto object-cover max-h-48" />
          </div>
          
          <div class="text-center text-slate-300 text-xs sm:text-sm mb-5 px-1 leading-relaxed">
            <p>Halo! 👋 Selamat datang di XS-Pedia API. Terima kasih sudah berkunjung. API ini dibuat untuk membantu developer dengan berbagai fitur yang terus diperbarui. Silakan gunakan API Key di bawah ini.</p>
          </div>
          
          <div class="mb-5 flex justify-center">
            <div class="bg-black/30 rounded-full py-2 px-5 border-2 border-dashed border-cyan-500/30">
              <span class="font-bold text-xs sm:text-sm text-slate-200 tracking-wide">
                apikey : <span id="welcomeApiKey" class="font-mono text-cyan-400 select-all">${(req.user && req.user.apikey) ? req.user.apikey : 'Silakan Login'}</span>
              </span>
            </div>
          </div>
          
          <a href="/support" class="w-full bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-white font-bold py-3 px-6 rounded-xl shadow-lg transition-all text-sm block text-center tracking-wider uppercase">
            Donate Sekarang
          </a>
        </div>
      </div>
    </div>
    
<!-- Bright Comic Green Theme Overrides -->
<style>
  :root{
    --comic-ink:#244235;
    --comic-green:#48c774;
    --comic-green-2:#8be28f;
    --comic-mint:#effff0;
    --comic-cream:#fffdf5;
    --comic-border:#b8dcb8;
  }
  body{
    background:
      radial-gradient(circle at 10% 0%, rgba(139,226,143,.42), transparent 34%),
      radial-gradient(circle at 100% 20%, rgba(72,199,116,.25), transparent 30%),
      linear-gradient(135deg,#f7fff5 0%,#ecfff0 48%,#fdfcf3 100%) !important;
    color:var(--comic-ink) !important;
    font-family: Georgia,'Times New Roman',serif !important;
  }
  body:before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.22;background-image:radial-gradient(#67b978 1px,transparent 1px);background-size:18px 18px;z-index:-1}
  .glass-panel{background:rgba(255,255,252,.9)!important;border:2px solid rgba(94,151,100,.22)!important;box-shadow:0 8px 24px rgba(69,114,76,.10)!important;color:#31513e!important}
  .light-mode .glass-panel{background:rgba(255,255,252,.96)!important;border-color:rgba(94,151,100,.24)!important}
  .light-mode{background:transparent!important;color:var(--comic-ink)!important}
  .light-mode #mainTitle,.light-mode #mainDescription,.light-mode #no-results-title{color:var(--comic-ink)!important}
  .filter-btn{border:2px solid #afd8af!important;background:rgba(255,255,255,.7)!important;color:#547161!important;border-radius:999px!important;padding:10px 18px!important;font-family:Georgia,'Times New Roman',serif!important;font-size:14px!important;font-weight:700!important;box-shadow:4px 4px 0 rgba(95,137,100,.12);white-space:nowrap}
  .filter-btn:hover{background:#eaffea!important;color:#31513e!important}
  .filter-btn.active{background:linear-gradient(135deg,#35b86a,#8fe28c)!important;color:#123b24!important;border-color:#54bc71!important}
  .category-scroll{display:flex!important;flex-wrap:nowrap!important;overflow-x:auto!important;overflow-y:hidden!important;scroll-snap-type:x proximity!important;padding:4px 4px 12px!important;-webkit-overflow-scrolling:touch}
  .category-scroll .filter-btn{flex:0 0 auto!important;scroll-snap-align:start}
  #bioDropdown{background:linear-gradient(180deg,#fbfff8,#edffef)!important;border-left:2px solid #9dce9e!important;color:#355040!important}
  #bioDropdown .menu-link span{color:#4e6d58!important}
  #bioDropdown .menu-link:hover{background:#e6f8e7!important}
  #bioDropdown nav>div{color:#6c8a73!important}
  .music-player-card{background:rgba(255,255,252,.94)!important;border:2px solid #c4dfc2!important;box-shadow:0 8px 24px rgba(69,114,76,.10)!important}
  .music-text-title{color:#31513e!important}.music-text-artist{color:#6f8274!important}
  #profilePopup{font-family:Georgia,'Times New Roman',serif}
  #profilePopup .profile-card{background:linear-gradient(145deg,#fbfff8,#fffdf7)!important;border:2px solid #acd5ac!important;box-shadow:0 18px 50px rgba(49,101,59,.18)!important}
  #profilePopup .profile-chip{background:linear-gradient(135deg,#f1fff0,#e6f9e7)!important;border:2px solid #6bb274!important;color:#477259!important;box-shadow:4px 4px 0 rgba(94,151,100,.10)}
  #profilePopup .profile-docs{background:linear-gradient(135deg,#2c9a5f,#79c66d)!important;box-shadow:5px 5px 0 rgba(55,122,77,.12)!important}
  #profilePopup .profile-main{background:rgba(255,255,250,.95)!important;border:2px solid #d0e6ce!important}
  #profilePopup .profile-row{border-bottom:2px dashed #cde2ca!important}
  #profilePopup .profile-badge{background:linear-gradient(135deg,#dff4df,#f2fbec)!important;color:#52705b!important}
  #profilePopup .profile-key-box,#profilePopup .profile-log{background:linear-gradient(135deg,#f2fbef,#fffdf7)!important;border:2px solid #d0e3cc!important}
  #profilePopup .profile-copy,#profilePopup .profile-upgrade{background:linear-gradient(135deg,#e7f8e6,#f5f8ed)!important;border:2px solid #6eb176!important;color:#4c7259!important;box-shadow:4px 4px 0 rgba(85,132,90,.10)}
  #profilePopup .profile-upgrade{background:linear-gradient(135deg,#2f925a,#7bc96c)!important;color:#fff!important;border:0!important}
  #profilePopup .profile-footer .profile-close{background:#f8fff6!important;border:2px solid #b8d9b5!important;color:#385843!important}
  #profilePopup .profile-footer .profile-logout{background:#fff7f7!important}
  #profilePopup .profile-avatar-ring{border:3px solid #72a974!important;box-shadow:5px 5px 0 rgba(91,133,94,.10)!important}
  #profilePopup .profile-camera{background:linear-gradient(135deg,#3c9e62,#83cb74)!important;border-color:#fff!important}
  #profilePopup .profile-title{color:#294335!important}
  #profilePopup .profile-subtitle{color:#6c8174!important}
  #profilePopup .profile-label{color:#718176!important}
  #profilePopup .profile-value,#profilePopup .profile-name{color:#30483b!important}
  #profilePopup .profile-value.accent{color:#4c805d!important}
  @media(max-width:640px){
    #profilePopup .profile-wrap{padding:10px!important}
    #profilePopup .profile-card{max-width:430px!important;border-radius:24px!important;padding:12px!important}
    #profilePopup .profile-main{padding:15px 13px!important}
    #profilePopup .profile-title{font-size:26px!important}
    #profilePopup .profile-subtitle{font-size:13px!important}
    #profilePopup .profile-identity{gap:10px!important}
    #profilePopup .profile-avatar-wrap{width:70px!important;height:70px!important;flex-basis:70px!important}
    #profilePopup .profile-name{font-size:18px!important}
    #profilePopup .profile-row{padding:10px 0!important}
    #profilePopup .profile-label{font-size:13px!important}
    #profilePopup .profile-value{font-size:13px!important}
    #profilePopup .profile-section{margin-top:13px!important}
    #profilePopup .profile-section-title{font-size:13px!important}
    #profilePopup .profile-log{grid-template-columns:auto minmax(0,1fr)!important}
    #profilePopup .profile-log-meta{grid-column:2!important;text-align:left!important;margin-top:-2px!important}
  }
</style>

<!-- User Profile Pop-up Modal -->
<style>
  #profilePopup .profile-shell{font-family:Georgia,'Times New Roman',serif;color:#52645a}
  #profilePopup .profile-card{background:linear-gradient(145deg,#f8fbf5,#fffdf9);border:1.5px solid #cfe1cc;border-radius:24px;box-shadow:0 18px 50px rgba(47,90,61,.16)}
  #profilePopup .profile-chip{display:inline-flex;align-items:center;gap:8px;background:#eef6ea;border:1.5px solid #78a96d;border-radius:999px;color:#47765a;font-weight:700;letter-spacing:2px;font-size:11px;padding:7px 14px;text-transform:uppercase}
  #profilePopup .profile-title{font-family:Georgia,'Times New Roman',serif;font-size:30px;line-height:1.05;font-weight:800;color:#304338;margin:14px 0 6px}
  #profilePopup .profile-subtitle{font-size:14px;line-height:1.45;color:#708078;margin:0 0 14px}
  #profilePopup .profile-docs{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;background:linear-gradient(135deg,#2f6f52,#6f9f67);color:#fff;border-radius:999px;padding:12px 16px;font-weight:800;font-size:16px;text-decoration:none;box-shadow:0 7px 18px rgba(47,111,82,.18)}
  #profilePopup .profile-main{background:rgba(255,255,252,.92);border:1.5px solid #d6e5d1;border-radius:22px;padding:20px 20px 18px}
  #profilePopup .profile-identity{display:flex;align-items:center;gap:14px;margin-bottom:18px}
  #profilePopup .profile-avatar-wrap{position:relative;width:82px;height:82px;flex:0 0 82px}
  #profilePopup .profile-avatar-ring{width:100%;height:100%;border-radius:50%;padding:2px;border:2px solid #6f9f67;background:#fff;overflow:hidden;box-shadow:0 4px 14px rgba(62,107,72,.12)}
  #profilePopup .profile-avatar{width:100%;height:100%;border-radius:50%;object-fit:cover;background:#eef5eb}
  #profilePopup .profile-camera{position:absolute;right:-4px;bottom:-3px;width:34px;height:34px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#3d7b5b,#74a36c);color:#fff;border:3px solid #fffdf9;box-shadow:0 4px 10px rgba(47,90,61,.2)}
  #profilePopup .profile-name{font-size:22px;font-weight:800;color:#304338;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  #profilePopup .profile-email{margin-top:5px;font-size:14px;color:#718079;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  #profilePopup .profile-row{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:13px 0;border-bottom:1.5px dashed #d7e5d3}
  #profilePopup .profile-row:last-child{border-bottom:0}
  #profilePopup .profile-label{font-size:14px;font-weight:700;color:#718079}
  #profilePopup .profile-value{font-family:'Courier New',monospace;font-size:15px;font-weight:800;color:#304338;text-align:right;min-width:0}
  #profilePopup .profile-value.accent{color:#4f815f}
  #profilePopup .profile-badge{background:linear-gradient(135deg,#dcebd7,#eef5e9);color:#52705b;border-radius:999px;padding:6px 13px;font-size:13px;font-weight:800}
  #profilePopup .profile-actions{display:flex;align-items:center;gap:8px;min-width:0;max-width:100%}
  #profilePopup .profile-upgrade{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;margin-top:14px;border:0;border-radius:999px;background:linear-gradient(135deg,#315f49,#78a96d);color:#fff;padding:12px 16px;font-size:15px;font-weight:800;box-shadow:0 7px 18px rgba(49,95,73,.16)}
  #profilePopup .profile-section{margin-top:16px}
  #profilePopup .profile-section-title{font-size:14px;font-weight:800;color:#60766a;margin-bottom:8px}
  #profilePopup .profile-key-box{background:linear-gradient(135deg,#f3f8ef,#fafbf6);border:1.5px solid #d3e2ce;border-radius:16px;padding:10px 12px}
  #profilePopup .profile-key{font-family:'Courier New',monospace;font-size:14px;font-weight:800;color:#42534a;word-break:break-all}
  #profilePopup .profile-copy{margin-top:8px;width:100%;border:1.5px solid #6f9f67;border-radius:999px;background:linear-gradient(135deg,#eaf4e6,#f5f8ef);color:#4f725b;padding:10px 12px;font-size:12px;font-weight:800;letter-spacing:1.1px}
  #profilePopup .profile-activity{max-height:190px;overflow:auto;display:flex;flex-direction:column;gap:8px;padding-right:2px}
  #profilePopup .profile-log{display:grid;grid-template-columns:auto minmax(0,1fr) auto;align-items:center;gap:8px;background:linear-gradient(135deg,#f4f7ef,#fbf8f0);border:1.5px solid #dce5d6;border-radius:13px;padding:9px 10px;font-family:'Courier New',monospace;min-width:0}
  #profilePopup .profile-log-method{background:#fffdf7;border:1.5px solid #d9dfd0;border-radius:7px;padding:4px 7px;font-size:10px;font-weight:800;color:#6c786f}
  #profilePopup .profile-log-endpoint{min-width:0;font-size:11px;font-weight:800;color:#35473d;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  #profilePopup .profile-log-meta{text-align:right;white-space:nowrap;font-size:10px;font-weight:800}
  #profilePopup .profile-log-status.ok{color:#5d8b66}
  #profilePopup .profile-log-status.err{color:#ad5960}
  #profilePopup .profile-log-date{display:block;color:#847e76;font-weight:600;margin-top:2px}
  #profilePopup .profile-footer{display:flex;gap:8px;margin-top:14px}
  #profilePopup .profile-close{flex:1;border:1.5px solid #cfe1cc;border-radius:999px;background:#fffefb;color:#35513e;padding:10px;font-weight:800;font-size:13px}
  #profilePopup .profile-logout{flex:1;border:1.5px solid #d78a91;border-radius:999px;background:#fff8f8;color:#a25059;padding:10px;font-weight:800;font-size:13px;text-align:center;text-decoration:none}
  @media (max-width:480px){
    #profilePopup .profile-wrap{padding:8px}
    #profilePopup .profile-card{border-radius:22px;max-height:calc(100vh - 16px);overflow:auto}
    #profilePopup .profile-main{padding:17px 15px 16px}
    #profilePopup .profile-title{font-size:27px}
    #profilePopup .profile-subtitle{font-size:13px}
    #profilePopup .profile-identity{gap:12px}
    #profilePopup .profile-avatar-wrap{width:74px;height:74px;flex-basis:74px}
    #profilePopup .profile-name{font-size:19px}
    #profilePopup .profile-email{font-size:13px}
    #profilePopup .profile-row{padding:11px 0}
    #profilePopup .profile-value{font-size:14px}
    #profilePopup .profile-docs{font-size:15px;padding:11px 14px}
    #profilePopup .profile-log{grid-template-columns:auto minmax(0,1fr);gap:7px}
    #profilePopup .profile-log-meta{grid-column:2;text-align:left;margin-top:-3px}
  }
</style>
<div id="profilePopup" class="fixed inset-0 z-[99999] hidden" style="display:none" aria-hidden="true">
  <div class="fixed inset-0 bg-[#183024]/25 backdrop-blur-[2px]" onclick="closeProfilePopup()"></div>
  <div class="fixed inset-0 overflow-y-auto">
    <div class="profile-wrap min-h-full flex items-start sm:items-center justify-center p-3 sm:p-5">
      <div class="profile-card profile-shell w-full max-w-[560px] p-4 sm:p-5 my-auto relative">
        <div class="profile-chip">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21a8 8 0 0 0-16 0"/><circle cx="12" cy="7" r="4"/></svg>
          ACCOUNT SETTINGS
        </div>

        <div class="profile-title">User Profile</div>
        <p class="profile-subtitle">Manage your account settings, daily limits, and API credentials.</p>

        <a href="/docs" class="profile-docs">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 2h9l3 3v17H6a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2Z"/><path d="M14 2v5h5M8 12h8M8 16h8"/></svg>
          API Docs
        </a>

        <div class="profile-main mt-4">
          <div class="profile-identity">
            <div class="profile-avatar-wrap">
              <input type="file" id="avatarInput" accept="image/*" class="hidden" onchange="uploadAvatarFile(this)">
              <div class="profile-avatar-ring cursor-pointer" onclick="document.getElementById('avatarInput').click()">
                <img id="userAvatar" src="https://arulz-xd.my.id/files/X1F0Cn.png" class="profile-avatar">
              </div>
              <div class="profile-camera cursor-pointer" onclick="document.getElementById('avatarInput').click()">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 7h3l1.4-2h5.2L16 7h3a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V9a2 2 0 0 1 2-2Z"/><circle cx="12" cy="13" r="3.5"/></svg>
              </div>
            </div>
            <div class="min-w-0 flex-1">
              <div id="userName" class="profile-name">loading...</div>
              <div id="userEmail" class="profile-email">loading_email@gmail.com</div>
            </div>
          </div>

          <div class="profile-row">
            <span class="profile-label">Subscription Plan</span>
            <span id="userPlanTextBadge" class="profile-badge"><span id="userPlanText">FREE</span></span>
          </div>

          <div class="profile-row">
            <span class="profile-label">Username</span>
            <div class="profile-actions">
              <span id="userUsername" class="profile-value truncate">-</span>
            </div>
          </div>

          <div class="profile-row">
            <span class="profile-label">Email</span>
            <div class="profile-actions">
              <span id="userEmailRow" class="profile-value truncate">-</span>
            </div>
          </div>

          <div class="profile-row">
            <span class="profile-label">Daily Limit</span>
            <span class="profile-value"><span id="popupLimitUsed">0</span> / <span id="popupLimitMax">100</span></span>
          </div>

          <div class="profile-section">
            <div class="profile-section-title">API Key</div>
            <div class="profile-key-box"><span id="userApiKey" class="profile-key">loading-key</span></div>
            <div id="vipCustomKeyBox" class="hidden mt-3">
              <div class="flex gap-2">
                <input type="text" id="customApiKeyInput" placeholder="Ketik Custom API Key..." class="flex-1 bg-[#fffefb] border border-[#cfe1cc] rounded-full px-4 py-2.5 text-sm text-[#4a5c51] outline-none">
                <button onclick="saveCustomApiKey()" class="profile-copy mt-0 !w-auto !px-4 whitespace-nowrap">SIMPAN</button>
              </div>
            </div>
            <button onclick="copyText(document.getElementById('userApiKey').innerText, 'API Key')" class="profile-copy">SALIN API KEY</button>
          </div>

          <div class="profile-section">
            <div class="profile-section-title">Recent API Activity</div>
            <div id="activityLogsContainer" class="profile-activity">
              <div class="profile-log"><span class="profile-log-method">GET</span><span class="profile-log-endpoint">belum ada request</span><span></span></div>
            </div>
          </div>

          <a href="/upgrade-apikey" class="profile-upgrade">
            <svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor"><path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 0 0 .95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 0 0-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 0 0-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 0 0-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 0 0 .951-.69l1.07-3.292z"/></svg>
            Upgrade Plan / VIP
          </a>

          <div class="profile-footer">
            <button onclick="closeProfilePopup()" class="profile-close">TUTUP</button>
            <a href="/auth/logout" class="profile-logout">
              <span class="inline-flex items-center justify-center gap-2"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M17 16l4-4-4-4M21 12H7M13 5V4a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2-2h5a2 2 0 0 0 2-2v-1"/></svg> LOG OUT</span>
            </a>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<div id="toast" class="fixed top-6 right-6 z-[9999] flex flex-col gap-3 pointer-events-none items-end"></div>

    <!-- Header Actions -->
    <div class="fixed top-6 right-6 z-40 flex items-center gap-3">
        <button id="bioMenuBtn" class="flex items-center justify-center w-10 h-10 rounded-xl glass-panel text-slate-300 hover:text-white shadow-lg transition-all active:scale-95 focus:outline-none light-mode:text-slate-700 light-mode:hover:text-slate-900 border border-white/5">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2.3" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M4 6h16M4 12h16M4 18h16" />
            </svg>
        </button>
    </div>

    <!-- Sidebar Dropdown -->
    <div id="bioDropdown" class="fixed top-0 right-0 h-full w-72 bg-[#060c18] border-l border-white/5 transform translate-x-full transition-transform duration-300 ease-in-out z-50 shadow-2xl flex flex-col p-6 font-['Space_Grotesk'] light-mode:bg-white light-mode:border-slate-200">
        <div class="flex items-center justify-between mb-5">
            <div class="flex gap-0 border border-white/10 rounded-lg p-0.5 bg-black/40">
                <button id="lang-id" class="lang-btn rounded-md active" onclick="setLanguage('id')">ID</button>
                <button id="lang-en" class="lang-btn rounded-md" onclick="setLanguage('en')">EN</button>
            </div>
            
            <div class="flex items-center gap-1.5">
                <button id="themeToggle" class="flex items-center justify-center w-8 h-8 rounded-lg transition-all active:scale-95 focus:outline-none border border-white/10 bg-slate-900/50 text-white light-mode:bg-slate-100 light-mode:border-slate-300 light-mode:text-slate-900">
                    <svg id="theme-toggle-dark-icon" class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                        <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z"></path>
                    </svg>
                    <svg id="theme-toggle-light-icon" class="w-4 h-4 hidden" fill="currentColor" viewBox="0 0 20 20">
                        <path d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z" fill-rule="evenodd" clip-rule="evenodd"></path>
                    </svg>
                </button>

                <button id="closeMenuBtn" class="text-white hover:text-red-400 transition-colors p-1.5 border border-white/10 rounded bg-slate-900/40 light-mode:text-slate-700 light-mode:bg-slate-100 light-mode:border-slate-300 light-mode:hover:text-red-500">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
                    </svg>
                </button>
            </div>
        </div>

        ${req.user ? `
        <div class="mb-4 flex flex-col antialiased font-['Space_Grotesk']">
            <button onclick="openProfilePopup()" class="group relative flex items-center gap-3 bg-slate-950/80 text-white font-bold p-3 rounded-xl transition-all duration-300 text-xs tracking-wider uppercase overflow-hidden active:scale-95 border border-cyan-500/20 hover:border-cyan-500/40 shadow-lg w-full">
                <div class="relative flex-shrink-0 z-10">
                    <img id="sidebarUserAvatar" src="${req.user.avatar}" class="w-8 h-8 rounded-full border border-white/20 object-cover shadow-sm">
                    <span class="absolute bottom-0 right-0 w-2.5 h-2.5 bg-emerald-400 border-2 border-slate-950 rounded-full"></span>
                </div>
                
                <div class="flex flex-col text-left min-w-0 z-10">
                    <span class="text-[8px] text-cyan-400 font-mono tracking-widest opacity-90">PROFILE USER</span>
                    <span class="truncate text-white font-black tracking-wide normal-case text-xs shadow-sm">${req.user.username}</span>
                </div>

                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2.5" stroke="currentColor" class="w-4 h-4 ml-auto text-cyan-400 opacity-90 z-10 transition-transform group-hover:translate-x-1">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M13.5 4.5 21 12m0 0-7.5 7.5M21 12H3" />
                </svg>
            </button>
        </div>
        ` : `
        <div class="mb-3 flex flex-col gap-2">
            <a href="/login" class="flex items-center justify-center gap-2 bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-white font-bold p-3 rounded-xl text-xs uppercase tracking-wider transition-all duration-200">
                <span>Masuk ke Akun</span>
            </a>
        </div>
        `}

        <nav class="flex flex-col gap-1.5 text-xs font-semibold tracking-wider uppercase text-slate-300 flex-1 py-1 overflow-y-auto scrollbar-hide">
    <div class="text-[10px] font-bold text-slate-500 px-2 pt-2 pb-1 tracking-widest">PAGES</div>

    <a href="/" class="menu-link group flex items-center gap-3 px-2 py-1.5 rounded-lg hover:bg-cyan-950/30 transition-all duration-300">
        <div class="w-8 h-8 rounded-lg bg-cyan-950/40 border border-cyan-500/20 flex items-center justify-center group-hover:border-cyan-400/50 group-hover:shadow-[0_0_10px_rgba(34,211,238,0.2)] transition-all shrink-0">
            <svg viewBox="0 0 24 24" fill="none" class="w-5 h-5 transform group-hover:scale-110 transition-transform duration-300" style="filter: drop-shadow(0 0 3px rgba(34, 211, 238, 0.8));">
                <path d="M3 11l9-9 9 9v11H3V11z" stroke="#22d3ee" stroke-width="1.5" stroke-linejoin="round" />
                <path d="M19 8v-3h-2v1.5M10 16h4v6h-4v-6z" stroke="#22d3ee" stroke-width="1.5" stroke-linecap="round" />
                <path d="M7 13v6M9 13v6M7 16h2" stroke="#22d3ee" stroke-width="1" stroke-linecap="round" stroke-linejoin="round" />
                <path d="M14 13v6l1.5-1.5 1.5 1.5v-6" stroke="#22d3ee" stroke-width="1" stroke-linecap="round" stroke-linejoin="round" />
                <path d="M12 5v3M10 8h4" stroke="#22d3ee" stroke-width="0.5" stroke-linecap="round" />
                <circle cx="12" cy="5.5" r="0.5" fill="#22d3ee" />
                <circle cx="9" cy="9" r="0.4" fill="#22d3ee" />
                <circle cx="15" cy="9" r="0.4" fill="#22d3ee" />
            </svg>
        </div>
        <span class="font-medium text-cyan-100 group-hover:text-cyan-400 transition-colors duration-300">Dashboard</span>
    </a>

    <a href="/docs" class="menu-link group flex items-center gap-3 px-2 py-1.5 rounded-lg hover:bg-cyan-950/30 transition-all duration-300">
        <div class="w-8 h-8 rounded-lg bg-cyan-950/40 border border-cyan-500/20 flex items-center justify-center group-hover:border-cyan-400/50 group-hover:shadow-[0_0_10px_rgba(34,211,238,0.2)] transition-all shrink-0">
            <svg viewBox="0 0 24 24" fill="none" class="w-5 h-5 transform group-hover:scale-110 transition-transform duration-300" style="filter: drop-shadow(0 0 3px rgba(34, 211, 238, 0.8));">
                <path d="M2 5c0-1.1.9-2 2-2h6.5l1.5 1.5L13.5 3H20c1.1 0 2 .9 2 2v13c0 1.1-.9 2-2 2h-6.5L12 18.5 10.5 20H4c-1.1 0-2-.9-2-2V5z" stroke="#22d3ee" stroke-width="1" stroke-linecap="round" stroke-linejoin="round"/>
                <path d="M3 6.5C3 5.7 3.7 5 4.5 5H11v13H4.5C3.7 18 3 17.3 3 16.5V6.5zM21 6.5c0-.8-.7-1.5-1.5-1.5H13v13h6.5c.8 0 1.5-.7 1.5-1.5V6.5z" stroke="#22d3ee" stroke-width="1.2" stroke-linejoin="round"/>
                <path d="M12 4v14.5" stroke="#22d3ee" stroke-width="1.2" stroke-linecap="round"/>
                <rect x="5.5" y="8" width="4.5" height="6.5" rx="0.8" stroke="#22d3ee" stroke-width="0.9" fill="none"/>
                <line x1="6.5" y1="10" x2="9" y2="10" stroke="#22d3ee" stroke-width="0.7" stroke-linecap="round"/>
                <line x1="6.5" y1="11.5" x2="9" y2="11.5" stroke="#22d3ee" stroke-width="0.7" stroke-linecap="round"/>
                <text x="16.8" y="11" fill="#22d3ee" font-size="2.6" font-weight="900" font-family="sans-serif" text-anchor="middle">DOCS</text>
            </svg>
        </div>
        <span class="font-medium text-cyan-100 group-hover:text-cyan-400 transition-colors duration-300">Docs</span>
    </a>

    <a href="/store" class="menu-link group flex items-center gap-3 px-2 py-1.5 rounded-lg hover:bg-cyan-950/30 transition-all duration-300">
        <div class="w-8 h-8 rounded-lg bg-cyan-950/40 border border-cyan-500/20 flex items-center justify-center group-hover:border-cyan-400/50 group-hover:shadow-[0_0_10px_rgba(34,211,238,0.2)] transition-all shrink-0">
            <svg class="w-4 h-4 text-cyan-400 transform group-hover:scale-110 transition-transform duration-300" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M2.25 3h1.386c.51 0 .955.343 1.087.835l.383 1.437M4.756 5.272h15.744l-1.38 6.21a2.25 2.25 0 01-2.195 1.762H7.27a2.25 2.25 0 01-2.196-1.762L3.636 3.835M7.5 21a1.5 1.5 0 100-3 1.5 1.5 0 000 3zm10.5 0a1.5 1.5 0 100-3 1.5 1.5 0 000 3z" />
                <polygon points="12,5.5 13.09,7.71 15.54,8.07 13.77,9.8 14.19,12.24 12,11.09 9.81,12.24 10.23,9.8 8.46,8.07 10.91,7.71" stroke-linecap="round" stroke-linejoin="round" />
            </svg>
        </div>
        <span class="font-medium text-cyan-100 group-hover:text-cyan-400 transition-colors duration-300">Store</span>
    </a>

    <a href="/changelog" class="menu-link group flex items-center gap-3 px-2 py-1.5 rounded-lg hover:bg-cyan-950/30 transition-all duration-300">
        <div class="w-8 h-8 rounded-lg bg-cyan-950/40 border border-cyan-500/20 flex items-center justify-center group-hover:border-cyan-400/50 group-hover:shadow-[0_0_10px_rgba(34,211,238,0.2)] transition-all shrink-0">
            <svg class="w-4 h-4 text-cyan-400 transform group-hover:scale-110 transition-transform duration-300" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
        </div>
        <span class="font-medium text-cyan-100 group-hover:text-cyan-400 transition-colors duration-300">Changelog</span>
    </a>

    <a href="/uploader" class="menu-link group flex items-center gap-3 px-2 py-1.5 rounded-lg hover:bg-cyan-950/30 transition-all duration-300">
        <div class="w-8 h-8 rounded-lg bg-cyan-950/40 border border-cyan-500/20 flex items-center justify-center group-hover:border-cyan-400/50 group-hover:shadow-[0_0_10px_rgba(34,211,238,0.2)] transition-all shrink-0">
            <svg class="w-4 h-4 text-cyan-400 transform group-hover:scale-110 transition-transform duration-300" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M12 16.5V9.75m0 0l3 3m-3-3l-3 3M6.75 19.5a4.5 4.5 0 01-1.41-8.775 5.25 5.25 0 0110.233-2.33 3 3 0 013.758 3.848A3.752 3.752 0 0118 19.5H6.75z" />
            </svg>
        </div>
        <span class="font-medium text-cyan-100 group-hover:text-cyan-400 transition-colors duration-300">Uploader</span>
    </a>

    <a href="/pastecode" class="menu-link group flex items-center gap-3 px-2 py-1.5 rounded-lg hover:bg-cyan-950/30 transition-all duration-300">
        <div class="w-8 h-8 rounded-lg bg-cyan-950/40 border border-cyan-500/20 flex items-center justify-center group-hover:border-cyan-400/50 group-hover:shadow-[0_0_10px_rgba(34,211,238,0.2)] transition-all shrink-0">
            <svg class="w-4 h-4 text-cyan-400 transform group-hover:scale-110 transition-transform duration-300" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M17.25 6.75 22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3-4.5 16.5" />
            </svg>
        </div>
        <span class="font-medium text-cyan-100 group-hover:text-cyan-400 transition-colors duration-300">Pastecode</span>
    </a>

    <a href="/feedback" class="menu-link group flex items-center gap-3 px-2 py-1.5 rounded-lg hover:bg-cyan-950/30 transition-all duration-300">
        <div class="w-8 h-8 rounded-lg bg-cyan-950/40 border border-cyan-500/20 flex items-center justify-center group-hover:border-cyan-400/50 group-hover:shadow-[0_0_10px_rgba(34,211,238,0.2)] transition-all shrink-0">
            <svg class="w-4 h-4 text-cyan-400 transform group-hover:scale-110 transition-transform duration-300" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M17 8.5h1.5A2.5 2.5 0 0 1 21 11v5a2.5 2.5 0 0 1-2.5 2.5H17v2.5l-3-2.5h-1" />
                <path stroke-linecap="round" stroke-linejoin="round" d="M5.5 3.5h10A2.5 2.5 0 0 1 18 6v7a2.5 2.5 0 0 1-2.5 2.5H8.5L5 18.5V15.5H5.5A2.5 2.5 0 0 1 3 13V6a2.5 2.5 0 0 1 2.5-2.5Z" />
                <path stroke-linecap="round" stroke-linejoin="round" d="M4.5 9.5h1.5l1-2 1.5 4 1.5-3h1" />
            </svg>
        </div>
        <span class="font-medium text-cyan-100 group-hover:text-cyan-400 transition-colors duration-300">Feedback</span>
    </a>

    <a href="/status" class="menu-link group flex items-center gap-3 px-2 py-1.5 rounded-lg hover:bg-cyan-950/30 transition-all duration-300">
        <div class="w-8 h-8 rounded-lg bg-cyan-950/40 border border-cyan-500/20 flex items-center justify-center group-hover:border-cyan-400/50 group-hover:shadow-[0_0_10px_rgba(34,211,238,0.2)] transition-all shrink-0">
            <svg class="w-4 h-4 text-cyan-400 transform group-hover:scale-110 transition-transform duration-300" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24">
                <rect x="3" y="3" width="18" height="6" rx="2" stroke-linecap="round" stroke-linejoin="round"/>
                <rect x="3" y="10.5" width="18" height="6" rx="2" stroke-linecap="round" stroke-linejoin="round"/>
                <path stroke-linecap="round" stroke-linejoin="round" d="M12 16.5v2M3 20.5h6.5m5 0H21"/>
                <circle cx="12" cy="20.5" r="1.5"/>
            </svg>
        </div>
        <span class="font-medium text-cyan-100 group-hover:text-cyan-400 transition-colors duration-300">Stats / Status</span>
    </a>

    <div class="text-[10px] font-bold text-slate-500 px-2 pt-3 pb-1 tracking-widest">LEGAL</div>

    <a href="/privacy" class="menu-link group flex items-center gap-3 px-2 py-1.5 rounded-lg hover:bg-cyan-950/30 transition-all duration-300">
        <div class="w-8 h-8 rounded-lg bg-cyan-950/40 border border-cyan-500/20 flex items-center justify-center group-hover:border-cyan-400/50 group-hover:shadow-[0_0_10px_rgba(34,211,238,0.2)] transition-all shrink-0">
            <svg class="w-4 h-4 text-cyan-400 transform group-hover:scale-110 transition-transform duration-300" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M12 2.25c-3.6 0-6.818 1.433-9.176 3.766A.75.75 0 0 0 2.6 6.58C3.12 11.95 6.35 18.08 12 21.75c5.65-3.67 8.88-9.8 9.4-15.17a.75.75 0 0 0-.224-.564A12.986 12.986 0 0 0 12 2.25Z" />
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.2" d="M10 8h2.8a2.2 2.2 0 0 1 0 4.4H10V8Zm0 0v8" />
            </svg>
        </div>
        <span class="font-medium text-cyan-100 group-hover:text-cyan-400 transition-colors duration-300">Privacy Policy</span>
    </a>

    <a href="/support" class="menu-link group flex items-center gap-3 px-2 py-1.5 rounded-lg hover:bg-cyan-950/30 transition-all duration-300">
        <div class="w-8 h-8 rounded-lg bg-cyan-950/40 border border-cyan-500/20 flex items-center justify-center group-hover:border-cyan-400/50 group-hover:shadow-[0_0_10px_rgba(34,211,238,0.2)] transition-all shrink-0">
            <svg class="w-4 h-4 text-cyan-400 transform group-hover:scale-110 transition-transform duration-300" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M11 20H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v4M22 6v6m-3-3h6m-13 1h2m-2 4h4" stroke-linecap="round" stroke-linejoin="round"/>
                <path d="M16 14.5a3 3 0 0 1-4.8 2.4l-1.2 1.2a1 1 0 0 1-1.4-1.4l1.2-1.2A3 3 0 1 1 16 14.5Zm0 0V21a1 1 0 0 1-1 1h-2a1 1 0 0 1-1-1v-4.5" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        </div>
        <span class="font-medium text-cyan-100 group-hover:text-cyan-400 transition-colors duration-300">Support</span>
      </a>
     </nav>
    </div>

    <div id="menuOverlay" class="fixed inset-0 bg-black/60 backdrop-blur-xs hidden z-30 transition-opacity duration-300"></div>

    <div class="max-w-5xl mx-auto px-4 py-8 relative z-10">
        <header id="api" class="mb-10 text-center">
            <div class="flex items-center justify-center gap-3 mb-3">
                <span class="bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 px-3.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-widest flex items-center gap-2 light-mode:bg-cyan-100 light-mode:text-cyan-700">
                    <span class="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping"></span> ONLINE
                </span>
            </div>
            
            <div id="mainTitle" class="flex justify-center mb-3 min-h-[50px] items-center text-4xl md:text-5xl font-extrabold tracking-tight text-white"><img src="https://readme-typing-svg.demolab.com?font=Poppins&weight=700&size=28&pause=1000&color=00D4FF&center=true&vCenter=true&width=600&lines=Welcome+To+XS-Pedia+API;Fast+%F0%9F%9A%80+Reliable+%E2%9A%A1;Free+REST+API+Services;Developer+Friendly+API" alt="Typing SVG" class="mx-auto" /></div>
            <p id="mainDescription" class="text-sm md:text-base font-normal tracking-wide text-slate-400 max-w-xl mx-auto leading-relaxed">
  Jelajahi, uji, dan jalankan request secara langsung ke endpoint aktif.
</p>

            <div class="mt-8 grid grid-cols-2 md:grid-cols-4 gap-4 max-w-4xl mx-auto">
                <div class="glass-panel flex flex-col items-center justify-center p-4 rounded-xl shadow-lg border border-white/5">
                    <div class="text-center font-['Space_Grotesk']">
                        <div id="liveClock" class="text-xl md:text-2xl font-extrabold tracking-wider text-cyan-400 light-mode:text-cyan-600 font-mono">
                            00:00:00
                        </div>
                        <div id="liveDate" class="text-[9px] font-bold opacity-60 tracking-wide mt-1 uppercase">
                            Loading...
                        </div>
                    </div>
                </div>
                
                <div class="glass-panel flex flex-col items-center justify-center p-4 rounded-xl shadow-lg border border-white/5">
                    <span class="text-[10px] font-bold uppercase tracking-wider text-slate-400 text-center">Limit Terpakai</span>
                    <div class="flex items-baseline gap-0.5 mt-0.5">
                        <span id="userLimitUsed" class="text-2xl font-black text-cyan-400">0</span>
                        <span class="text-slate-500 font-bold text-xs">/</span>
                        <span id="userLimitMax" class="text-xs font-bold text-slate-400">100</span>
                    </div>
                    <span id="userLimitBadge" class="text-[8px] font-bold px-1.5 py-0.5 mt-1 rounded bg-slate-900 text-slate-400 uppercase tracking-widest border border-white/5">FREE</span>
                </div>
                
                <div class="glass-panel flex flex-col items-center justify-center p-4 rounded-xl shadow-lg border border-white/5">
                    <span id="stat-endpoints-title" class="text-[10px] font-bold uppercase tracking-wider text-slate-400">Total Endpoint</span>
                    <span id="totalEndpoints" class="text-2xl font-black text-cyan-400 mt-0.5 light-mode:text-cyan-600">0</span>
                </div>
                
                <div class="glass-panel flex flex-col items-center justify-center p-4 rounded-xl shadow-lg border border-white/5">
                    <span id="stat-categories-title" class="text-[10px] font-bold uppercase tracking-wider text-slate-400">Total Kategori</span>
                    <span id="totalCategories" class="text-2xl font-black text-cyan-400 mt-0.5 light-mode:text-cyan-600">0</span>
                </div>
            </div>

            <div class="glass-panel max-w-4xl mx-auto mt-4 p-3 rounded-xl flex flex-col sm:flex-row items-center justify-between gap-3 border border-cyan-500/10">
                <div class="flex items-center gap-2 text-xs md:text-sm text-cyan-400 light-mode:text-cyan-700 font-mono">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                    </svg>
                    <span class="underline break-all font-semibold">https://xs-pedia.id</span>
                </div>
                <a href="/feedback" 
                   class="w-full sm:w-auto px-5 py-2 bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-slate-950 font-bold text-[11px] uppercase rounded-lg shadow-md transition-all active:scale-95 light-mode:text-white text-center flex items-center justify-center gap-1.5">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M12 4.5v15m7.5-7.5h-15" />
                    </svg>
                    Request Feature
                </a>
            </div>

            <div class="flex justify-center gap-4 mt-4 max-w-4xl mx-auto">
                <a href="https://whatsapp.com/channel/0029VbAwdIyJJhzRMpjUcS3P" 
                   target="_blank" 
                   class="flex-1 glass-panel py-2.5 rounded-xl text-xs font-bold uppercase tracking-wider hover:bg-white/5 transition-all text-center flex items-center justify-center gap-2 border border-white/5 text-slate-300">
                   <svg class="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                       <path stroke-linecap="round" stroke-linejoin="round" d="M8.684 10.742l.08-.08a2.25 2.25 0 013.182 0l.397.397m-1.397-1.398a2.25 2.25 0 00-3.182 0l-3.472 3.472a2.25 2.25 0 000 3.181l.08.08a2.25 2.25 0 003.181 0l3.472-3.472a2.25 2.25 0 000-3.181c-.074-.074-.154-.14-.237-.196zm7.708-.943a2.25 2.25 0 00-3.182 0l-.397.397m1.397-1.397a2.25 2.25 0 013.182 0l3.472 3.473a2.25 2.25 0 010 3.182l-.08.08a2.25 2.25 0 01-3.181 0l-3.472-3.472a2.25 2.25 0 010-3.181c.074-.074.154-.14.237-.196z" />
                   </svg>
                   Channel
                </a>
                <a href="https://chat.whatsapp.com/LBeGqVsmDBb6j29ysuusd9" 
                   target="_blank" 
                   class="flex-1 glass-panel py-2.5 rounded-xl text-xs font-bold uppercase tracking-wider hover:bg-white/5 transition-all text-center flex items-center justify-center gap-2 border border-white/5 text-slate-300">
                   <svg class="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                       <path stroke-linecap="round" stroke-linejoin="round" d="M18 18.72a9.094 9.094 0 003.741-.479 3 3 0 00-4.682-2.72m.94 3.198l.001.031c0 .225-.012.447-.037.666A11.944 11.944 0 0112 21c-2.17 0-4.207-.576-5.963-1.584A6.062 6.062 0 016 18.719m12 0a5.998 5.998 0 00-12 0m12 0a5.998 5.998 0 00-12 0m12 0a5.998 5.998 0 00-12 0M12 12a4.5 4.5 0 100-9 4.5 4.5 0 000 9zm0 0l.001.031c0 .225-.012.447-.037.666A11.944 11.944 0 0112 21c-2.17 0-4.207-.576-5.963-1.584A6.062 6.062 0 016 18.719m12 0a5.998 5.998 0 00-12 0m12 0a5.998 5.998 0 00-12 0" />
                   </svg>
                   Group
                </a>
            </div>

            <div class="music-player-card glass-panel mt-6 max-w-2xl mx-auto rounded-2xl p-4 shadow-xl relative overflow-hidden border border-white/5">
                <audio id="audioElement"></audio>
                <div class="flex items-center justify-between gap-4">
                    <div class="flex items-center gap-4 flex-1 min-w-0">
                        <div class="relative w-14 h-14 rounded-xl overflow-hidden bg-black/50 flex-shrink-0 border border-white/10 shadow-md">
                            <img id="musicCoverImg" src="" alt="Cover" class="w-full h-full object-cover">
                        </div>
                        <div class="flex-1 min-w-0 text-left">
                            <h3 id="musicTitle" class="music-text-title text-white font-bold text-[13px] tracking-wide truncate m-0 uppercase">Loading...</h3>
                            <p id="musicArtist" class="music-text-artist text-slate-400 text-[11px] font-medium truncate mt-0.5">-</p>
                            <div class="flex items-center gap-2 mt-2">
                                <span id="currentTime" class="text-[9px] text-slate-400 font-mono w-7 text-left">0:00</span>
                                <div id="progressContainer" class="music-progress-bar-bg flex-1 h-1 bg-white/10 rounded-full relative cursor-pointer">
                                    <div id="progressBar" class="h-full bg-cyan-400 rounded-full w-0 transition-all duration-300"></div>
                                </div>
                                <span id="totalDuration" class="text-[9px] text-slate-400 font-mono w-7 text-right">0:00</span>
                            </div>
                        </div>
                    </div>
                    <div class="flex items-center gap-1.5 flex-shrink-0">
                        <button id="prevBtn" class="music-btn-nav w-8 h-8 flex items-center justify-center glass-panel rounded-lg text-slate-300 hover:text-white transition-all active:scale-95 border border-white/5">
                            <svg class="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 24 24"><path d="M6 6h2v12H6zm3.5 6l8.5 6V6z"/></svg>
                        </button>
                        <button id="playBtn" class="music-btn-nav w-10 h-10 flex items-center justify-center glass-panel rounded-lg text-slate-300 hover:text-white transition-all active:scale-95 border border-white/5">
                            <svg id="playIcon" class="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>
                        </button>
                        <button id="nextBtn" class="music-btn-nav w-8 h-8 flex items-center justify-center glass-panel rounded-lg text-slate-300 hover:text-white transition-all active:scale-95 border border-white/5">
                            <svg class="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 24 24"><path d="M16 6h2v12h-2zm-10.5 12l8.5-6-8.5-6z"/></svg>
                        </button>
                        <button id="playlistToggleBtn" class="music-btn-nav w-8 h-8 flex items-center justify-center glass-panel rounded-lg text-slate-300 hover:text-white transition-all active:scale-95 border border-white/5">
                            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M4 6h16M4 12h16M4 18h16"/></svg>
                        </button>
                    </div>
                </div>
                <div id="playlistPanel" class="music-playlist-border hidden mt-4 pt-4 border-t border-white/10 max-h-40 overflow-y-auto space-y-1 light-mode:border-slate-200"></div>
            </div>
            
        </header>

        <div class="mb-8">
            <div class="relative max-w-4xl mx-auto">
                <input 
                    type="text" 
                    id="searchInput" 
                    placeholder="Cari endpoint berdasarkan nama, path, atau kategori..."
                    class="search-input w-full px-4 py-3.5 pl-11 text-xs rounded-xl focus:outline-none focus:border-cyan-500 transition-all font-mono glass-panel border border-white/5 text-white placeholder-slate-400 light-mode:text-slate-900 light-mode:placeholder-slate-500 light-mode:focus:border-cyan-600"
                >
                <svg class="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                </svg>
            </div>
            <div id="categoryFilters" class="category-scroll flex flex-nowrap gap-3 mt-4 justify-start overflow-x-auto pb-3 scrollbar-hide max-w-4xl mx-auto"></div>
        </div>

        <div id="noResults" class="text-center py-12 hidden">
            <div class="flex justify-center mb-3">
                <svg class="w-12 h-12 text-amber-500" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
            </div>
            <h3 id="no-results-title" class="text-sm font-bold mb-1 text-white">Endpoint tidak ditemukan</h3>
            <p id="no-results-desc" class="text-xs text-slate-400 light-mode:text-slate-500">Coba gunakan kata kunci lain</p>
        </div>

        <div id="apiList" class="space-y-4 max-w-4xl mx-auto"></div>

        <footer id="siteFooter" class="mt-16 pt-6 border-t border-white/5 text-center text-[11px] text-slate-500">
            © XS-Pedia
        </footer>
    </div>

    <div id="imageLightbox" class="fixed inset-0 bg-black/95 z-[100] hidden flex items-center justify-center p-4 opacity-0 transition-opacity duration-300 backdrop-blur-xs cursor-zoom-out">
        <div class="relative max-w-4xl max-h-[90vh] flex items-center justify-center">
            <img id="lightboxImage" src="" alt="Preview" class="max-w-full max-h-[85vh] rounded-lg shadow-2xl object-contain scale-95 transition-transform duration-300" />
            <button id="closeLightbox" class="absolute -top-12 right-0 text-white hover:text-cyan-400 transition-colors focus:outline-none flex items-center gap-1 bg-black/50 px-3 py-1.5 rounded-lg border border-white/10 text-xs font-mono">
                ✕ Close
            </button>
        </div>
    </div>
    
<script src="https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.30.1/moment.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.30.1/locale/id.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/moment-timezone/0.5.45/moment-timezone-with-data.min.js"></script>

<script class="notranslate" translate="no">
    window.musicPlaylist = ${JSON.stringify(playlist)};
    const displayApiKey = "${req.user ? (req.user.apikey) : 'Silakan Login'}";
</script>
<script src="script.js"></script>

<script>
        function copyText(text, label) {
            if (navigator.clipboard) {
                navigator.clipboard.writeText(text).then(() => {
                    alert((label || 'Teks') + ' berhasil disalin!');
                });
            }
        }

        function openProfilePopup() {
            const popup = document.getElementById('profilePopup');
            const menu = document.getElementById('bioDropdown');
            if (!popup) return;
            if (menu) menu.classList.add('translate-x-full');
            popup.classList.remove('hidden');
            popup.style.display = 'block';
            popup.setAttribute('aria-hidden', 'false');
            document.body.classList.add('overflow-hidden');
            fetchUserProfile();
        }

        function closeProfilePopup() {
            const popup = document.getElementById('profilePopup');
            if (!popup) return;
            popup.classList.add('hidden');
            popup.style.display = 'none';
            popup.setAttribute('aria-hidden', 'true');
            document.body.classList.remove('overflow-hidden');
        }

        function showWelcomePopup() {
            const popup = document.getElementById('welcomePopup');
            const closeBtn = document.getElementById('closePopupBtn');
            if (popup) {
                popup.classList.remove('hidden');
                document.body.classList.add('overflow-hidden');
            }
            if (closeBtn) {
                closeBtn.onclick = () => {
                    popup.classList.add('hidden');
                    document.body.classList.remove('overflow-hidden');
                };
            }
        }

        function setRoleTheme(roleName) {
            const planText = document.getElementById('userPlanText');
            const vipCustomBox = document.getElementById('vipCustomKeyBox');
            if (!planText) return;

            const role = (roleName || '').toLowerCase();

            if (role.includes('vip')) {
                planText.textContent = 'VIP';
                planText.setAttribute('fill', '#00f3ff');
                if (vipCustomBox) vipCustomBox.classList.remove('hidden');
            } else if (role.includes('premium')) {
                planText.textContent = 'PREM';
                planText.setAttribute('fill', '#fbbf24');
                if (vipCustomBox) vipCustomBox.classList.add('hidden');
            } else {
                planText.textContent = 'FREE';
                planText.setAttribute('fill', '#34d399');
                if (vipCustomBox) vipCustomBox.classList.add('hidden');
            }
        }

        async function saveCustomApiKey() {
            const input = document.getElementById('customApiKeyInput');
            if (!input || !input.value.trim()) {
                alert('Ketik API Key kustom yang diinginkan terlebih dahulu!');
                return;
            }

            try {
                const response = await fetch('/api/user/custom-apikey', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ customKey: input.value.trim() })
                });

                const resData = await response.json();
                if (resData.status) {
                    alert(resData.message);
                    document.getElementById('userApiKey').innerText = resData.apikey;
                    input.value = '';
                } else {
                    alert(resData.message || 'Gagal mengubah API Key.');
                }
            } catch (err) {
                alert('Terjadi kesalahan koneksi saat menyimpan API Key.');
            }
        }

        async function uploadAvatarFile(input) {
            if (!input.files || !input.files[0]) return;

            const file = input.files[0];
            if (!file.type.startsWith('image/')) return;

            const userAvatarImg = document.getElementById('userAvatar');
            const sidebarAvatarImg = document.getElementById('sidebarUserAvatar');
            const oldSrc = userAvatarImg ? userAvatarImg.src : '';

            // Preview langsung agar gambar baru langsung terlihat sebelum response server.
            const previewUrl = URL.createObjectURL(file);
            document.querySelectorAll('#userAvatar, #sidebarUserAvatar').forEach(img => {
                img.style.display = '';
                img.style.opacity = '0.55';
                img.src = previewUrl;
            });

            const formData = new FormData();
            formData.append('avatar', file);

            try {
                const response = await fetch('/api/user/update-avatar', {
                    method: 'POST',
                    body: formData,
                    credentials: 'same-origin'
                });

                const result = await response.json();
                if (!response.ok || !result.status) throw new Error(result.message || 'Gagal mengunggah avatar.');

                const newAvatarUrl = result.avatar;
                document.querySelectorAll('#userAvatar, #sidebarUserAvatar').forEach(img => {
                    img.style.display = '';
                    img.style.opacity = '1';
                    img.src = newAvatarUrl || previewUrl;
                });

                try { sessionStorage.setItem('latestProfileAvatar', newAvatarUrl || previewUrl); } catch (_) {}

                if (typeof Swal !== 'undefined') {
                    Swal.fire({
                        icon: 'success',
                        title: 'Avatar diperbarui',
                        text: 'Foto profil berhasil disimpan.',
                        confirmButtonText: 'OKE',
                        confirmButtonColor: '#4f815f'
                    });
                } else {
                    alert('Foto profil berhasil diperbarui.');
                }
            } catch (error) {
                console.error('Error uploading avatar:', error);
                document.querySelectorAll('#userAvatar, #sidebarUserAvatar').forEach(img => {
                    img.style.opacity = '1';
                    img.src = oldSrc || img.src;
                });
                alert(error.message || 'Terjadi kesalahan saat mengunggah foto.');
            } finally {
                if (userAvatarImg) userAvatarImg.style.opacity = '1';
                if (sidebarAvatarImg) sidebarAvatarImg.style.opacity = '1';
                input.value = '';
                setTimeout(() => URL.revokeObjectURL(previewUrl), 1500);
            }
        }

        
        function syncProfileMirrorFields() {
            const name = document.getElementById('userName')?.innerText || '';
            const email = document.getElementById('userEmail')?.innerText || '';
            const usernameEl = document.getElementById('userUsername');
            const emailRowEl = document.getElementById('userEmailRow');
            if (usernameEl && name) usernameEl.innerText = name;
            if (emailRowEl && email) emailRowEl.innerText = email;
        }
        document.addEventListener('DOMContentLoaded', () => {
            const watcher = new MutationObserver(syncProfileMirrorFields);
            const n = document.getElementById('userName');
            const e = document.getElementById('userEmail');
            if (n) watcher.observe(n, {childList:true, subtree:true, characterData:true});
            if (e) watcher.observe(e, {childList:true, subtree:true, characterData:true});
            syncProfileMirrorFields();
        });

function fetchUserProfile() {
            fetch('/api/user-status')
                .then(res => res.json())
                .then(data => {
                    if (data.loggedIn && data.user) {
                        const latestAvatar = data.user.avatar || sessionStorage.getItem('latestProfileAvatar') || 'https://arulz-xd.my.id/files/X1F0Cn.png';

                        document.querySelectorAll('#userAvatar, #sidebarUserAvatar').forEach(img => {
                            if (img) img.src = latestAvatar;
                        });

                        document.getElementById('userName').innerText = data.user.username || 'User';
                        document.getElementById('userEmail').innerText = data.user.email || 'no-email@mail.com';
                        
                        const userKey = data.user.apikey || '';
                        document.getElementById('userApiKey').innerText = userKey || 'No Key Found';
                                                
                        setRoleTheme(data.user.role || 'Free User');

                        fetchUserActivityLogs(userKey);
                        if (typeof fetchAndUpdateUserLimit === 'function') {
                            fetchAndUpdateUserLimit();
                        }
                    }
                })
                .catch((err) => {
                    console.error("Gagal sinkronisasi profile:", err);
                });
        }

        function escapeActivityText(value) {
            return String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
        }

        function fetchUserActivityLogs() {
            const container = document.getElementById('activityLogsContainer');
            if (!container) return;

            fetch('/api/user-activity', { credentials: 'same-origin' })
              .then(res => res.json())
              .then(resData => {
                  if (resData.status && Array.isArray(resData.data) && resData.data.length > 0) {
                      container.innerHTML = resData.data.slice(0, 12).map(item => {
                          // Kompatibel dengan format string lama dan format object baru.
                          if (typeof item === 'string') {
                              const match = item.match(/^\[(.*?)\] \[(OK|ERR)\] \[(.*?)\] : (.*)$/);
                              if (!match) {
                                  return '<div class="profile-log"><span class="profile-log-method">GET</span><span class="profile-log-endpoint">' + escapeActivityText(item) + '</span><span></span></div>';
                              }
                              return '<div class="profile-log"><span class="profile-log-method">' + escapeActivityText(match[3]) + '</span><span class="profile-log-endpoint">' + escapeActivityText(match[4]) + '</span><span class="profile-log-meta"><span class="profile-log-status ' + (match[2] === 'OK' ? 'ok' : 'err') + '">' + escapeActivityText(match[2]) + '</span><span class="profile-log-date">' + escapeActivityText(match[1]) + '</span></span></div>';
                          }

                          const method = escapeActivityText(item.method || 'GET');
                          const endpoint = escapeActivityText(item.endpoint || '/');
                          const status = escapeActivityText(item.status || ((Number(item.statusCode) >= 200 && Number(item.statusCode) < 300) ? 'OK' : 'ERR'));
                          const statusClass = status === 'OK' ? 'ok' : 'err';
                          const time = escapeActivityText(item.time || '');
                          const date = escapeActivityText(item.date || '');
                          return '<div class="profile-log"><span class="profile-log-method">' + method + '</span><span class="profile-log-endpoint" title="' + endpoint + '">' + endpoint + '</span><span class="profile-log-meta"><span class="profile-log-status ' + statusClass + '">' + status + (item.statusCode ? ' ' + escapeActivityText(item.statusCode) : '') + '</span><span class="profile-log-date">' + time + (time && date ? ' - ' : '') + date + '</span></span></div>';
                      }).join('');
                  } else {
                      container.innerHTML = '<div class="profile-log"><span class="profile-log-method">GET</span><span class="profile-log-endpoint">Belum ada aktivitas request</span><span></span></div>';
                  }
              })
              .catch(() => {
                  container.innerHTML = '<div class="profile-log"><span class="profile-log-method">!</span><span class="profile-log-endpoint">Gagal memuat aktivitas</span><span></span></div>';
              });
        }

        document.addEventListener('DOMContentLoaded', () => {
            fetchUserProfile();
        });

        function getPageDisplayName() {
            const path = window.location.pathname;
            let fileName = path.split('/').pop().replace('.html', '').toLowerCase();

            if (!fileName || fileName === '' || fileName === 'index') return 'Home';

            const pageMap = {
                'home': 'Home',
                'docs': 'Dokumentasi',
                'doc': 'Dokumentasi',
                'status': 'Status Server',
                'store': 'Store API',
                'changelog': 'Changelog',
                'uploader': 'Uploader File',
                'pastecode': 'Pastecode',
                'feedback': 'Feedback',
                'privacy': 'Kebijakan Privasi',
                'support': 'Dukungan Support',
                'login': 'Halaman Login'
            };

            if (pageMap[fileName]) return pageMap[fileName];
            return fileName.charAt(0).toUpperCase() + fileName.slice(1);
        }

        const pageName = getPageDisplayName();
        const loaderTitleEl = document.getElementById('loader-title-text');
        if (loaderTitleEl) {
            loaderTitleEl.innerHTML = 'Memuat ' + pageName + '<span class="animated-dots"></span>';
        }

        let currentProgress = 0;
        let hasFinishedLoading = false;
        const progressFill = document.getElementById('loader-progress-fill');
        const percentageText = document.getElementById('loader-percentage');
        const loaderOverlay = document.getElementById('cyber-loader-overlay');

        function updateProgress(targetVal) {
            currentProgress = Math.min(Math.max(currentProgress, targetVal), 100);
            if (progressFill) progressFill.style.width = currentProgress + '%';
            if (percentageText) percentageText.innerText = Math.floor(currentProgress) + '%';
        }

        let progressInterval = null;
        function hideLoaderImmediately() {
            if (loaderOverlay) {
                loaderOverlay.classList.add('fade-out');
                loaderOverlay.style.display = 'none';
            }
        }

        function finishLoader() {
            if (hasFinishedLoading) return;
            hasFinishedLoading = true;
            if (progressInterval) clearInterval(progressInterval);
            updateProgress(100);
            try { sessionStorage.setItem('xs_pedia_loader_seen', '1'); } catch (_) {}
            setTimeout(() => {
                if (loaderOverlay) {
                    loaderOverlay.classList.add('fade-out');
                    setTimeout(() => { loaderOverlay.style.display = 'none'; }, 650);
                }
            }, 180);
        }

        let hasSeenLoader = false;
        try { hasSeenLoader = sessionStorage.getItem('xs_pedia_loader_seen') === '1'; } catch (_) {}
        if (hasSeenLoader) {
            hideLoaderImmediately();
            hasFinishedLoading = true;
        } else {
            progressInterval = setInterval(() => {
                if (currentProgress < 85) updateProgress(currentProgress + Math.random() * 12 + 5);
            }, 120);
            window.addEventListener('load', finishLoader, { once:true });
            setTimeout(finishLoader, 1500);
        }
</script>

</body>
</html>
    `);
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

module.exports = app;
