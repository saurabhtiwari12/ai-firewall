'use strict';

const express = require('express');
const { authenticate } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimiter');
const { validateUserCreation, validateLogin } = require('../middleware/validation');
const { register, login, refresh, getMe } = require('../controllers/authController');

const router = express.Router();

// POST /api/auth/register
router.post('/register', authLimiter, validateUserCreation, register);

// POST /api/auth/login
router.post('/login', authLimiter, validateLogin, login);

// POST /api/auth/refresh
router.post('/refresh', authLimiter, refresh);

// GET /api/auth/me
router.get('/me', authenticate, getMe);

module.exports = router;
