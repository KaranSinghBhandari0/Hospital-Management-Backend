const express = require('express');
const router = express.Router();
const { login, logout, isAdmin } = require('../controller/admin');
const { isAuthorized } = require('../middlewares/auth');

router.post("/login", login);
router.get('/logout', logout);
router.get('/isAdmin', isAuthorized, isAdmin);

module.exports = router;