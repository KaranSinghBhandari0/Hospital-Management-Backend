const express = require('express');
const router = express.Router();
const { signup, login, logout, isAuth, getDetails, updateDetails, getAllUsers } = require('../controller/user');
const {isAuthenticated} = require('../middlewares/auth');

router.post("/signup", signup);
router.post("/login", login);
router.get("/logout", logout);
router.get("/isAuth", isAuthenticated, isAuth);
router.get("/getDetails", getDetails);
router.post("/updateDetails", updateDetails);
router.get("/allUsers", getAllUsers);

module.exports = router;