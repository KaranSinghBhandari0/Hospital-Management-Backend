const express = require('express');
const router = express.Router();
const { filterDoctors, login, logout, isDoctorAuth, findCurrDoctor, addNewDoctor, getDoctors, getDoctorInfo, changeAvail, getDoctorAppointments } = require('../controller/doctor');
const { isAuthorized, isDoctorAuthenticated } = require('../middlewares/auth');
const multer = require('multer');
const path = require("path");

// Multer config
const upload = multer({
    storage: multer.diskStorage({}),
    fileFilter: (req, file, cb) => {
      let ext = path.extname(file.originalname);  
      if (ext !== ".jpg" && ext !== ".jpeg" && ext !== ".png" && ext !== ".webp") {
        cb(new Error("File type is not supported"), false);
        return;
      }
      cb(null, true);
    },
});

router.post("/login", login);
router.get("/logout", logout);
router.get("/isAuth" , isDoctorAuthenticated, isDoctorAuth);
router.get("/relatedDoctors/:speciality", filterDoctors);
router.get("/getDoctor" , findCurrDoctor);
router.post('/addNewDoctor', isAuthorized, upload.single('image'),  addNewDoctor);
router.get('/getDoctors', getDoctors);
router.get('/getDoctorInfo/:id', getDoctorInfo);
router.get('/changeAvail/:id', changeAvail);
router.get("/appointments/:id", getDoctorAppointments);

module.exports = router;
