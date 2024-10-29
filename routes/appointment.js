const express = require('express');
const router = express.Router();
const {bookAppointment, getAppointments, cancelAppointment, getAllAppointments, confirmAppointment, cancelDocAppointment } = require('../controller/appointment');
const {isAuthenticated, isDoctorAuthenticated} = require('../middlewares/auth');

router.post("/bookAppointment", isAuthenticated, bookAppointment);
router.get("/getAppointments", getAppointments);
router.get("/cancelAppointment/:appointmentId", cancelAppointment);    // from user side
router.get("/allAppointments", getAllAppointments);
router.get("/confirmAppointment/:id", isDoctorAuthenticated, confirmAppointment);
router.get("/cancelDocAppointment/:id", isDoctorAuthenticated, cancelDocAppointment); // from doctor side

module.exports = router;