const mongoose = require('mongoose');

//appointment schema
const appointmentSchema = new mongoose.Schema({
    date: {
        type: Date,
    },
    time: {
        type: String,
    },
    day: {
        type: String,
    },
    fee : {
        type: Number,
    },
    status: {
        type: String,
        enum: ["pending", "confirmed", "cancelled", "completed"],
        default: "pending"
    },
    patientName: {
        type: String,
    },
    docId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Doctor',
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
    },
    docName: {
        type: String,
    },
    speciality: {
        type: String,
    },
    docImg: {
        type: String,
    },
    docAddress: {
        type: String,
    },
});

const Appointment = mongoose.model("Appointment", appointmentSchema);
module.exports = Appointment;
