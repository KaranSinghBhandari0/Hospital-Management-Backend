const mongoose = require('mongoose');
const validator = require('validator');

const doctorSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, "Doctor's name is required"],
    },
    email: {
        type: String,
        required: [true, "Email is required"],
        unique: true,
        validate: [validator.isEmail, "Provide A Valid Email!"],
    },
    password: {
        type: String,
        required: [true, "Password is required"],
        minlength: [6, "Password must be at least 6 characters long"],
    },
    image: {
        type: String,
        required: [true, "Image URL is required"],
    },
    speciality: {
        type: String,
        required: [true, "Speciality is required"],
    },
    degree: {
        type: String,
        required: [true, "Degree is required"],
    },
    experience: {
        type: String,
        required: [true, "Experience is required"],
        min: [0, "Experience cannot be less than 0 years"],
    },
    about: {
        type: String,
        required: [true, "About section is required"],
    },
    fees: {
        type: Number,
        required: [true, "Consultation fees are required"],
        min: [0, "Fees cannot be negative"],
    },
    address: {
        type: String,
        required: [true, "Address is required"],
    },
    available: {
        type: Boolean,
        default: true,
        required: true,
    },
});

const Doctor = mongoose.model("Doctor", doctorSchema);
module.exports = Doctor;
