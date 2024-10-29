const mongoose = require('mongoose');
const validator = require('validator');

// User schema
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, "Name is required"]
    },
    email: {
        type: String,
        required: [true, "Email is required"],
        unique: true,
        validate: [validator.isEmail, "Provide A Valid Email!"]
    },
    password: {
        type: String,
        required: [true, "Password is required"],
        minlength: [6, "Password must be at least 6 characters long"]
    },
    gender: {
        type: String,
        enum: ['Male', 'Female', 'Other'],
        default: 'Other'
    },
    dob: {
        type: String,
        default: 'N/A'
    }
});

const User = mongoose.model("User", userSchema);
module.exports = User;
