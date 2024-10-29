const Doctor = require('../models/doctor');
const Appointment = require('../models/appointment');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cloudinary = require('../cloudConfig')

// cookies option
const cookieOptions = {
    httpOnly: true,
    secure: true,
    sameSite: "None",
    maxAge: 60 * 60 * 1000,
};

const findCurrDoctor = async (req, res) => {
    const docToken = req.cookies.docToken;

    if (!docToken) {
        return res.status(401).json({ msg: 'Not authenticated' });
    }

    try {
        const decoded = jwt.verify(docToken, process.env.JWT_SECRET);
        const currDoctor = await Doctor.findById(decoded.id);

        if (!currDoctor) {
            return res.status(404).json({ msg: 'Doctor not found' });
        }

        res.status(200).json({currDoctor});
    } catch (error) {
        return res.status(401).json({ msg: 'Invalid or expired token' });
    }
}

const filterDoctors = async (req, res) => {
    try {
        const { speciality } = req.params;
        const doctors = await Doctor.find({ speciality: speciality });
        res.status(200).json({ doctors });
    } catch (error) {
        console.log(error);
        res.status(500).json({ msg: error.message });
    }
}

const login = async (req, res) => {
    try {
        const { email, password } = req.body;

        // Checking email
        const doctor = await Doctor.findOne({ email });
        if (!doctor) {
            return res.status(400).json({ msg: 'Invalid email' });
        }

        // Compare passwords
        const isMatch = await bcrypt.compare(password, doctor.password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid password' });
        }

        // Generate a JWT token
        const docToken = jwt.sign({ id: doctor._id }, process.env.JWT_SECRET);
        // store in cookies
        res.cookie('docToken', docToken, cookieOptions);

        res.status(200).json({ msg: 'Login successful' , doctor});
    } catch (error) {
        res.status(500).json({ msg: 'Server error', error: error.message });
    }
};

const logout = async (req,res) => {
    res.clearCookie('docToken' , {
        httpOnly: true,
        secure: true,
        sameSite: "None",
    });
    res.status(200).json({msg: 'logout successfull'})
}

const isDoctorAuth = (req,res) => {
    res.status(200).json({ msg: 'Doctor is authorized'});
}

const addNewDoctor = async (req,res) => {
    try {
        const { name, email, password, experience, fees, speciality, degree, address, about } = req.body;
        // Check if the doctor already exists
        const existingDoctor = await Doctor.findOne({ email });
        if(existingDoctor) {
            return res.status(400).json({ msg: 'e-mail already exists' });
        }

        // checking for strong password
        if (password.length < 6) {
            return res.status(400).json({ msg: 'Password must be at least 6 characters long' });
        }

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // uploading image to cloudinary
        const result = await cloudinary.uploader.upload(req.file.path);

        // saving doctor in DB
        const newDoctor = new Doctor({
            name,
            email,
            password : hashedPassword,
            experience,
            fees,
            speciality,
            degree,
            address,
            about,
            image: result.secure_url,
        });
        await newDoctor.save();

        res.status(200).json({msg: 'doctor added', doctor: newDoctor});
    } catch (error) {
        console.log(error);
        res.status(500).json({msg:error.message})
    }
}

const getDoctors = async (req,res) => {
    try {
        const doctors = await Doctor.find();
        res.status(200).json({doctors});
    } catch (error) {
        console.log(error);
        res.status(500).json({msg:error.message})
    }
}

const getDoctorInfo = async (req,res) => {
    try {
        const { id } = req.params;
        const currDoctor = await Doctor.findById(id);

        if (!currDoctor) {
            return res.status(404).json({ message: 'No Doctor found' });
        }

        res.status(200).json({ doctor: currDoctor });
    } catch (error) {
        console.log(error);
        res.status(500).json({msg:error.message})
    }
}

const changeAvail = async (req, res) => {
    try {
        const { id } = req.params;
        const currDoctor = await Doctor.findById(id);

        if (!currDoctor) {
            return res.status(404).json({ message: 'No Doctor found' });
        }

        // Toggle the availability
        currDoctor.available = !currDoctor.available;
        await currDoctor.save();

        res.status(200).json({ msg: 'Availability changed', available: currDoctor.available });
    } catch (error) {
        console.log(error);
        res.status(500).json({ msg: error.message });
    }
};

const getDoctorAppointments = async (req, res) => {
    try {
        let {id} = req.params;

        const appointments = await Appointment.find({docId: id});
        return res.status(200).json({ appointments });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ msg: 'Server error', error: error.message });
    }
};

module.exports = { filterDoctors, login, logout, isDoctorAuth, findCurrDoctor, addNewDoctor, getDoctors, getDoctorInfo, changeAvail, getDoctorAppointments };
