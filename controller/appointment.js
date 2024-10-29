const User = require('../models/user');
const Doctor = require('../models/doctor');
const Appointment = require('../models/appointment');
const jwt = require('jsonwebtoken');

// Helper function to find the current user from token
const findCurrUser = async (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        throw new Error('Not authenticated');
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const currUser = await User.findById(decoded.id);

        if (!currUser) {
            throw new Error('User not found');
        }

        return currUser;
    } catch (error) {
        throw new Error('Invalid or expired token');
    }
};

// Book an appointment
const bookAppointment = async (req, res) => {
    try {
        const { date, time, day, docID } = req.body;
        const currUser = await findCurrUser(req, res);
        const currDoc = await Doctor.findById(docID);

        if(!currDoc.available) {
            return res.status(400).json({msg: 'Doctor is currently unavailable!'})
        }

        const newAppointment = new Appointment({
            date,
            time,
            day,
            fee: currDoc.fees,
            patientName: currUser.username,
            docName: currDoc.name,
            docId : docID,
            userId : currUser._id,
            specialty: currDoc.speciality,
            docImg: currDoc.image,
            docAddress: currDoc.address,
        })

        await newAppointment.save();

        return res.status(200).json({ msg: 'Appointment booked successfully' });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ msg: 'Server error', error: error.message });
    }
}

// Cancel an appointment
const cancelAppointment = async (req, res) => {
    try {
        const { appointmentId } = req.params;

        const appointment = await Appointment.findOneAndUpdate(
            { _id: appointmentId},
            { status: 'cancelled' },
            { new: true }
        );

        if(!appointment) {
            return res.status(404).json({ msg: 'Appointment not found or already cancelled' });
        }

        return res.status(200).json({ msg: 'Appointment cancelled successfully' });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ msg: 'Server error', error: error.message });
    }
};

// Get appointments for the current user
const getAppointments = async (req, res) => {
    try {
        const currUser = await findCurrUser(req, res);
        const appointments = await Appointment.find({ userId: currUser._id });

        return res.status(200).json({ appointments });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ msg: 'Server error', error: error.message });
    }
};

// Get all appointments
const getAllAppointments = async (req, res) => {
    try {
        const allAppointments = await Appointment.find();
        return res.status(200).json({ allAppointments });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ msg: 'Server error', error: error.message });
    }
};

// confirm appointment
const confirmAppointment = async (req, res) => {
    try {
        let {id} = req.params;
        const appointment = await Appointment.findById(id);
        appointment.status = 'confirmed';
        await appointment.save();
        return res.status(200).json({ msg: "Appointment confirmed" });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ msg: 'Server error', error: error.message });
    }
};

// Cancel an appointment from Doctor 
const cancelDocAppointment = async (req, res) => {
    try {
        const { id } = req.params;

        const appointment = await Appointment.findById(id);
        appointment.status = 'cancelled';
        await appointment.save();

        return res.status(200).json({ msg: 'Appointment cancelled' });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ msg: 'Server error', error: error.message });
    }
};

module.exports = { bookAppointment, getAppointments, cancelAppointment, getAllAppointments, confirmAppointment, cancelDocAppointment };
