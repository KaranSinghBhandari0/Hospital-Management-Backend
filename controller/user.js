const bcrypt = require('bcrypt');
const User = require('../models/user');
const jwt = require('jsonwebtoken');

// cookies option
const cookieOptions = {
    httpOnly: true,
    secure: true,
    sameSite: "None",
    maxAge: 24 * 60 * 60 * 1000,
};

// helper function to find curr user
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

const signup = async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Check if the user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ msg: 'e-mail already exists' });
        }

        // checking for strong password
        if (password.length < 6) {
            return res.status(400).json({ msg: 'Password must be at least 6 characters long' });
        }

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create a new user
        const newUser = new User({
            username,
            email,
            password: hashedPassword,
        });

        // Generate a JWT token
        const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET);
        // store in cookies
        res.cookie('token', token, cookieOptions);

        // Save the user to the database
        await newUser.save();

        res.status(200).json({ msg: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ msg: 'Server error', error: error.message });
    }
};

const login = async (req, res) => {
    try {
        const { email, password } = req.body;

        // Checking email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'Invalid email' });
        }

        // Compare passwords
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid password' });
        }

        // Generate a JWT token
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
        // store in cookies
        res.cookie('token', token, cookieOptions);

        res.status(200).json({ msg: 'Login successful'});
    } catch (error) {
        res.status(500).json({ msg: 'Server error', error: error.message });
    }
};

const logout = async (req,res) => {
    res.clearCookie('token' , {
        httpOnly: true,
        secure: true,
        sameSite: "None",
    });
    res.status(200).json({msg: 'logout successfull'})
}

const isAuth = (req,res) => {
    res.status(200).json({msg : 'user is authenticated'})
}

const getDetails = async (req, res) => {
    try {
        const currUser = await findCurrUser(req, res);

        return res.status(200).json({ user: currUser });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ msg: 'Server error', error: error.message });
    }
}

const updateDetails = async (req, res) => {
    try {
        let {username,dob,gender} = req.body;

        const currUser = await findCurrUser(req, res);
        currUser.gender = gender;
        currUser.dob = dob;
        currUser.username = username;

        await currUser.save();

        res.status(200).json({ msg: 'Profile updated successfully!', user: currUser });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ msg: 'Server error', error: error.message });
    }
}

const getAllUsers = async (req, res) => {
    try {
        const allUsers = await User.find();
        const totalUsers = allUsers.length;

        res.status(200).json({ totalUsers });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ msg: 'Server error', error: error.message });
    }
}

module.exports = { signup, login, logout, isAuth, getDetails, updateDetails, getAllUsers };
