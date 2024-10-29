require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const connectDB = require('./connectDB');
const cors = require('cors');

const app = express();

app.use(
	cors({
	  origin: ['https://hospital-management-frontend-nu.vercel.app' , 'https://hospital-management-admin.vercel.app'],
	  method: ["GET", "POST", "DELETE", "PUT"],
	  credentials: true,
	})
);
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
	console.log("Listening on port " + PORT);
	connectDB();
});

app.get('/', (req, res) => {
    res.send('this is root');
});

// user routes
const user = require('./routes/user');
app.use("/user", user);

// admin routes
const admin = require('./routes/admin');
app.use('/admin', admin);

// doctor routes
const doctor = require('./routes/doctor');
app.use('/doctor', doctor);

// appointment routes
const appointment = require('./routes/appointment');
app.use('/appointment', appointment);