const jwt = require('jsonwebtoken')

const cookieOptions = {
    httpOnly: true,
    secure: true,
    sameSite: "None",
    maxAge: 60 * 60 * 1000,
};

const login = (req,res) => {
    try {
        let {email , password} = req.body;
        if(email == process.env.ADMIN_EMAIL && password == process.env.ADMIN_PASSWORD) {
            // Generate a JWT token and store in cookies
            const admin_token = jwt.sign({ id: process.env.ADMIN_ID }, process.env.JWT_SECRET);
            res.cookie('admin_token', admin_token, cookieOptions);

            return res.status(200).json({msg:'login successful'});
        }
        res.status(401).json({msg:'wrong creadentials'})
    } catch (error) {
        console.log(error);
        res.status(500).json({msg:'Server Error'})
    }
}

const logout = async (req,res) => {
    res.clearCookie('admin_token', {
        httpOnly: true,
        secure: true,
        sameSite: "None",
    });
    res.status(200).json({msg: 'logout successful'})
}

const isAdmin = (req,res) => {
    res.status(200).json({ msg: 'user is authorized'});
}

module.exports = { login, isAdmin, logout };