const jwt = require('jsonwebtoken');

const isAuthenticated = (req, res, next) => {
  const token = req.cookies.token; // Get token from the cookie

  if (!token) {
    return res.status(401).json({ message: 'not authenticated' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};

const isAuthorized = (req,res,next) => {
  const admin_token = req.cookies.admin_token; // Get token from the cookie

  if (!admin_token) {
    return res.status(401).json({ message: 'not authenticated' });
  }

  try {
    const decoded = jwt.verify(admin_token, process.env.JWT_SECRET);
    if(decoded.id === process.env.ADMIN_ID) {
      next();
    }
  } catch (error) {
    return res.status(500).json({ message: 'Invalid or expired token' });
  }
}

const isDoctorAuthenticated = (req,res,next) => {
  const docToken = req.cookies.docToken; // Get token from the cookie

  if (!docToken) {
    return res.status(401).json({ message: 'not authenticated' });
  }

  try {
    const decoded = jwt.verify(docToken, process.env.JWT_SECRET);
    if(decoded) {
      req.doctor = decoded;
      next();
    }
  } catch (error) {
    return res.status(500).json({ message: 'Invalid or expired token' });
  }
}

module.exports = {isAuthenticated, isAuthorized, isDoctorAuthenticated};
