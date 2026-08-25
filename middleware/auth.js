const jwt = require('jsonwebtoken');
const Cookies = require('cookies');
require('dotenv').config();

module.exports = (req, res, next) => {
  try {
    const cookies = new Cookies(req, res);
    const token = cookies.get('token');

    console.log('=== AUTH MIDDLEWARE ===');
    console.log('Origin:', req.headers.origin);
    console.log('Cookie header exists:', !!req.headers.cookie);
    console.log('Token exists:', !!token);

    if (!token) {
      console.log('AUTH FAILED: no token');
      return res.status(401).json({ error: 'Authentication failed' });
    }

    const decodedToken = jwt.verify(token, process.env.TOKEN_SECRET);

    console.log('JWT valid:', true);
    console.log('User ID:', decodedToken.userId);

    req.auth = {
      userId: decodedToken.userId,
    };

    next();
  } catch (err) {
    console.error('AUTH FAILED:', err.message);
    res.status(401).json({ error: 'Authentication failed' });
  }
};
