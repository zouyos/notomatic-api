const jwt = require('jsonwebtoken');
const Cookies = require('cookies');
require('dotenv').config();

module.exports = (req, res, next) => {
  try {
    const cookies = new Cookies(req, res);
    const token = cookies.get('token');

    if (!token) {
      return res.status(401).json({
        error: 'Authentication failed',
      });
    }

    const decodedToken = jwt.verify(token, process.env.TOKEN_SECRET);

    if (!decodedToken.userId) {
      return res.status(401).json({
        error: 'Authentication failed',
      });
    }

    req.auth = {
      userId: decodedToken.userId,
    };

    next();
  } catch (err) {
    return res.status(401).json({
      error: 'Authentication failed',
    });
  }
};
