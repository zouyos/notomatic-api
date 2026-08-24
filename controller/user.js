const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

require('dotenv').config();

const User = require('../model/User');

exports.signup = (req, res, next) => {
  bcrypt
    .hash(req.body.password, 10)
    .then((hash) => {
      const user = new User({ email: req.body.email, password: hash });
      user
        .save()
        .then(() => res.status(201).json({ message: 'User created' }))
        .catch((err) => res.status(500).json({ err }));
    })
    .catch((err) => res.status(500).json({ err }));
};

exports.login = (req, res, next) => {
  User.findOne({ email: req.body.email })
    .then((user) => {
      if (!user) {
        return res.status(401).json({ message: 'Incorrect email or password' });
      }
      bcrypt
        .compare(req.body.password, user.password)
        .then((valid) => {
          if (!valid) {
            return res
              .status(401)
              .json({ message: 'Incorrect email or password' });
          }
          const token = jwt.sign(
            { userId: user.id },
            process.env.TOKEN_SECRET,
            {
              expiresIn: '24h',
            },
          );
          res
            .status(200)
            .cookie('token', token, {
              sameSite: 'None',
              secure: true,
              httpOnly: true,
            })
            .json({
              message: 'Login successful',
            });
        })
        .catch((error) => res.status(500).json({ error }));
    })
    .catch((error) => res.status(500).json({ error }));
};

exports.checkAuth = (req, res) => {
  res.status(200).json({
    userId: req.auth.userId,
  });
};

exports.logout = (req, res) => {
  res.clearCookie('token', {
    sameSite: 'None',
    secure: true,
    httpOnly: true,
  });

  res.status(200).json({
    message: 'Logout successful',
  });
};

exports.requestPasswordReset = (req, res, next) => {
  const { email } = req.body;

  User.findOne({ email })
    .then((user) => {
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      const token = crypto.randomBytes(20).toString('hex');

      user.resetPasswordToken = token;
      user.resetPasswordExpires = Date.now() + 3600000;

      return user.save().then(() => token);
    })
    .then((token) => {
      const transporter = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS,
        },
      });

      const mailOptions = {
        to: req.body.email,
        from: process.env.EMAIL_USER,
        subject: 'Password Reset',
        text: `You are receiving this because you have requested the reset of the password for your account.\n\n
        Please click on the following link, or paste this into your browser to complete the process:\n\n
        https://${process.env.FRONT_END_DOMAIN}/reset/${token}\n\n
        If you did not request this, please ignore this email and your password will remain unchanged.\n`,
      };

      return transporter.sendMail(mailOptions);
    })
    .then(() => res.status(200).json({ message: 'Password reset link sent' }))
    .catch((error) => {
      console.error('Error sending email:', error);
      res.status(500).json({ error: 'Error sending email' });
    });
};

exports.resetPassword = (req, res, next) => {
  const { token } = req.params;
  const { password } = req.body;

  User.findOne({
    resetPasswordToken: token,
    resetPasswordExpires: { $gt: Date.now() },
  })
    .then((user) => {
      if (!user) {
        return res
          .status(400)
          .json({ message: 'Password reset token is invalid or has expired' });
      }

      bcrypt
        .hash(password, 10)
        .then((hash) => {
          user.password = hash;
          user.resetPasswordToken = undefined;
          user.resetPasswordExpires = undefined;

          return user.save();
        })
        .then(() =>
          res.status(200).json({ message: 'Password has been reset' }),
        )
        .catch((error) => res.status(500).json({ error }));
    })
    .catch((error) => res.status(500).json({ error }));
};
