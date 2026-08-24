const express = require('express');
const router = express.Router();

const userCtrl = require('../controller/user');
const auth = require('../middleware/auth');

const { body } = require('express-validator');
const validate = require('../middleware/validation');

const validationRules = [
  body('email').isEmail().withMessage('Incorrect email format'),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password too short (min 6 characters)')
    .isLength({ max: 30 })
    .withMessage('Password too long (max 30 characters)')
    .matches(/^(?=.*[A-Z])[A-Za-z0-9]+$/)
    .withMessage('Only letters (at least one uppercase) and numbers allowed'),
  validate,
];

router.post('/signup', validationRules, userCtrl.signup);
router.post('/login', validationRules, userCtrl.login);
router.get('/check', auth, userCtrl.checkAuth);
router.post('/logout', auth, userCtrl.logout);
router.post('/request-password-reset', userCtrl.requestPasswordReset);
router.post('/reset/:token', validationRules, userCtrl.resetPassword);

module.exports = router;
