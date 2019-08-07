const express = require('express');
const router = express.Router();
const auth = require('../../middleware/auth');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { check, validationResult } = require('express-validator');
const config = require('config');
const crypto = require('crypto');

const User = require('../../models/User');

// @route   GET api/auth
// @desc    Get logged in user
// @access  Private
router.get('/', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch (error) {
    console.error(error.message);
    res.status(500).send('Server error');
  }
});

// @route   POST api/auth
// @desc    Authenticate user and get token
// @access  Public
router.post(
  '/',
  [
    check('email', 'Email is required').isEmail(),
    check('password', 'Password is required').exists()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;
    try {
      let user = await User.findOne({ email });
      if (!user) {
        return res
          .status(400)
          .json({ errors: [{ msg: 'Invalid credentials' }] });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res
          .status(400)
          .json({ errors: [{ msg: 'Invalid credentials' }] });
      }

      const payload = {
        user: {
          id: user.id
        }
      };

      jwt.sign(
        payload,
        config.get('jwtSecret'),
        { expiresIn: 360000 }, // TODO change to 3600 later
        (err, token) => {
          if (err) {
            throw err;
          }
          res.json({ token });
        }
      );
    } catch (error) {
      console.error(error.message);
      res.status(500).send('Server error');
    }
  }
);

// @route   POST /api/auth/change-password
// @desc    Change the password for the logged in user
// @access  Private
router.post(
  '/change-password',
  [
    auth,
    [
      check('oldPassword', 'Old password is required')
        .not()
        .isEmpty(),
      check(
        'newPassword',
        'Please enter a password with at least 8 characters'
      ).isLength({ min: 8 })
    ]
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { oldPassword, newPassword, newPassword2 } = req.body;
    if (newPassword !== newPassword2) {
      return res.status(400).json({
        errors: [{ msg: 'New passwords do not match', param: 'newPassword2' }]
      });
    }
    try {
      let user = await User.findOne({ _id: req.user.id });
      const isMatch = await bcrypt.compare(oldPassword, user.password);
      if (!isMatch) {
        return res.status(400).json({
          errors: [{ msg: 'Old password does not match', param: 'oldPassword' }]
        });
      }
      const salt = await bcrypt.genSalt(12);
      user.password = await bcrypt.hash(newPassword, salt);
      await user.save();
      res.status(200).json({ msg: 'Password saved' });
    } catch (error) {
      console.error(error.message);
      res.status(500).send('Server error');
    }
  }
);

// @route   POST /api/auth/forgot-password
// @desc    Generate forgot password email for user
// @access  Public
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ msg: 'User not found' });
    }
    const token = await crypto.randomBytes(20).toString('hex');
    await User.findByIdAndUpdate(
      { _id: user._id },
      {
        resetPasswordToken: token,
        resetPasswordExpiration: Date.now() + 86400000
      },
      {}
    );
    // TODO user nodemailer to send email
    res.json({
      msg: 'Please check your email for password reset instructions'
    });
  } catch (error) {
    console.error(error.message);
    res.status(500).send('Server error');
  }
});

// @route   POST /api/auth/reset-password
// @desc    Reset password for given token
// @access  Public
router.post(
  '/reset-password',
  [
    check(
      'newPassword',
      'Please enter a password with at least 8 characters'
    ).isLength({ min: 8 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { token, newPassword, newPassword2 } = req.body;
    if (newPassword !== newPassword2) {
      return res.status(400).json({
        errors: [{ msg: 'New passwords do not match', param: 'newPassword2' }]
      });
    }
    try {
      let user = await User.findOne({
        resetPasswordToken: token,
        resetPasswordExpiration: { $gt: Date.now() }
      });
      if (!user) {
        return res
          .status(400)
          .send({ msg: 'Password reset token is invalid or has expired' });
      }
      const salt = await bcrypt.genSalt(12);
      user.password = await bcrypt.hash(newPassword, salt);
      user.resetPasswordExpiration = undefined;
      user.resetPasswordToken = undefined;
      await user.save();
      const payload = {
        user: {
          id: user.id
        }
      };

      jwt.sign(
        payload,
        config.get('jwtSecret'),
        { expiresIn: 360000 }, // TODO change to 3600 later
        (err, token) => {
          if (err) {
            throw err;
          }
          res.json({ token, msg: 'Password updated' });
        }
      );
    } catch (error) {
      console.error(error.message);
      res.status(500).send('Server Error');
    }
  }
);
module.exports = router;
