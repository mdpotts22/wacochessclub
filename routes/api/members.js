const express = require('express');
const router = express.Router();

// @route   GET api/members
// @desc    Test route
// @access  Public
router.get('/', (req, res) => res.send('Members route'));

module.exports = router;
