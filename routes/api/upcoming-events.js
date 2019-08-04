const express = require('express');
const router = express.Router();

// @route   GET api/upcoming-events
// @desc    Test route
// @access  Public
router.get('/', (req, res) => res.send('Upcoming events route'));

module.exports = router;
