const express = require("express");
const router = express.Router();
const { fakeLogin, captureGet } = require("../controllers/honeypotController");

// Login route used in fake login forms
router.post("/login", fakeLogin);

// Generic capture for malicious links (e.g. /api/honeypot/anything)
router.get("/:path", captureGet);

module.exports = router;
