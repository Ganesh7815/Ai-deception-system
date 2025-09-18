const axios = require("axios");
const Log = require("../models/logModel");

const AI_URL = process.env.AI_SERVICE_URL || "http://127.0.0.1:5001/analyze";

async function callAI(activity) {
  try {
    const resp = await axios.post(`${AI_URL}/analyze`, activity, { timeout: 5000 });
    return resp.data;
  } catch (err) {
    console.warn("AI service call failed:", err.message || err);
    return null;
  }
}

// POST /api/honeypot/login
exports.fakeLogin = async (req, res) => {
  const payload = {
    ip: req.ip || req.body.ip || req.headers["x-forwarded-for"] || "unknown",
    ua: req.headers["user-agent"] || req.body.ua || "",
    path: req.originalUrl,
    method: req.method,
    body: JSON.stringify(req.body || {}),
    event: "login_attempt"
  };

  // call AI for scoring (best-effort)
  const ai = await callAI(payload);
  const riskScore = ai?.risk ?? ai?.riskScore ?? 0;
  const decision = ai?.decision || "allow";

  try {
    const logDoc = await Log.create({
      ...payload,
      riskScore,
      decision,
      extra: { ai: ai || null }
    });

    return res.json({
      message: "Fake login accepted",
      fakeData: { token: "fake-jwt-token" },
      logId: logDoc._id,
      ai
    });

  } catch (err) {
    console.error("Error saving log:", err);
    return res.status(500).json({ error: "Failed to save log" });
  }
};

// GET /api/honeypot/:path   <- generic entry for malicious link redirect
exports.captureGet = async (req, res) => {
  const pathParam = req.params.path || "unknown";
  const payload = {
    ip: req.ip || req.headers["x-forwarded-for"] || "unknown",
    ua: req.headers["user-agent"] || "",
    path: req.originalUrl,
    method: req.method,
    body: "",
    event: "landing"
  };

  const ai = await callAI(payload);
  const riskScore = ai?.risk ?? ai?.riskScore ?? 0;
  const decision = ai?.decision || "allow";

  // Save to DB
  try {
    const logDoc = await Log.create({
      ...payload,
      riskScore,
      decision,
      extra: { pathParam, ai: ai || null }
    });

    // Return fake analyzer JSON OR redirect to frontend fake page (common patterns)
    // Option A: Return JSON (useful for API-only flows)
    // res.json({ message: "Malicious request captured", requestedPath: pathParam, logId: logDoc._id, ai });

    // Option B (recommended for browser flow): Redirect attacker to frontend fake analyzer with logId
    const frontendBase = process.env.FRONTEND_BASE || "http://localhost:5173";
    return res.redirect(`${frontendBase}/fake-analyzer?log=${logDoc._id}`);

  } catch (err) {
    console.error("Error saving capture log:", err);
    return res.status(500).json({ error: "Failed to record capture" });
  }
};
