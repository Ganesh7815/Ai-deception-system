const Log = require("../models/logModel");

// GET /api/logs
exports.getLogs = async (req, res) => {
  try {
    const logs = await Log.find().sort({ createdAt: -1 }).limit(500);
    res.json(logs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// POST /api/logs  (generic event ingest from frontend fake analyzer)
exports.postLog = async (req, res) => {
  try {
    const payload = {
      ip: req.ip || req.body.ip || req.headers["x-forwarded-for"] || "unknown",
      ua: req.headers["user-agent"] || req.body.ua || "",
      path: req.body.path || req.originalUrl || "",
      method: req.method || "POST",
      body: req.body.body ? JSON.stringify(req.body.body) : JSON.stringify(req.body),
      event: req.body.event || "interaction",
      extra: req.body.extra || {}
    };

    // Optionally call AI scoring for this specific event
    let riskScore = req.body.riskScore || 0;
    let decision = req.body.decision || "allow";

    // Save
    const doc = await Log.create({ ...payload, riskScore, decision });
    // Emit via socket (if attached)
    if (global.io) {
      global.io.emit("attackData", {
        id: doc._id,
        timestamp: doc.createdAt,
        sourceIP: payload.ip,
        event: payload.event,
        riskScore: doc.riskScore,
        path: payload.path
      });
    }

    res.json({ status: "ok", id: doc._id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to save log" });
  }
};
