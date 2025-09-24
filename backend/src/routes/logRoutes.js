const express = require("express");
const Log = require("../models/logModel");
const { Parser } = require("json2csv");
const fs = require("fs");
const path = require("path");
const axios = require("axios");

const router = express.Router();

// ✅ Get logs normally
router.get("/", async (req, res) => {
  try {
    const logs = await Log.find().sort({ createdAt: -1 });
    res.json(logs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ Export + retrain automatically
router.get("/export-train", async (req, res) => {
  try {
    const logs = await Log.find().lean();
    if (!logs || logs.length === 0) {
      return res.status(404).json({ error: "No logs found to export" });
    }

    // Keep only fields required by AI service
    const fields = ["ip", "ua", "path", "method", "body", "label"];
    const parser = new Parser({ fields });
    const csv = parser.parse(logs);

    // Save CSV file locally
    const exportPath = path.join(__dirname, "../exports/logs.csv");
    fs.mkdirSync(path.dirname(exportPath), { recursive: true });
    fs.writeFileSync(exportPath, csv);

    // ✅ Tell AI service to train from CSV (send JSON not file)
    const aiServiceUrl = process.env.AI_SERVICE_URL || "http://127.0.0.1:5001/train";
    const aiRes = await axios.post(aiServiceUrl, {
      csv_path: exportPath,
      label_column: "label"
    });

    res.json({
      message: "Logs exported and model retrained successfully",
      aiResponse: aiRes.data,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
