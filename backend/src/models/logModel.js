const mongoose = require("mongoose");

const logSchema = new mongoose.Schema({
  ip: { type: String, default: "unknown" },
  ua: { type: String, default: "" },
  path: { type: String, default: "" },
  method: { type: String, default: "GET" },
  body: { type: String, default: "" },
  event: { type: String, default: "" }, // e.g., 'landed', 'click', 'submitted'
  extra: { type: Object, default: {} }, // arbitrary metadata
  riskScore: { type: Number, default: 0 },
  decision: { type: String, default: "allow" },
  createdAt: { type: Date, default: Date.now },
  label:{type:Number,default:0}
});

module.exports = mongoose.model("AttackLog", logSchema);
