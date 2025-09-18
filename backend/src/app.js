require("dotenv").config();
const express = require("express");
const http = require("http");
const cors = require("cors");
const { Server } = require("socket.io");
const connectDB = require("./config/db");
const honeypotRoutes = require("./routes/honeypotRoutes");
const logRoutes = require("./routes/logRoutes");

const app = express();
const server = http.createServer(app);

const allowedOrigins = (process.env.ALLOWED_ORIGINS || "http://localhost:5173").split(",");

const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    methods: ["GET", "POST"]
  }
});
global.io = io; // expose for controllers

io.on("connection", (socket) => {
  console.log("Socket client connected:", socket.id);
  socket.on("disconnect", () => console.log("Socket disconnected:", socket.id));
});

// connect DB
connectDB();

app.use(cors({ origin: allowedOrigins }));
app.use(express.json());

// routes
app.use("/api/honeypot", honeypotRoutes);
app.use("/api/logs", logRoutes);

// health
app.get("/ping", (req, res) => res.json({ message: "pong" }));

const port = process.env.PORT || 7777;
server.listen(port, () => console.log(`🚀 Backend running on port ${port}`));
