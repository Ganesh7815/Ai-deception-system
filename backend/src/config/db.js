const mongoose = require("mongoose");
require('dotenv').config();

const dbconncetion = process.env.MONGO_URI || "mongodb+srv://machavarapuganesh2004:GaneshMachavarapu@cluster0.dj4kaq9.mongodb.net/AI-deception-sytem"
const port = process.env.PORT || 7777

const connectDB = async () => {
    try {
        await mongoose.connect(dbconncetion, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        console.log("✅ MongoDb  Connected");
    } catch (err) {
        console.error("❌ MongoDB Connection Error:", err);
        process.exit(1);
    }
};

module.exports = connectDB;







