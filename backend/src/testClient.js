const { io } = require("socket.io-client");
const socket = io("http://localhost:7777");

socket.on("connect", () => {
  console.log("Connected OK, id:", socket.id);
});

socket.on("attackData", (data) => {
  console.log("attackData event:", data);
});
