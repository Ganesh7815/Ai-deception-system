import React, { useEffect, useState } from "react";
import axios from "axios";
import { io } from "socket.io-client";
import AttackTable from "./AttackTable";

export default function Dashboard() {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    const backend = import.meta.env.VITE_BACKEND_URL || "http://localhost:7777";
    // load initial logs
    axios.get(`${backend}/api/logs`).then(res => setLogs(res.data)).catch(()=>{});

    // socket
    const socket = io(backend, { transports: ["websocket"] });
    socket.on("connect", () => console.log("socket connected", socket.id));
    socket.on("attackData", (data) => {
      setLogs(prev => [data, ...prev]);
    });

    return () => socket.disconnect();
  }, []);

  return (
    <div>
      <h2 className="text-xl mb-4">Live Attack Logs</h2>
      <AttackTable data={logs} />
    </div>
  );
}
