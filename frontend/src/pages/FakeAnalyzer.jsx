import React, { useEffect } from "react";
import axios from "axios";
import { useSearchParams } from "react-router-dom";

export default function FakeAnalyzer() {
  const [params] = useSearchParams();
  const logId = params.get("log") || null;

  useEffect(() => {
    const backend = import.meta.env.VITE_BACKEND_URL || "http://localhost:7777";

    // helper to send event
    const send = (payload) =>
      axios.post(`${backend}/api/logs`, payload).catch((e) => console.warn(e));

    // record landing
    send({ event: "landed", path: window.location.pathname + window.location.search, extra: { logId } });

    // mouse move throttled
    let last = 0;
    const onMove = (e) => {
      const t = Date.now();
      if (t - last < 1000) return; // every 1s
      last = t;
      send({ event: "mousemove", extra: { x: e.clientX, y: e.clientY, logId } });
    };
    const onClick = (e) => {
      send({ event: "click", extra: { x: e.clientX, y: e.clientY, element: e.target.tagName, logId } });
    };
    const onKey = (e) => {
      // DO NOT log keystrokes in plaintext if sensitive — here we record key names only.
      send({ event: "keydown", extra: { key: e.key, logId } });
    };

    window.addEventListener("mousemove", onMove);
    window.addEventListener("click", onClick);
    window.addEventListener("keydown", onKey);

    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("click", onClick);
      window.removeEventListener("keydown", onKey);
    };
  }, []);

  return (
    <div className="p-8 max-w-3xl mx-auto bg-slate-900 rounded-lg shadow-lg">
      <h2 className="text-2xl font-semibold">Security Analyzer</h2>
      <p className="mt-2 text-slate-300">We are analyzing your request. This may take a few seconds.</p>

      <div className="mt-6 bg-slate-800 p-4 rounded">
        <h3 className="text-lg">Scan result</h3>
        <p className="text-slate-400">Status: <span className="text-amber-300">Collecting telemetry</span></p>
        <div className="mt-4">
          <button className="px-4 py-2 bg-emerald-600 rounded" onClick={() => {
            // example: attacker clicks a fake "download report" button — we record that
            fetch("http://localhost:7777/api/logs", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ event: "clicked_download_report", extra: {} })
            });
            alert("Preparing report...");
          }}>Download Report</button>
        </div>
      </div>
    </div>
  );
}
