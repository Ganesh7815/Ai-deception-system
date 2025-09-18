import React from "react";

export default function AttackTable({ data }) {
  return (
    <div className="overflow-auto">
      <table className="min-w-full text-left border-collapse">
        <thead>
          <tr className="bg-slate-800">
            <th className="px-3 py-2">Time</th>
            <th className="px-3 py-2">IP</th>
            <th className="px-3 py-2">Event</th>
            <th className="px-3 py-2">Risk</th>
            <th className="px-3 py-2">Path</th>
          </tr>
        </thead>
        <tbody>
          {data.map((d, i) => (
            <tr key={d.id || d._id || i} className="border-b border-slate-700">
              <td className="px-3 py-2 text-sm">{new Date(d.timestamp || d.createdAt || d.date || Date.now()).toLocaleString()}</td>
              <td className="px-3 py-2 text-sm">{d.sourceIP || d.ip || (d.extra && d.extra.ip) || "unknown"}</td>
              <td className="px-3 py-2 text-sm">{d.event || d.eventType || "-"}</td>
              <td className="px-3 py-2 text-sm">{d.riskScore ?? d.risk ?? "-"}</td>
              <td className="px-3 py-2 text-sm">{d.path || (d.extra && d.extra.path) || "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
