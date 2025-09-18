import React from "react";
import Dashboard from "./components/Dashboard";

export default function App() {
  return (
    <div className="min-h-screen">
      <header className="p-4 bg-slate-800">
        <h1 className="text-2xl font-bold">AI Deception — Admin Dashboard</h1>
        <p className="text-sm text-slate-300">Live attacker sessions and logs</p>
      </header>
      <main className="p-4">
        <Dashboard />
      </main>
    </div>
  );
}
