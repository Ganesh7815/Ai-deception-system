import React from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import App from "./App";
import FakeAnalyzer from "./pages/FakeAnalyzer";
import "./index.css";

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<App />} />
        <Route path="/fake-analyzer" element={<FakeAnalyzer />} />
      </Routes>
    </BrowserRouter>
  </React.StrictMode>
);
