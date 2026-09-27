import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import SocShell from "./SocShell";
import LoginPage from "./LoginPage";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    {(window.location.hash === "#/login" || window.location.pathname === "/login") ? <LoginPage /> : <SocShell><App /></SocShell>}
  </React.StrictMode>
);
