import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import SocShell from "./SocShell";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <SocShell>
      <App />
    </SocShell>
  </React.StrictMode>
);
