import React, { useEffect, useState } from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import SocShell from "./SocShell";
import LoginPage from "./LoginPage";
import "./styles.css";

function Root() {
  const [route, setRoute] = useState(window.location.hash);

  useEffect(() => {
    const syncRoute = () => setRoute(window.location.hash);
    window.addEventListener("hashchange", syncRoute);
    return () => window.removeEventListener("hashchange", syncRoute);
  }, []);

  return route === "#/dashboard" ? <SocShell><App /></SocShell> : <LoginPage />;
}

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode><Root /></React.StrictMode>
);
