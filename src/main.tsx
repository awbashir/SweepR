import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App.tsx";
import "./index.css";

const root = document.getElementById("root");
if (!root) throw new Error("missing #root element");

// Native-feeling app: no browser context menu except where the app provides its own.
document.addEventListener("contextmenu", (e) => {
  const t = e.target;
  if (!(t instanceof HTMLInputElement || t instanceof HTMLTextAreaElement)) e.preventDefault();
});

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
