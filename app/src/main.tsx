import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource-variable/inter";
import "@fontsource-variable/jetbrains-mono";
import "./theme.css";
import "./styles.css";
import App from "./App";

// Dev-only mock backend (`npm run dev:mock`): the banner marks it.
if (__SPARROW_MOCK__) void import("./mock/banner").then((m) => m.mountMockBanner());

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
