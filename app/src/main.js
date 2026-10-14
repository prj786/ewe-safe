import { mount } from "svelte";
import App from "./App.svelte";
import "./app.css";

// a plain browser with ?mock=1 gets the dev mock (screenshots, UI work)
if (!window.__TAURI_INTERNALS__ && new URLSearchParams(location.search).get("mock") === "1") {
  const { install } = await import("./lib/devmock.js");
  install(new URLSearchParams(location.search));
}

const app = mount(App, { target: document.getElementById("app") });

export default app;
