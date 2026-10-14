import { mount } from "svelte";
import App from "./App.svelte";
import "./app.css";
import { applyCachedTheme } from "./lib/theme.js";

applyCachedTheme();

// a plain browser with ?mock=1 gets the dev mock (screenshots, UI work)
if (!window.__TAURI_INTERNALS__ && new URLSearchParams(location.search).get("mock") === "1") {
  const params = new URLSearchParams(location.search);
  const { install, arrange } = await import("./lib/devmock.js");
  const { ui } = await import("./lib/ui.svelte.js");
  install(params);
  await arrange(params, ui);
}

const app = mount(App, { target: document.getElementById("app") });

export default app;
