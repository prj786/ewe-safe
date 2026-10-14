// The live look (the ewe-sync runtime): tokens.css is compiled in (Ewe Dark,
// the default accent) so the window paints before this runs; then
// `ewe-theme show` gives this machine's token map — the active scheme, light
// or dark, the accent, look presets and accessibility modes — and every value
// lands as an inline custom property on <html>, which beats the compiled
// file. Nothing here knows which scheme is active.

import { api } from "./api.js";

let seq = 0;
const KEY = "safe.theme";

/** The look as last seen, before the first paint: a light desktop never
 *  flashes dark while `ewe-theme` answers. Browser storage may be missing
 *  or refused; then the compiled tokens.css paints first. */
export function applyCachedTheme() {
  try {
    const t = JSON.parse(localStorage.getItem(KEY) ?? "null");
    if (t?.css_vars) apply(t);
  } catch {
    // no storage: tokens.css it is
  }
}

export async function refreshTheme() {
  const mine = ++seq;
  const t = await api.themeTokens();
  if (mine !== seq || !t || !t.css_vars) return null; // dev browser or no ewe: keep tokens.css
  apply(t);
  try {
    localStorage.setItem(KEY, JSON.stringify({ css_vars: t.css_vars, motion: t.motion, input: t.input, scheme: t.scheme }));
  } catch {
    // no storage: the next start paints tokens.css first
  }
  return t;
}

function apply(t) {
  const root = document.documentElement;
  // a scheme change recolours at once: transitions are for interaction
  root.classList.add("safe-instant");
  for (const [k, v] of Object.entries(t.css_vars)) root.style.setProperty(k, v);

  // Motion (README "Motion"): the four durations divided by the animation
  // speed; Off makes them 0. Reduce motion is already folded in.
  const m = t.motion || {};
  const speed = Number(m.speed ?? 1);
  const dur = (ms) => (speed > 0 ? Math.round(Number(ms) / speed) : 0) + "ms";
  if (m.durFast != null) {
    root.style.setProperty("--dur-fast", dur(m.durFast));
    root.style.setProperty("--dur-base", dur(m.durBase));
    root.style.setProperty("--dur-slow", dur(m.durSlow));
    root.style.setProperty("--dur-dim", dur(m.durDim));
  }
  const variant = t.input?.variant || t.scheme?.variant || "dark";
  root.style.colorScheme = variant === "light" ? "light" : "dark";
  root.classList.toggle("dark", variant !== "light");
  root.dataset.variant = variant;
  requestAnimationFrame(() => requestAnimationFrame(() => root.classList.remove("safe-instant")));
}

/** Follow the desktop: at start, when the window regains focus, and when
 *  the files the look comes from change (a cheap key, every 4 s). */
export function watchTheme(every = 4000) {
  refreshTheme();
  const onFocus = () => refreshTheme();
  window.addEventListener("focus", onFocus);
  let last = null;
  const timer = setInterval(async () => {
    const k = await api.themeKey();
    if (typeof k !== "string") return;
    if (last !== null && k !== last) refreshTheme();
    last = k;
  }, every);
  return () => {
    window.removeEventListener("focus", onFocus);
    clearInterval(timer);
  };
}
