<script>
  // The SSH agent's question (TRIO.md S2): `ewe-safe-app --approve`, a
  // compact process like the unlock prompt (the same app_id, so
  // hyprland.lua floats it at 560×200). "Allow ssh (from git) to use GitHub
  // key?" — Allow exits 0, Deny or Esc exits 1, and no answer in 60 s is a
  // Deny (the daemon closes the prompt then too). Deny has the focus: an
  // Enter meant for the terminal never allows.
  import Icon from "../components/Icon.svelte";
  import { api } from "../api.js";

  let { app = "An app", key = "an SSH key" } = $props();

  const WAIT = 60;
  let left = $state(WAIT);
  let denyBtn = $state();

  $effect(() => {
    denyBtn?.focus();
    const t = setInterval(() => {
      left -= 1;
      if (left <= 0) api.quit(1);
    }, 1000);
    return () => clearInterval(t);
  });

  function onkey(e) {
    if (e.key === "Escape") api.quit(1);
  }
</script>

<svelte:window onkeydown={onkey} />

<div class="safe-compact" role="alertdialog" aria-labelledby="approve-title">
  <span class="ewe-appicon safe-tile"><Icon name="terminal" /></span>
  <div class="safe-compact__body">
    <div class="safe-head">
      <div class="h3" id="approve-title">Allow <strong>{app}</strong> to use <strong>{key}</strong>?</div>
      <div class="caption safe-muted">It asks to sign in with your key. No answer is a Deny, in {left} s.</div>
    </div>
    <div class="safe-compact__row">
      <button class="ewe-btn ewe-btn--secondary" bind:this={denyBtn} onclick={() => api.quit(1)}>Deny</button>
      <button class="ewe-btn ewe-btn--primary" onclick={() => api.quit(0)}><Icon name="check" />Allow</button>
    </div>
  </div>
</div>
