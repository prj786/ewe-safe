<script>
  // A card fill's fresh check (docs/SYSTEM.md §4): `ewe-safe-app --confirm
  // --reason "Fill Visa •• 4242 on shop.com"`, the same compact process as
  // the unlock prompt (floated 560×200 by hyprland.lua). Type your password —
  // the login password when login unlock is on, the master password
  // otherwise, either one is accepted. Confirmed exits 0, Esc or Cancel
  // exits 1. The safe is already unlocked; this is only a presence check.
  import Icon from "../components/Icon.svelte";
  import { api } from "../api.js";
  import { safe } from "../safe.svelte.js";

  let { reason = "" } = $props();

  let password = $state("");
  let show = $state(false);
  let wrong = $state(false);
  let error = $state("");
  let busy = $state(false);
  let input = $state();

  const methods = $derived(safe.status?.unlock_methods ?? ["password"]);
  const loginOn = $derived(methods.includes("login"));
  const label = $derived(loginOn ? "Your login password" : "Your password");

  $effect(() => {
    input?.focus();
  });

  async function submit(e) {
    e?.preventDefault();
    if (busy || !password) {
      input?.focus();
      return;
    }
    const pw = password;
    password = "";
    wrong = false;
    error = "";
    busy = true;
    // the daemon takes either; send it as the login password when that's on
    const r = await api.confirm(loginOn ? { loginPassword: pw } : { password: pw });
    busy = false;
    if (r?.ok) {
      api.quit(0);
      return;
    }
    if (r?.error === "wrong-key") {
      wrong = true;
      input?.focus();
    } else {
      error = r?.message ?? "Couldn't confirm.";
    }
  }

  function onkey(e) {
    if (e.key === "Escape") api.quit(1);
  }
</script>

<svelte:window onkeydown={onkey} />

<form class="safe-compact" onsubmit={submit}>
  <span class="ewe-appicon safe-tile"><Icon name="shield-check" /></span>
  <div class="safe-compact__body">
    <div class="safe-head">
      <div class="h3">{reason || "Type your password to continue"}</div>
      <div class="caption safe-muted">Safe asks again before it fills a card. Nothing is saved; this only checks it's you.</div>
    </div>
    <div class="safe-compact__row">
      <span class="ewe-input" class:is-error={wrong}>
        <input
          bind:this={input}
          bind:value={password}
          class={show ? "mono" : ""}
          type={show ? "text" : "password"}
          placeholder={label}
          aria-label={label}
          autocomplete="current-password"
          spellcheck="false"
          oninput={() => (wrong = false)}
        />
        <button type="button" class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm" aria-label={show ? "Hide password" : "Show password"} onclick={() => (show = !show)}>
          <Icon name={show ? "eye-off" : "eye"} />
        </button>
      </span>
      <button class="ewe-btn ewe-btn--primary" disabled={busy}>{busy ? "Checking…" : "Confirm"}</button>
    </div>
    {#if wrong}
      <div class="ewe-field__helper ewe-field__helper--error"><Icon name="circle-x" /><span>Wrong password. Check Caps Lock and try again.</span></div>
    {:else if error}
      <div class="ewe-field__helper ewe-field__helper--error"><Icon name="circle-x" /><span>{error}</span></div>
    {:else}
      <div class="caption safe-muted">Esc cancels.</div>
    {/if}
  </div>
</form>
