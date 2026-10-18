<script>
  // Unlock (the mockup's Unlock screen) — the window's, or `compact`: the
  // `--unlock` process the Passwords plugin opens (560×200, floated by
  // hyprland.lua), which quits once the safe is open. The master password is
  // typed here, never into the shell (PLAN.md S4).
  //
  // Login unlock (docs/SYSTEM.md §2): when it is on, the default field is the
  // login password ("Your login password"), with "Use master password
  // instead". "The master password was changed" (key-changed) asks for the
  // new one; local changes are kept.
  import Icon from "../components/Icon.svelte";
  import { api } from "../api.js";
  import { safe } from "../safe.svelte.js";
  import { placeLabel } from "../format.js";

  let { compact = false } = $props();

  let password = $state("");
  let show = $state(false);
  let wrong = $state(false);
  let error = $state("");
  let input = $state();
  // null = follow whether login unlock is on; true/false = the user chose
  let useLogin = $state(null);

  const place = $derived(safe.status?.place);
  // a This-computer safe's location is a full path: its file name says enough here
  const where = $derived(
    place
      ? [placeLabel(place), place.kind === "local" ? place.location?.split("/").pop() : place.location].filter(Boolean).join(" · ")
      : ""
  );
  const minutes = $derived(Number(safe.settings.lock_after_minutes ?? 30));
  const methods = $derived(safe.status?.unlock_methods ?? ["password"]);
  const loginOn = $derived(methods.includes("login"));
  // the master field always, unless login unlock is on and not overridden
  const loginMode = $derived(!safe.keyChanged && (useLogin ?? loginOn));
  const upgrade = $derived(safe.status?.upgrade_from);

  $effect(() => {
    safe.loadSettings();
    input?.focus();
  });

  const label = $derived(
    safe.keyChanged ? "New master password" : loginMode ? "Your login password" : "Master password"
  );

  async function unlock(e) {
    e?.preventDefault();
    if (safe.busy === "unlock") return;
    if (!password) {
      input?.focus();
      return;
    }
    const pw = password;
    password = "";
    wrong = false;
    error = "";
    const r = loginMode ? await safe.unlockLogin(pw) : await safe.unlock(pw);
    if (r?.ok) {
      if (compact) api.quit(0);
      return;
    }
    if (r?.error === "wrong-key") {
      wrong = true;
      input?.focus();
    } else if (r?.error === "too-many-tries") {
      // the login password is locked out: fall back to the master password
      useLogin = false;
      error = r?.message ?? "Too many tries. Use your master password.";
      input?.focus();
    } else if (r?.error === "not-enabled") {
      useLogin = false;
      input?.focus();
    } else if (r?.error !== "key-changed") {
      error = r?.message ?? "Couldn't unlock.";
    }
  }

  function toggleMode() {
    useLogin = !loginMode;
    password = "";
    wrong = false;
    error = "";
    input?.focus();
  }

  function onkey(e) {
    if (compact && e.key === "Escape") api.quit(1);
  }

  const lockLine = $derived(
    minutes > 0
      ? `Safe locks when the screen locks and after ${minutes < 60 ? `${minutes} min` : `${minutes / 60} h`} without use.`
      : "Safe locks when the screen locks."
  );
</script>

<svelte:window onkeydown={onkey} />

{#snippet field(lg)}
  <span class="ewe-input {lg ? 'ewe-input--lg' : ''}" class:is-error={wrong}>
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
{/snippet}

{#snippet switcher()}
  {#if loginOn && !safe.keyChanged}
    <button type="button" class="ewe-btn ewe-btn--ghost ewe-btn--sm" onclick={toggleMode}>
      {loginMode ? "Use master password instead" : "Use your login password instead"}
    </button>
  {/if}
{/snippet}

{#if compact}
  <form class="safe-compact" onsubmit={unlock}>
    <span class="ewe-appicon safe-tile"><Icon name="lock" /></span>
    <div class="safe-compact__body">
      <div class="safe-head">
        <div class="h3">{safe.keyChanged ? "The master password was changed" : "Unlock Safe"}</div>
        <div class="caption safe-muted">{safe.keyChanged ? "Type the new one. Changes on this computer are kept." : loginMode ? "Type your login password." : where}</div>
      </div>
      <div class="safe-compact__row">
        {@render field(false)}
        <button class="ewe-btn ewe-btn--primary" disabled={safe.busy === "unlock"}>{safe.busy === "unlock" ? "Unlocking…" : "Unlock"}</button>
      </div>
      {#if wrong}
        <div class="ewe-field__helper ewe-field__helper--error"><Icon name="circle-x" /><span>Wrong password. Check Caps Lock and try again.</span></div>
      {:else if error}
        <div class="ewe-field__helper ewe-field__helper--error"><Icon name="circle-x" /><span>{error}</span></div>
      {:else}
        <div class="caption safe-muted">Esc closes this. The Super+P picker opens again once Safe is unlocked.</div>
      {/if}
      {@render switcher()}
    </div>
  </form>
{:else}
  <div class="safe-win">
    <div class="safe-solo">
      <form class="safe-col safe-col--narrow safe-col--center safe-center" onsubmit={unlock}>
        <span class="ewe-appicon safe-tile safe-tile--lg"><Icon name="lock" /></span>
        <div class="safe-head safe-center">
          <div class="h2">Safe is locked</div>
          {#if where}<div class="caption safe-muted">{where}</div>{/if}
        </div>
        <label class="ewe-field" style="width:100%">
          <span class="ewe-field__label"><span>{label}</span></span>
          {@render field(true)}
          {#if wrong}
            <span class="ewe-field__helper ewe-field__helper--error"><Icon name="circle-x" /><span>Wrong password. Check Caps Lock and try again.</span></span>
          {:else if error}
            <span class="ewe-field__helper ewe-field__helper--error"><Icon name="circle-x" /><span>{error}</span></span>
          {/if}
        </label>
        <button class="ewe-btn ewe-btn--primary ewe-btn--lg ewe-btn--block" disabled={safe.busy === "unlock"}>
          {safe.busy === "unlock" ? "Unlocking…" : "Unlock"}
        </button>
        {@render switcher()}
        <div class="caption safe-muted">{lockLine}</div>
        {#if upgrade}
          <div class="caption safe-muted">This file is {upgrade}. Safe saves it as KDBX 4.1 and keeps a copy of the original in its backups.</div>
        {/if}
      </form>

      {#if safe.keyChanged}
        <div class="safe-scrim">
          <div role="dialog" aria-modal="true" aria-label="Password changed"><form class="ewe-dialog" onsubmit={unlock}>
            <div class="ewe-dialog__head">
              <span class="ewe-dialog__icon"><Icon name="key-round" /></span>
              <div class="ewe-dialog__titles">
                <h3 class="ewe-dialog__title">The master password was changed</h3>
                <p class="ewe-dialog__desc">
                  It was changed on {safe.status?.sync?.by_machine ? `${safe.status.sync.by_machine}` : "another computer"}. Type the new password to keep using your safe. Changes on this computer are kept.
                </p>
              </div>
            </div>
            <div class="safe-dialog-field">
              <label class="ewe-field">
                <span class="ewe-field__label"><span>New master password</span></span>
                {@render field(false)}
              </label>
              {#if wrong}<div class="ewe-field__helper ewe-field__helper--error"><Icon name="circle-x" /><span>Wrong password. Check Caps Lock and try again.</span></div>{/if}
            </div>
            <div class="ewe-dialog__foot">
              <button type="button" class="ewe-btn ewe-btn--ghost" onclick={() => (safe.keyChanged = false)}>Later</button>
              <button class="ewe-btn ewe-btn--primary" disabled={safe.busy === "unlock"}>Unlock</button>
            </div>
          </form></div>
        </div>
      {/if}
    </div>
  </div>
{/if}
