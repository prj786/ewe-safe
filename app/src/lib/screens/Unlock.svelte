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
  import Dialog from "../components/Dialog.svelte";
  import { api } from "../api.js";
  import { safe } from "../safe.svelte.js";
  import { placeLabel, placeName } from "../format.js";

  let { compact = false } = $props();

  let password = $state("");
  let show = $state(false);
  let wrong = $state(false);
  let error = $state("");
  let input = $state();
  // null = follow whether login unlock is on; true/false = the user chose
  let useLogin = $state(null);

  // a new machine (status.offer): the safe another computer keeps in the
  // account — the master password opens it and sets this one up
  const offer = $derived(safe.status?.offer);
  const place = $derived(safe.status?.place ?? (offer ? { kind: offer.place, location: offer.location } : null));
  // a This-computer safe's location is a full path: its file name says enough here
  const where = $derived(
    place
      ? [placeLabel(place), place.kind === "local" ? place.location?.split("/").pop() : place.location].filter(Boolean).join(" · ")
      : ""
  );
  const minutes = $derived(Number(safe.settings.lock_after_minutes ?? 0));
  const onScreen = $derived(safe.settings.lock_on_screen_lock === true || safe.settings.lock_on_screen_lock === "true");
  const onSleep = $derived(safe.settings.lock_on_sleep === true || safe.settings.lock_on_sleep === "true");
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
      error = r?.message ?? "Couldn’t unlock.";
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

  const lockLine = $derived.by(() => {
    const when = [];
    if (onScreen) when.push("when the screen locks");
    if (onSleep) when.push("before sleep");
    if (minutes > 0) when.push(`after ${minutes < 60 ? `${minutes} min` : `${minutes / 60} h`} without use`);
    if (!when.length) return "ewe Safe stays open until this computer turns off, or until you lock it.";
    return `ewe Safe locks ${when.join(", ")}.`;
  });
</script>

<svelte:window onkeydown={onkey} />

<!-- `ph`: no label on screen (the compact window), so the field says what it wants -->
{#snippet field(lg, ph = false)}
  <span class="ewe-input {lg ? 'ewe-input--lg' : ''}" class:is-error={wrong}>
    <input
      bind:this={input}
      bind:value={password}
      class={show ? "mono" : ""}
      type={show ? "text" : "password"}
      placeholder={ph ? label : undefined}
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
    <button type="button" class="ewe-btn ewe-btn--ghost ewe-btn--sm safe-switcher" onclick={toggleMode}>
      {loginMode ? "Use master password instead" : "Use your login password instead"}
    </button>
  {/if}
{/snippet}

{#if compact}
  <form class="safe-compact" onsubmit={unlock}>
    <span class="ewe-appicon safe-tile"><Icon name="lock" /></span>
    <div class="safe-compact__body">
      <div class="safe-head">
        <div class="h3">{safe.keyChanged ? "The master password was changed" : offer ? `Open your safe from ${placeName(place)}` : "Unlock ewe Safe"}</div>
        <div class="caption safe-muted">{safe.keyChanged ? "Type the new one. Changes on this computer are kept." : loginMode ? "Type your login password." : where}</div>
      </div>
      <div class="safe-compact__row">
        {@render field(false, true)}
        <button type="submit" class="ewe-btn ewe-btn--primary" disabled={safe.busy === "unlock"}>{safe.busy === "unlock" ? "Unlocking…" : "Unlock"}</button>
      </div>
      {#if wrong}
        <div class="ewe-field__helper ewe-field__helper--error"><Icon name="circle-x" /><span>Wrong password. Check Caps Lock and try again.</span></div>
      {:else if error}
        <div class="ewe-field__helper ewe-field__helper--error"><Icon name="circle-x" /><span>{error}</span></div>
      {:else}
        <div class="caption safe-muted">Esc closes this. The Super+P picker opens again once ewe Safe is unlocked.</div>
      {/if}
      {@render switcher()}
    </div>
  </form>
{:else}
  <!-- in the window's pane: the rail stays, so unlocking moves nothing -->
  <div class="safe-stage">
    <form class="safe-col safe-col--narrow safe-col--center safe-center" onsubmit={unlock}>
      <span class="ewe-appicon safe-tile safe-tile--lg" aria-hidden="true"><Icon name="lock" /></span>
      <div class="safe-head safe-center">
        <h1 class="h2">ewe Safe is locked</h1>
        {#if where}<div class="caption safe-muted">{where}</div>{/if}
      </div>
      <label class="ewe-field safe-wide">
        <span class="ewe-field__label"><span>{label}</span></span>
        {@render field(true)}
        {#if wrong}
          <span class="ewe-field__helper ewe-field__helper--error"><Icon name="circle-x" /><span>Wrong password. Check Caps Lock and try again.</span></span>
        {:else if error}
          <span class="ewe-field__helper ewe-field__helper--error"><Icon name="circle-x" /><span>{error}</span></span>
        {/if}
      </label>
      <button type="submit" class="ewe-btn ewe-btn--primary ewe-btn--lg ewe-btn--block" disabled={safe.busy === "unlock"}>
        {safe.busy === "unlock" ? "Unlocking…" : "Unlock"}
      </button>
      {@render switcher()}
      <div class="caption safe-muted">{lockLine}</div>
      {#if upgrade}
        <div class="caption safe-muted">This file is {upgrade}. ewe Safe saves it as KDBX 4.1 and keeps a copy of the original in its backups.</div>
      {/if}
    </form>
  </div>

  {#if safe.keyChanged}
    <Dialog
      title="The master password was changed"
      desc="It was changed on {safe.status?.sync?.by_machine || 'another computer'}. Type the new password to keep using your safe. Changes on this computer are kept."
      icon="key-round"
      onsubmit={unlock}
      onclose={() => (safe.keyChanged = false)}
    >
      <label class="ewe-field">
        <span class="ewe-field__label"><span>New master password</span></span>
        {@render field(false)}
      </label>
      {#if wrong}<div class="ewe-field__helper ewe-field__helper--error"><Icon name="circle-x" /><span>Wrong password. Check Caps Lock and try again.</span></div>{/if}
      {#snippet foot()}
        <button type="button" class="ewe-btn ewe-btn--ghost" onclick={() => (safe.keyChanged = false)}>Later</button>
        <button type="submit" class="ewe-btn ewe-btn--primary" disabled={safe.busy === "unlock"}>Unlock</button>
      {/snippet}
    </Dialog>
  {/if}
{/if}
