<script>
  // Settings: where the safe lives and how it syncs — shown in ewe Sync's
  // words, never a button (house rule 6: ewe Safe syncs by itself, ewe Sync
  // shows the same state) — how it locks, the master password, the
  // Emergency Kit, cards and addresses, the keyring, import and export,
  // About. Switches go through ewe-conf.
  import Icon from "../components/Icon.svelte";
  import Switch from "../components/Switch.svelte";
  import Kit from "../components/Kit.svelte";
  import Dialog from "../components/Dialog.svelte";
  import { api } from "../api.js";
  import { safe } from "../safe.svelte.js";
  import { edge } from "../trap.js";
  import { ui } from "../ui.svelte.js";
  import { toasts } from "../toast.svelte.js";
  import { day, placeIcon, placeLabel, placeLine, strength, syncDetail } from "../format.js";
  import { ENCRYPTED_NOTE } from "../cards.js";

  let server = $state("");
  let pw = $state(null); // the change-password dialog: {a, b, error}
  let now = $state(new Date());
  // the "turn on login unlock" dialog: {login, master, error, busy} (master
  // only asked when the safe is locked)
  let login = $state(null);

  $effect(() => {
    safe.loadSettings();
    api.cloudStatus().then((c) => (server = c?.signed_in ? c.server ?? "" : ""));
    const t = setInterval(() => (now = new Date()), 30000);
    return () => clearInterval(t);
  });

  const place = $derived(safe.status?.place);
  const sync = $derived(safe.status?.sync);
  const state = $derived(syncDetail(sync, place, place?.kind === "nextcloud" ? server : "", now));
  const s = $derived(safe.settings);
  const flag = (k) => s[k] !== false;
  // once per power-on: these are off until the user turns them on
  const optIn = (k) => s[k] === true || s[k] === "true";
  const loginOn = $derived((safe.status?.unlock_methods ?? []).includes("login"));

  // the toggle: on opens the one-time setup dialog; off turns it straight off
  function onLoginToggle(on) {
    if (on) login = { login: "", master: "", error: "", busy: false };
    else safe.loginDisable();
  }

  async function enableLogin(e) {
    e.preventDefault();
    if (!login.login) return;
    const needMaster = safe.locked;
    if (needMaster && !login.master) {
      login = { ...login, error: "Type your master password to seal the safe." };
      return;
    }
    login = { ...login, busy: true, error: "" };
    const r = await safe.loginEnable(login.login, needMaster ? login.master : undefined);
    if (r?.ok) {
      login = null;
      toasts.show("Login unlock is on. Your login password opens ewe Safe on this computer.", { icon: "circle-check", ms: 6000 });
    } else {
      login = { ...login, login: "", master: "", busy: false, error: r?.message ?? "Couldn’t turn it on." };
    }
  }
  const lockAfter = $derived(Number(s.lock_after_minutes ?? 0));
  const clearAfter = $derived(Number(s.clipboard_clear_seconds ?? 30));

  // The keyring (docs/KEYRING.md): who keeps the apps' passwords, the fix
  // for the password prompt at every start, the app secrets (names and
  // dates, never a secret). Hidden when the daemon has no keyring verbs.
  let kr = $state(null);
  let krList = $state(null);
  let krBusy = $state(false);
  async function loadKeyring() {
    const st = await api.keyringStatus();
    kr = st?.ok ? st : null;
    const l = await api.keyringList();
    krList = l?.ok ? l : null;
  }
  $effect(() => {
    loadKeyring();
  });
  const KEEPERS = { "gnome-keyring": "GNOME Keyring", "ewe-safe": "ewe Safe", kwallet: "KWallet", other: "another app" };
  const keeper = $derived(KEEPERS[kr?.owner] ? `Kept by ${KEEPERS[kr.owner]}` : "No keyring runs now");
  const keeperLine = $derived(
    kr?.owner === "none"
      ? "It starts when an app needs it."
      : kr?.needs_repair
        ? "Your apps save into a second keyring with its own password."
        : kr?.owner === "ewe-safe"
          ? "ewe Safe keeps them, on this computer only."
          : "It opens with your login password when you sign in."
  );
  async function repairKeyring() {
    krBusy = true;
    const r = await api.keyringRepair();
    krBusy = false;
    if (!r?.ok) {
      toasts.show(r?.message ?? "Couldn’t fix the keyring.", { icon: "circle-alert", ms: 8000 });
    } else if (r.fixed) {
      const n = r.moved + r.replaced;
      toasts.show(
        n ? `Fixed. ${n} ${n === 1 ? "password" : "passwords"} moved into your login keyring. The old keyring stays as a backup.` : "Fixed. Your login keyring is the default now.",
        { icon: "circle-check", ms: 7000 }
      );
    } else {
      toasts.show(r.message ?? "Nothing was changed.", { icon: "circle-alert", ms: 8000 });
    }
    await loadKeyring();
  }

  async function set(key, value) {
    const r = await safe.setSetting(key, value);
    if (!r?.ok) toasts.show(r?.message ?? "Couldn’t change the setting.", { icon: "circle-alert" });
  }

  // cards and addresses: the notes an earlier 1Password import made from
  // them, turned into cards and addresses (`convert`, a dry run first)
  let conv = $state(null); // {converted, skipped, busy}
  async function checkConvert() {
    conv = { converted: [], skipped: [], busy: true };
    const r = await api.convert(true);
    if (!r?.ok) {
      conv = null;
      toasts.show(r?.message ?? "Couldn’t check.", { icon: "circle-alert" });
      return;
    }
    conv = { converted: r.converted ?? [], skipped: r.skipped ?? [], busy: false };
  }
  async function runConvert() {
    conv = { ...conv, busy: true };
    const r = await api.convert(false);
    const n = r?.converted?.length ?? 0;
    conv = null;
    if (r?.ok) {
      await safe.loadItems();
      toasts.show(n === 1 ? "1 note is now a card or an address." : `${n} notes are now cards and addresses.`, { icon: "circle-check" });
    } else toasts.show(r?.message ?? "Couldn’t change them.", { icon: "circle-alert" });
  }

  const meter = $derived(strength(pw?.a ?? ""));
  async function changePassword(e) {
    e.preventDefault();
    if (!pw.a || pw.a !== pw.b) {
      pw = { ...pw, error: "The two passwords are not the same." };
      return;
    }
    const a = pw.a;
    pw = { ...pw, a: "", b: "", busy: true };
    const r = await safe.passwd(a);
    if (r?.ok) {
      pw = null;
      toasts.show("The master password is changed. Your other computers will ask for it once.", { icon: "circle-check", ms: 6000 });
    } else pw = { a: "", b: "", error: r?.message ?? "Couldn’t change it." };
  }
</script>

<header class="ewe-headerbar ewe-headerbar--page safe-pagehead">
  <div class="ewe-headerbar__titles">
    <h1 class="ewe-headerbar__title">Settings</h1>
    <div class="ewe-headerbar__subtitle">Where your safe lives, how it locks, and import and export.</div>
  </div>
</header>

<div class="safe-page" use:edge>
  <div class="safe-page__body">
    {@render section("Place")}
    <div class="ewe-list">
      <div class="ewe-row">
        <span class="ewe-row__lead ewe-row__lead--tile"><Icon name={placeIcon(place)} /></span>
        <span class="ewe-row__text">
          <span class="ewe-row__title">{placeLabel(place)}</span>
          <span class="ewe-row__desc">{placeLine(place, place?.kind === "nextcloud" ? server : "")}</span>
        </span>
      </div>
      {#if state}
        <div class="ewe-list__divider"></div>
        <div class="ewe-row">
          <span class="ewe-row__lead ewe-row__lead--tile safe-tone--{state.tone}"><Icon name={state.icon} /></span>
          <span class="ewe-row__text">
            <span class="ewe-row__title">{state.word}</span>
            {#if state.desc}<span class="ewe-row__desc">{state.desc}</span>{/if}
          </span>
          {#if state.action === "ewe-sync"}
            <span class="ewe-row__trail"><button type="button" class="ewe-btn ewe-btn--secondary ewe-btn--sm" onclick={() => api.openEweSync()}>Open ewe Sync</button></span>
          {/if}
        </div>
      {/if}
    </div>
    <div class="caption safe-muted">ewe Safe saves and syncs by itself. ewe Sync shows the same state. Moving a safe to another place comes in a later version.</div>

    {@render section("Security")}
    <div class="ewe-list">
      <div class="ewe-switch-row ewe-row">
        <span class="ewe-check__text"><span class="ewe-check__label">Lock when the screen locks</span></span>
        <Switch on={optIn("lock_on_screen_lock")} label="Lock when the screen locks" toggled={(v) => set("lock_on_screen_lock", v)} />
      </div>
      <div class="ewe-list__divider"></div>
      <div class="ewe-switch-row ewe-row">
        <span class="ewe-check__text"><span class="ewe-check__label">Lock before sleep</span></span>
        <Switch on={optIn("lock_on_sleep")} label="Lock before sleep" toggled={(v) => set("lock_on_sleep", v)} />
      </div>
      <div class="ewe-list__divider"></div>
      <div class="ewe-row">
        <span class="ewe-row__text"><span class="ewe-row__title">Lock after</span><span class="ewe-row__desc">Time without using ewe Safe</span></span>
        <span class="ewe-row__trail">
          <select class="ewe-input ewe-input--sm ewe-select" aria-label="Lock after" value={lockAfter} onchange={(e) => set("lock_after_minutes", Number(e.currentTarget.value))}>
            {#each [5, 15, 30, 60, 240, 0] as m (m)}
              <option value={m}>{m === 0 ? "Never" : m < 60 ? `${m} min` : `${m / 60} h`}</option>
            {/each}
          </select>
        </span>
      </div>
      <div class="ewe-list__divider"></div>
      <div class="ewe-row">
        <span class="ewe-row__text"><span class="ewe-row__title">Clear copied passwords after</span></span>
        <span class="ewe-row__trail">
          <div class="ewe-seg ewe-seg--sm" role="radiogroup" aria-label="Clear copied passwords after">
            {#each [10, 30, 90] as sec (sec)}
              <button type="button" class="ewe-seg__item" class:is-selected={clearAfter === sec} role="radio" aria-checked={clearAfter === sec} onclick={() => set("clipboard_clear_seconds", sec)}>{sec} s</button>
            {/each}
          </div>
        </span>
      </div>
      <div class="ewe-list__divider"></div>
      <div class="ewe-switch-row ewe-row">
        <span class="ewe-check__text">
          <span class="ewe-check__label">Unlock with my login password</span>
          <span class="ewe-check__desc">With this on, ewe Safe on this computer is as strong as your login password. Your copy in Nextcloud still needs your master password.</span>
        </span>
        <Switch on={loginOn} disabled={safe.busy === "login-enable" || safe.busy === "login-disable"} label="Unlock with my login password" toggled={onLoginToggle} />
      </div>
      {#if loginOn}
        <div class="ewe-list__divider"></div>
        <div class="ewe-switch-row ewe-row">
          <span class="ewe-check__text">
            <span class="ewe-check__label">Unlock ewe Safe when I sign in</span>
            <span class="ewe-check__desc">Open your safe as the computer starts, with no extra step. Off, ewe Safe waits for your login or master password.</span>
          </span>
          <Switch on={flag("unlock_at_login")} label="Unlock ewe Safe when I sign in" toggled={(v) => set("unlock_at_login", v)} />
        </div>
      {/if}
      <div class="ewe-list__divider"></div>
      <div class="ewe-row">
        <span class="ewe-row__text"><span class="ewe-row__title">Master password</span><span class="ewe-row__desc">Your other computers and phones will ask for the new one once.</span></span>
        <span class="ewe-row__trail"><button type="button" class="ewe-btn ewe-btn--secondary ewe-btn--sm" disabled={safe.readOnly} onclick={() => (pw = { a: "", b: "", error: "" })}>Change…</button></span>
      </div>
      <div class="ewe-list__divider"></div>
      <div class="ewe-row">
        <span class="ewe-row__text"><span class="ewe-row__title">Emergency Kit</span><span class="ewe-row__desc">Where your safe lives, on one printed page.</span></span>
        <span class="ewe-row__trail"><button type="button" class="ewe-btn ewe-btn--secondary ewe-btn--sm" onclick={() => (ui.kit = true)}><Icon name="printer" />Print…</button></span>
      </div>
    </div>

    {@render section("Cards and addresses")}
    <div class="ewe-list">
      <div class="ewe-switch-row ewe-row">
        <span class="ewe-check__text">
          <span class="ewe-check__label">Ask for my password before filling a card</span>
          <span class="ewe-check__desc">ewe Browser fills a card only after you type your password. Once is enough for 5 minutes.</span>
        </span>
        <Switch on={flag("confirm_cards")} label="Ask for my password before filling a card" toggled={(v) => set("confirm_cards", v)} />
      </div>
      <div class="ewe-list__divider"></div>
      <div class="ewe-row">
        <span class="ewe-row__text">
          <span class="ewe-row__title">Cards from an earlier import</span>
          <span class="ewe-row__desc">1Password’s cards and identities that came in as notes. ewe Safe can turn them into cards and addresses.</span>
        </span>
        <span class="ewe-row__trail"><button type="button" class="ewe-btn ewe-btn--secondary ewe-btn--sm" disabled={safe.readOnly || conv?.busy} onclick={checkConvert}>Check…</button></span>
      </div>
    </div>
    <div class="caption safe-muted safe-note"><Icon name="shield-check" /><span>Kept like your passwords. {ENCRYPTED_NOTE}</span></div>
    {#if kr}
      {@render section("Keyring", "Apps keep their passwords here, like ewe Sync’s account. They stay on this computer.")}
      {#if kr.needs_repair}
        <div class="ewe-alert ewe-alert--warning" role="status">
          <Icon name="triangle-alert" />
          <div class="ewe-alert__body">
            <div class="ewe-alert__title">The keyring asks for a password at every start</div>
            <div class="ewe-alert__desc">The fix moves everything into your login keyring, which opens when you sign in. The keyring may ask for the old password one last time. The old keyring stays as a backup.</div>
            <div class="ewe-alert__actions">
              <button type="button" class="ewe-btn ewe-btn--primary ewe-btn--sm" disabled={krBusy} onclick={repairKeyring}><Icon name="key-round" />{krBusy ? "Fixing…" : "Fix the keyring password prompt"}</button>
            </div>
          </div>
        </div>
      {/if}
      <div class="ewe-list">
        <div class="ewe-row">
          <span class="ewe-row__lead ewe-row__lead--tile"><Icon name="key-round" /></span>
          <span class="ewe-row__text">
            <span class="ewe-row__title">{keeper}</span>
            <span class="ewe-row__desc">{keeperLine}</span>
          </span>
          {#if kr.owner !== "none"}
            <span class="ewe-row__trail">
              <span class="ewe-badge ewe-badge--{kr.needs_repair ? 'warning' : 'success'}"><span class="ewe-badge__label">{kr.needs_repair ? "Asks at start" : "Opens at sign-in"}</span></span>
            </span>
          {/if}
        </div>
        {#each krList?.items ?? [] as s (s.id)}
          <div class="ewe-list__divider"></div>
          <div class="ewe-row">
            <span class="ewe-row__lead ewe-row__lead--tile"><Icon name="app-window" /></span>
            <span class="ewe-row__text">
              <span class="ewe-row__title">{s.label || "No name"}</span>
              <span class="ewe-row__desc">{[s.app, s.modified ? day(s.modified) : ""].filter(Boolean).join(" · ")}</span>
            </span>
          </div>
        {/each}
        {#each krList?.locked ?? [] as c (c.collection)}
          <div class="ewe-list__divider"></div>
          <div class="ewe-row">
            <span class="ewe-row__lead ewe-row__lead--tile"><Icon name="lock" /></span>
            <span class="ewe-row__text">
              <span class="ewe-row__title">{c.label || c.collection}</span>
              <span class="ewe-row__desc">Locked · {c.items} {c.items === 1 ? "password" : "passwords"}</span>
            </span>
          </div>
        {/each}
        {#if krList && !krList.items.length && !krList.locked.length && kr.owner !== "none"}
          <div class="ewe-list__divider"></div>
          <div class="ewe-row"><span class="ewe-row__text"><span class="ewe-row__desc">No app passwords yet. Apps add one here when they first need it.</span></span></div>
        {/if}
      </div>
      <div class="caption safe-muted">ewe Safe shows only names and dates here, never the passwords.</div>
    {/if}

    {@render section("Import and export")}
    <div class="ewe-list">
      <div class="ewe-row">
        <span class="ewe-row__lead ewe-row__lead--tile"><Icon name="file-down" /></span>
        <span class="ewe-row__text"><span class="ewe-row__title">Import</span><span class="ewe-row__desc">From 1Password: its export file, its CSV, or straight from the 1Password app.</span></span>
        <span class="ewe-row__trail"><button type="button" class="ewe-btn ewe-btn--secondary ewe-btn--sm" disabled={safe.readOnly} onclick={() => ui.go("import")}>Import…</button></span>
      </div>
      <div class="ewe-list__divider"></div>
      <div class="ewe-row">
        <span class="ewe-row__lead ewe-row__lead--tile"><Icon name="file-key" /></span>
        <span class="ewe-row__text"><span class="ewe-row__title">Export a KeePass copy</span><span class="ewe-row__desc">A .kdbx file. You can give it a different password. Comes in a later version.</span></span>
        <span class="ewe-row__trail"><button type="button" class="ewe-btn ewe-btn--secondary ewe-btn--sm" disabled>Export…</button></span>
      </div>
      <div class="ewe-list__divider"></div>
      <div class="ewe-row">
        <span class="ewe-row__lead ewe-row__lead--tile"><Icon name="file-up" /></span>
        <span class="ewe-row__text"><span class="ewe-row__title">Export as CSV</span><span class="ewe-row__desc">Comes in a later version. <span class="safe-danger">Anyone who gets this file can read every password.</span></span></span>
        <span class="ewe-row__trail"><button type="button" class="ewe-btn ewe-btn--secondary ewe-btn--sm" disabled>Export CSV…</button></span>
      </div>
    </div>

    {@render section("About")}
    <div class="ewe-list">
      <div class="ewe-row">
        <span class="ewe-row__lead ewe-row__lead--tile"><Icon name="vault" /></span>
        <span class="ewe-row__text">
          <span class="ewe-row__title">ewe Safe{safe.status?.version ? ` ${safe.status.version}` : ""}</span>
          <span class="ewe-row__desc">Passwords, passkeys and SSH keys, in a standard KeePass file. Part of ewe.</span>
        </span>
      </div>
    </div>
  </div>
</div>

{#snippet section(title, desc = "")}
  <div class="ewe-section safe-section">
    <div class="ewe-section__text">
      <h2 class="ewe-section__title ewe-section__title--overline">{title}</h2>
      {#if desc}<div class="ewe-section__desc">{desc}</div>{/if}
    </div>
  </div>
{/snippet}

{#if pw}
  <Dialog
    title="Change the master password"
    desc="Your other computers and phones will ask for the new one once. If you forget it, nobody can open your safe."
    icon="key-round"
    onsubmit={changePassword}
    onclose={() => (pw = null)}
  >
    <label class="ewe-field">
      <span class="ewe-field__label"><span>New master password</span></span>
      <span class="ewe-input"><input class="mono" type="password" bind:value={pw.a} autocomplete="new-password" /></span>
    </label>
    {#if pw.a}
      <div class="ewe-meter ewe-meter--{meter.tone}">
        <div class="ewe-meter__head"><Icon name="shield-check" /><span>Strength</span><span class="ewe-meter__value">{meter.label}</span></div>
        <div class="ewe-meter__track"><div class="ewe-meter__fill" style="--value:{meter.pct}%"></div></div>
      </div>
    {/if}
    <label class="ewe-field">
      <span class="ewe-field__label"><span>Type it again</span></span>
      <span class="ewe-input" class:is-error={!!pw.error}><input class="mono" type="password" bind:value={pw.b} autocomplete="new-password" /></span>
    </label>
    {#if pw.error}<div class="ewe-field__helper ewe-field__helper--error"><Icon name="circle-x" /><span>{pw.error}</span></div>{/if}
    {#snippet foot()}
      <button type="button" class="ewe-btn ewe-btn--ghost" onclick={() => (pw = null)}>Cancel</button>
      <button type="submit" class="ewe-btn ewe-btn--primary" disabled={pw.busy}>{pw.busy ? "Changing…" : "Change password"}</button>
    {/snippet}
  </Dialog>
{/if}

{#if login}
  <Dialog
    title="Unlock with my login password"
    desc="With this on, ewe Safe on this computer is as strong as your login password. Your copy in Nextcloud still needs your master password."
    icon="fingerprint"
    onsubmit={enableLogin}
    onclose={() => (login = null)}
  >
    <label class="ewe-field">
      <span class="ewe-field__label"><span>Your login password</span></span>
      <span class="ewe-input" class:is-error={!!login.error}><input type="password" bind:value={login.login} autocomplete="current-password" spellcheck="false" /></span>
    </label>
    {#if safe.locked}
      <label class="ewe-field">
        <span class="ewe-field__label"><span>Master password for ewe Safe</span></span>
        <span class="ewe-input"><input class="mono" type="password" bind:value={login.master} autocomplete="current-password" spellcheck="false" /></span>
      </label>
    {/if}
    {#if login.error}<div class="ewe-field__helper ewe-field__helper--error"><Icon name="circle-x" /><span>{login.error}</span></div>{/if}
    {#snippet foot()}
      <button type="button" class="ewe-btn ewe-btn--ghost" onclick={() => (login = null)}>Cancel</button>
      <button type="submit" class="ewe-btn ewe-btn--primary" disabled={login.busy}>{login.busy ? "Turning on…" : "Turn on"}</button>
    {/snippet}
  </Dialog>
{/if}

{#if conv && !conv.busy}
  <Dialog
    title={conv.converted.length ? `Turn ${conv.converted.length === 1 ? "1 note" : `${conv.converted.length} notes`} into cards and addresses?` : "Nothing to turn into cards"}
    desc={conv.converted.length
      ? `${conv.converted.map((c) => `${c.title} (${c.kind === "card" ? "card" : "address"})`).join(", ")}. Each one keeps its name, tags and folder. The note as it was stays in the item’s history.`
      : "ewe Safe found no note an earlier 1Password import made from a card or an identity."}
    icon="credit-card"
    onclose={() => (conv = null)}
  >
    {#if conv.skipped.length}
      <p class="ewe-dialog__desc">Left as notes: {conv.skipped.map((x) => `${x.title} (${x.reason})`).join("; ")}.</p>
    {/if}
    {#snippet foot()}
      <button type="button" class="ewe-btn ewe-btn--ghost" onclick={() => (conv = null)}>{conv.converted.length ? "Cancel" : "Close"}</button>
      {#if conv.converted.length}
        <button type="button" class="ewe-btn ewe-btn--primary" onclick={runConvert}>Turn them into cards</button>
      {/if}
    {/snippet}
  </Dialog>
{/if}

{#if ui.kit}
  <Dialog label="Emergency Kit" size="lg" onclose={() => (ui.kit = false)}>
    <Kit />
    {#snippet foot()}
      <button type="button" class="ewe-btn ewe-btn--ghost" onclick={() => (ui.kit = false)}>Close</button>
      <button type="button" class="ewe-btn ewe-btn--primary" data-autofocus onclick={() => api.print()}><Icon name="printer" />Print…</button>
    {/snippet}
  </Dialog>
{/if}
