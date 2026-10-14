<script>
  // Settings (the mockup's Settings screen): where the safe lives and how it
  // syncs — shown, never a button (house rule 6: Safe syncs by itself,
  // ewe-sync shows the same state) — how it locks, the master password, the
  // Emergency Kit, import and export. Switches go through ewe-conf.
  import Icon from "../components/Icon.svelte";
  import Switch from "../components/Switch.svelte";
  import Kit from "../components/Kit.svelte";
  import { api } from "../api.js";
  import { safe } from "../safe.svelte.js";
  import { ui } from "../ui.svelte.js";
  import { toasts } from "../toast.svelte.js";
  import { placeIcon, placeLabel, placeLine, strength, syncAlert, syncBadge, when } from "../format.js";

  let server = $state("");
  let pw = $state(null); // the change-password dialog: {a, b, error}
  let now = $state(new Date());

  $effect(() => {
    safe.loadSettings();
    api.cloudStatus().then((c) => (server = c?.signed_in ? c.server ?? "" : ""));
    const t = setInterval(() => (now = new Date()), 30000);
    return () => clearInterval(t);
  });

  const place = $derived(safe.status?.place);
  const sync = $derived(safe.status?.sync);
  const alert = $derived(syncAlert(sync, place, place?.kind === "nextcloud" ? server : "", now));
  const badge = $derived(syncBadge(sync));
  const s = $derived(safe.settings);
  const flag = (k) => s[k] !== false;
  const lockAfter = $derived(Number(s.lock_after_minutes ?? 30));
  const clearAfter = $derived(Number(s.clipboard_clear_seconds ?? 30));

  async function set(key, value) {
    const r = await safe.setSetting(key, value);
    if (!r?.ok) toasts.show(r?.message ?? "Couldn't change the setting.", { icon: "circle-alert" });
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
    } else pw = { a: "", b: "", error: r?.message ?? "Couldn't change it." };
  }
</script>

<div class="ewe-headerbar ewe-headerbar--page" style="padding:var(--space-md) calc(var(--space-md) + var(--space-s)) calc(var(--space-s) + var(--space-xs))">
  <div class="ewe-headerbar__titles">
    <div class="ewe-headerbar__title">Settings</div>
    <div class="ewe-headerbar__subtitle">Where your safe lives, how it locks, and import and export.</div>
  </div>
</div>

<div class="safe-page">
  <div class="safe-page__body">
    <div class="ewe-section"><div class="ewe-section__text"><div class="ewe-section__title ewe-section__title--overline">Place</div></div></div>
    {#if alert}
      <div class="ewe-alert ewe-alert--{alert.tone}" role="status">
        <Icon name={alert.icon} />
        <div class="ewe-alert__body"><div class="ewe-alert__title">{alert.title}</div><div class="ewe-alert__desc">{alert.desc}</div></div>
      </div>
    {/if}
    <div class="ewe-list">
      <div class="ewe-row">
        <span class="ewe-row__lead ewe-row__lead--tile"><Icon name={placeIcon(place)} /></span>
        <span class="ewe-row__text">
          <span class="ewe-row__title">{placeLabel(place)}</span>
          <span class="ewe-row__desc">{placeLine(place, place?.kind === "nextcloud" ? server : "")}</span>
        </span>
        <span class="ewe-row__trail">
          <button class="ewe-btn ewe-btn--secondary ewe-btn--sm" disabled title="Moving a safe comes in a later version"><Icon name="arrow-left-right" />Move safe…</button>
        </span>
      </div>
      {#if sync?.last || sync?.by_machine}
        <div class="ewe-list__divider"></div>
        <div class="ewe-row">
          <span class="ewe-row__lead ewe-row__lead--tile"><Icon name="laptop" /></span>
          <span class="ewe-row__text">
            <span class="ewe-row__title">Last saved</span>
            <span class="ewe-row__desc">{[sync.by_machine ? `By ${sync.by_machine}` : "", when(sync.last, now)].filter(Boolean).join(" · ")}</span>
          </span>
          {#if badge}
            <span class="ewe-row__trail"><span class="ewe-badge ewe-badge--{badge.tone}"><span class="ewe-badge__label">{badge.text}</span></span></span>
          {/if}
        </div>
      {/if}
    </div>
    <div class="caption safe-muted">Safe saves and syncs by itself. ewe-sync shows the same status.</div>

    <div class="ewe-section"><div class="ewe-section__text"><div class="ewe-section__title ewe-section__title--overline">Security</div></div></div>
    <div class="ewe-list">
      <div class="ewe-switch-row ewe-row">
        <span class="ewe-check__text"><span class="ewe-check__label">Lock when the screen locks</span></span>
        <Switch on={flag("lock_on_screen_lock")} label="Lock when the screen locks" toggled={(v) => set("lock_on_screen_lock", v)} />
      </div>
      <div class="ewe-list__divider"></div>
      <div class="ewe-switch-row ewe-row">
        <span class="ewe-check__text"><span class="ewe-check__label">Lock before sleep</span></span>
        <Switch on={flag("lock_on_sleep")} label="Lock before sleep" toggled={(v) => set("lock_on_sleep", v)} />
      </div>
      <div class="ewe-list__divider"></div>
      <div class="ewe-row">
        <span class="ewe-row__text"><span class="ewe-row__title">Lock after</span><span class="ewe-row__desc">Time without using Safe</span></span>
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
          <div class="ewe-seg ewe-seg--sm" role="radiogroup" aria-label="Clear after">
            {#each [10, 30, 90] as sec (sec)}
              <button class="ewe-seg__item" class:is-selected={clearAfter === sec} role="radio" aria-checked={clearAfter === sec} onclick={() => set("clipboard_clear_seconds", sec)}>{sec} s</button>
            {/each}
          </div>
        </span>
      </div>
      <div class="ewe-list__divider"></div>
      <div class="ewe-switch-row ewe-row">
        <span class="ewe-check__text">
          <span class="ewe-check__label">Unlock with login password or fingerprint</span>
          <span class="ewe-check__desc">Not on this computer yet: it needs a one-time setup that comes in a later version. Your master password always works.</span>
        </span>
        <Switch on={false} disabled label="Unlock with login password or fingerprint" />
      </div>
      <div class="ewe-list__divider"></div>
      <div class="ewe-row">
        <span class="ewe-row__text"><span class="ewe-row__title">Master password</span><span class="ewe-row__desc">Your other computers and phones will ask for the new one once.</span></span>
        <span class="ewe-row__trail"><button class="ewe-btn ewe-btn--secondary ewe-btn--sm" disabled={safe.readOnly} onclick={() => (pw = { a: "", b: "", error: "" })}>Change…</button></span>
      </div>
      <div class="ewe-list__divider"></div>
      <div class="ewe-row">
        <span class="ewe-row__text"><span class="ewe-row__title">Emergency Kit</span><span class="ewe-row__desc">Where your safe lives, on one printed page.</span></span>
        <span class="ewe-row__trail"><button class="ewe-btn ewe-btn--secondary ewe-btn--sm" onclick={() => (ui.kit = true)}><Icon name="printer" />Print…</button></span>
      </div>
    </div>

    <div class="ewe-section"><div class="ewe-section__text"><div class="ewe-section__title ewe-section__title--overline">Import and export</div></div></div>
    <div class="ewe-list">
      <div class="ewe-row">
        <span class="ewe-row__lead ewe-row__lead--tile"><Icon name="file-down" /></span>
        <span class="ewe-row__text"><span class="ewe-row__title">Import</span><span class="ewe-row__desc">From 1Password: its export file, its CSV, or straight from the 1Password app.</span></span>
        <span class="ewe-row__trail"><button class="ewe-btn ewe-btn--secondary ewe-btn--sm" disabled={safe.readOnly} onclick={() => ui.go("import")}>Import…</button></span>
      </div>
      <div class="ewe-list__divider"></div>
      <div class="ewe-row">
        <span class="ewe-row__lead ewe-row__lead--tile"><Icon name="file-key" /></span>
        <span class="ewe-row__text"><span class="ewe-row__title">Export a KeePass copy</span><span class="ewe-row__desc">A .kdbx file. You can give it a different password. Comes in a later version.</span></span>
        <span class="ewe-row__trail"><button class="ewe-btn ewe-btn--secondary ewe-btn--sm" disabled>Export…</button></span>
      </div>
      <div class="ewe-list__divider"></div>
      <div class="ewe-row">
        <span class="ewe-row__lead ewe-row__lead--tile"><Icon name="file-up" /></span>
        <span class="ewe-row__text"><span class="ewe-row__title">Export as CSV</span><span class="ewe-row__desc safe-danger">Anyone who gets this file can read every password.</span></span>
        <span class="ewe-row__trail"><button class="ewe-btn ewe-btn--secondary ewe-btn--sm" disabled>Export CSV…</button></span>
      </div>
    </div>
  </div>
</div>

{#if pw}
  <div class="safe-scrim">
    <div role="dialog" aria-modal="true" aria-label="Change the master password"><form class="ewe-dialog" onsubmit={changePassword}>
      <div class="ewe-dialog__head">
        <span class="ewe-dialog__icon"><Icon name="key-round" /></span>
        <div class="ewe-dialog__titles">
          <h3 class="ewe-dialog__title">Change the master password</h3>
          <p class="ewe-dialog__desc">Your other computers and phones will ask for the new one once. If you forget it, nobody can open your safe.</p>
        </div>
      </div>
      <div class="safe-dialog-field">
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
      </div>
      <div class="ewe-dialog__foot">
        <button type="button" class="ewe-btn ewe-btn--ghost" onclick={() => (pw = null)}>Cancel</button>
        <button type="submit" class="ewe-btn ewe-btn--primary" disabled={pw.busy}>{pw.busy ? "Changing…" : "Change password"}</button>
      </div>
    </form></div>
  </div>
{/if}

{#if ui.kit}
  <div class="safe-scrim">
    <div class="ewe-dialog ewe-dialog--lg" role="dialog" aria-label="Emergency Kit" style="padding:var(--space-md);gap:var(--space-md);display:flex;flex-direction:column">
      <Kit />
      <div class="safe-actions safe-actions--split">
        <button class="ewe-btn ewe-btn--ghost" onclick={() => (ui.kit = false)}>Close</button>
        <button class="ewe-btn ewe-btn--secondary" onclick={() => api.print()}><Icon name="printer" />Print…</button>
      </div>
    </div>
  </div>
{/if}
