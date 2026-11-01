<script>
  // One item, as a label/value grid with a copy on each line and no empty
  // rows. A login: username, password (hidden until asked), a live
  // one-time code, its passkey, websites, apps for Super+P, tags, notes. An
  // SSH key: its public key (Copy keeps it on the clipboard), fingerprint,
  // type, passphrase, whether ewe Safe's agent offers it, the hosts that use
  // it and when it was last used (docs/GATE.md S22), and Connect… (the
  // connect sheet). A card: number, security code and PIN hidden until
  // asked, expiry, name on card. An address: each part to copy. Copies go
  // through the daemon (the clipboard clears itself). A revealed value lives
  // here for 30 s at most and goes with the item.
  import { tick, untrack } from "svelte";
  import Icon from "./Icon.svelte";
  import Dialog from "./Dialog.svelte";
  import { api } from "../api.js";
  import { safe } from "../safe.svelte.js";
  import { ui } from "../ui.svelte.js";
  import { toasts } from "../toast.svelte.js";
  import { hostOf, href, letter, shortDay, syncWhere } from "../format.js";
  import { brandName, countryName, expired, expiryShort, grouped, masked } from "../cards.js";
  import { keyTypeName, lastUsed, usedBy } from "../ssh.js";
  import { arrowFocus } from "../trap.js";

  let { item, trash = false } = $props();

  let notes = $state("");
  let shown = $state(""); // the revealed password, briefly
  let revealed = $state({}); // a card's revealed number, code or PIN, briefly
  let full = $state(null); // an address's every part (`show`)
  let otp = $state(null); // {code, left}
  let menu = $state(false);
  let menuEl = $state();
  let unkey = $state(false); // asking before the passkey goes
  let hideTimer;

  const isLogin = $derived(item.kind === "login");
  const isKey = $derived(item.kind === "ssh-key");
  const isCard = $derived(item.kind === "card");
  const isAddress = $derived(item.kind === "address");
  const ICON = { "ssh-key": "terminal", card: "credit-card", address: "map-pin", note: "file-text" };
  const sub = $derived(
    isLogin
      ? [item.urls?.[0] ? hostOf(item.urls[0]) : "", "Login"].filter(Boolean).join(" · ")
      : isKey
        ? ["SSH key", item.ssh?.key_type].filter(Boolean).join(" · ")
        : isCard
          ? ["Card", item.card?.brand && item.card.brand !== "other" ? brandName(item.card.brand) : ""].filter(Boolean).join(" · ")
          : isAddress
            ? "Address"
            : "Note"
  );
  const ADDRESS_ROWS = [
    ["full_name", "Name"],
    ["organization", "Organization"],
    ["line1", "Address line 1"],
    ["line2", "Address line 2"],
    ["city", "City"],
    ["region", "Region"],
    ["postal_code", "Postal code"],
    ["country", "Country"],
    ["phone", "Phone"],
    ["email", "Email"]
  ];
  const foot = $derived(
    [
      item.modified ? `Changed ${shortDay(item.modified)}` : "",
      item.folder ? `In ${item.folder}` : "",
      trash ? "In Trash" : syncWhere(safe.status?.sync, safe.status?.place)
    ]
      .filter(Boolean)
      .join(" · ")
  );

  // a new item: drop what the last one showed, load this one's notes
  $effect(() => {
    const id = item.id;
    void safe.changes;
    shown = "";
    revealed = {};
    full = null;
    otp = null;
    menu = false;
    unkey = false;
    clearTimeout(hideTimer);
    notes = "";
    (async () => {
      const r = await api.show(id, item.kind !== "login");
      if (r?.ok && item.id === id) {
        notes = r.item?.notes ?? "";
        full = r.item?.address ?? null;
      }
    })();
    if (item.has_otp) loadOtp(id);
    // an SSH key: whether the agent is on, the hosts that use it ("Used by")
    if (item.kind === "ssh-key") untrack(() => safe.loadSsh());
    return () => clearTimeout(hideTimer);
  });

  // the code's countdown, a new code when it runs out
  $effect(() => {
    if (!otp) return;
    const t = setInterval(() => {
      if (!otp) return;
      if (otp.left <= 1) loadOtp(item.id);
      else otp = { ...otp, left: otp.left - 1 };
    }, 1000);
    return () => clearInterval(t);
  });

  async function loadOtp(id) {
    const r = await api.reveal(id, "otp");
    if (r?.ok && item.id === id) {
      const v = String(r.value ?? "");
      otp = { code: v.length === 6 ? `${v.slice(0, 3)} ${v.slice(3)}` : v, left: Number(r.expires_in ?? 30) };
    }
  }

  async function toggleReveal() {
    clearTimeout(hideTimer);
    if (shown) {
      shown = "";
      return;
    }
    const v = await safe.reveal(item.id, "password");
    if (v == null) return;
    shown = v;
    hideTimer = setTimeout(() => (shown = ""), 30000);
  }

  /** A card's number, code or PIN, shown for 30 s (one at a time). */
  async function toggleCard(field) {
    clearTimeout(hideTimer);
    if (revealed[field]) {
      revealed = {};
      return;
    }
    const v = await safe.reveal(item.id, field);
    if (v == null) return;
    revealed = { [field]: field === "number" ? grouped(v, item.card?.brand) : v };
    hideTimer = setTimeout(() => (revealed = {}), 30000);
  }

  const WHAT = {
    password: "the password",
    username: "the username",
    otp: "the code",
    public_key: "the public key",
    notes: "the notes",
    number: "the card number",
    security_code: "the security code",
    pin: "the PIN",
    holder: "the name",
    expiry: "the expiry date"
  };
  async function copy(field) {
    // a public key isn't a secret: it stays on the clipboard
    const r = await safe.copy(item.id, field, field === "public_key" ? 0 : undefined);
    if (!r?.ok) {
      toasts.show(r?.message ?? "Couldn’t copy.", { icon: "circle-alert" });
      return;
    }
    const s = Number(r.cleared_after ?? 0);
    const what = WHAT[field] ?? `the ${(ADDRESS_ROWS.find(([k]) => k === field)?.[1] ?? field).toLowerCase()}`;
    toasts.show(s > 0 ? `Copied ${what}. It clears in ${s} s.` : `Copied ${what}.`, {
      icon: "clipboard-copy",
      ms: s > 0 ? Math.min(s, 30) * 1000 : 3000,
      timer: s > 0
    });
  }

  async function toTrash() {
    menu = false;
    const r = await safe.remove(item.id);
    if (r?.ok) {
      toasts.show(`Moved “${item.title}” to Trash.`, { icon: "trash-2" });
      ui.selected = null;
    }
  }

  // the fields and the tag go; the login and its password stay, and the
  // item's history keeps the old version
  async function removePasskey() {
    const r = await safe.edit(item.id, { remove_passkey: true });
    unkey = false;
    if (r?.ok) toasts.show(`Removed the passkey from “${item.title}”.`, { icon: "key-round" });
    else toasts.show(r?.message ?? "Couldn’t remove the passkey.", { icon: "circle-alert" });
  }

  async function restore() {
    const r = await safe.restore(item.id);
    if (r?.ok) {
      toasts.show(`Restored “${item.title}”.`, { icon: "rotate-ccw" });
      ui.selected = null;
    }
  }

  const edit = () => (ui.editing = { mode: "edit", id: item.id, kind: item.kind });

  export function copyPassword() {
    if (isLogin && item.has_password) copy("password");
    else if (isCard && item.card?.has_number) copy("number");
  }
  export function copyUsername() {
    if (isLogin && item.username) copy("username");
  }
</script>

<svelte:window
  onclick={(e) => {
    if (menu && !e.target.closest?.(".safe-rel")) menu = false;
  }}
/>

<div class="safe-dhead">
  <span class="ewe-row__lead ewe-row__lead--tile safe-letter safe-letter--lg" aria-hidden="true">
    {#if isLogin}{letter(item.title)}{:else}<Icon name={ICON[item.kind] ?? "file-text"} />{/if}
  </span>
  <div class="safe-dhead__titles">
    <h2 class="h3 safe-dhead__title">{item.title}</h2>
    <div class="safe-sub">{trash ? `${sub} · in Trash` : sub}</div>
  </div>
  {#if trash}
    <button type="button" class="ewe-btn ewe-btn--secondary" disabled={safe.readOnly} onclick={restore}>
      <Icon name="rotate-ccw" />Restore
    </button>
  {:else}
    {#if isKey}
      <button type="button" class="ewe-btn ewe-btn--secondary" disabled={safe.readOnly} onclick={() => (ui.connect = { key: item.id })}>
        <Icon name="link" />Connect…
      </button>
    {/if}
    <button type="button" class="ewe-btn ewe-btn--secondary" disabled={safe.readOnly} onclick={edit}>
      <Icon name="pencil" />Edit
    </button>
    <div class="safe-rel">
      <button
        type="button"
        class="ewe-iconbtn ewe-iconbtn--ghost"
        aria-label="More for {item.title}"
        aria-haspopup="menu"
        aria-expanded={menu}
        onclick={async () => {
          menu = !menu;
          if (menu) {
            await tick();
            menuEl?.querySelector(".ewe-menu__item:not([disabled])")?.focus();
          }
        }}><Icon name="ellipsis" /></button
      >
      {#if menu}
        <div class="ewe-menu safe-menu" role="menu" tabindex="-1" bind:this={menuEl} onkeydown={(e) => (e.key === "Escape" ? (menu = false) : arrowFocus(e, menuEl, ".ewe-menu__item"))}>
          <button type="button" class="ewe-menu__item ewe-menu__item--danger" role="menuitem" disabled={safe.readOnly} onclick={toTrash}
            ><Icon name="trash-2" />Move to Trash</button
          >
        </div>
      {/if}
    </div>
  {/if}
</div>

<dl class="ewe-list safe-kv">
  {#if isLogin}
    {#if item.username}{@render text("Username", item.username, "username")}{/if}
    {#if item.has_password}{@render secret("Password", shown, "••••••••••••", toggleReveal, "password")}{/if}
    {#if item.has_otp}
      <div class="safe-kv__row">
        <dt class="safe-kv__label">One-time code</dt>
        <dd class="safe-kv__value">
          <span class="mono-numeric safe-otp">{otp?.code ?? "··· ···"}</span>
          {#if otp}<span class="caption safe-muted safe-tabular" aria-label="Seconds left">{otp.left} s</span>{/if}
        </dd>
        <dd class="safe-kv__actions">{@render copyBtn("otp", "Copy the one-time code")}</dd>
      </div>
    {/if}
    {#if item.passkey}
      <div class="safe-kv__row">
        <dt class="safe-kv__label">Passkey</dt>
        <dd class="safe-kv__value">
          Saved for {item.passkey.rp_id}{item.passkey.username && item.passkey.username !== item.username ? ` · ${item.passkey.username}` : ""}
        </dd>
        <dd class="safe-kv__actions">
          {#if !trash}<button type="button" class="ewe-btn ewe-btn--ghost ewe-btn--sm" disabled={safe.readOnly} onclick={() => (unkey = true)}>Remove…</button>{/if}
        </dd>
      </div>
    {/if}
    {#each item.urls ?? [] as url, n (url)}
      <div class="safe-kv__row">
        <dt class="safe-kv__label">{n ? "" : (item.urls.length > 1 ? "Websites" : "Website")}</dt>
        <dd class="safe-kv__value"><button type="button" class="ewe-link safe-url" onclick={() => api.openUrl(href(url))}>{url.replace(/^https?:\/\//, "")}</button></dd>
        <dd class="safe-kv__actions">
          <button type="button" class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm" aria-label="Open {hostOf(url)} in ewe Browser" title="Open in ewe Browser" onclick={() => api.openUrl(href(url))}
            ><Icon name="external-link" /></button
          >
        </dd>
      </div>
    {/each}
    {#if item.apps?.length}
      <div class="safe-kv__row">
        <dt class="safe-kv__label">Apps</dt>
        <dd class="safe-kv__value safe-kv__value--stack">
          <span class="safe-chips">{#each item.apps as app (app)}<span class="ewe-tag"><Icon name="app-window" />{app}</span>{/each}</span>
          <span class="caption safe-muted">Super+P fills this login in these apps.</span>
        </dd>
        <dd class="safe-kv__actions"></dd>
      </div>
    {/if}
    {@render extras()}
    {#if !item.username && !item.has_password && !item.has_otp && !item.passkey && !item.urls?.length && !item.apps?.length && !item.tags?.length && !notes}
      {@render nothing("Nothing saved in this login yet.")}
    {/if}
  {:else if isKey}
    {@const used = usedBy(safe.ssh.hosts, item.id)}
    {@const agentOn = safe.ssh.status?.enabled}
    {#if item.ssh?.public_key}
      <div class="safe-kv__row safe-kv__row--top">
        <dt class="safe-kv__label">Public key</dt>
        <dd class="safe-kv__value mono safe-key">{item.ssh.public_key}</dd>
        <dd class="safe-kv__actions">{@render copyBtn("public_key", "Copy the public key")}</dd>
      </div>
    {/if}
    {#if item.ssh?.fingerprint}
      <div class="safe-kv__row">
        <dt class="safe-kv__label">Fingerprint</dt>
        <dd class="safe-kv__value mono safe-key">{item.ssh.fingerprint}</dd>
        <dd class="safe-kv__actions"></dd>
      </div>
    {/if}
    {#if item.ssh?.key_type}
      <div class="safe-kv__row">
        <dt class="safe-kv__label">Type</dt>
        <dd class="safe-kv__value">{keyTypeName(item.ssh.key_type)}</dd>
        <dd class="safe-kv__actions"></dd>
      </div>
    {/if}
    {#if item.has_password}{@render secret("Passphrase", shown, "••••••••••••", toggleReveal, "password")}{/if}
    <div class="safe-kv__row">
      <dt class="safe-kv__label">SSH agent</dt>
      <dd class="safe-kv__value safe-kv__value--stack">
        {#if !item.ssh?.agent}
          <span>Not offered: the key’s KeeAgent setting keeps it out of agents.</span>
        {:else if agentOn === false}
          <span>ewe Safe’s SSH agent is off, so ssh doesn’t ask for this key.</span>
        {:else}
          <span>ssh and git can use it through ewe Safe.</span>
        {/if}
      </dd>
      <dd class="safe-kv__actions">
        {#if item.ssh?.agent && agentOn === false && !trash}
          <button type="button" class="ewe-btn ewe-btn--ghost ewe-btn--sm" onclick={() => ui.go("ssh")}>Open SSH</button>
        {/if}
      </dd>
    </div>
    {#if !trash}
      <div class="safe-kv__row">
        <dt class="safe-kv__label">Used by</dt>
        <dd class="safe-kv__value">
          {#if used.length}
            <span class="safe-chips">{#each used as h (h.alias)}<span class="ewe-tag"><Icon name="server" />{h.alias}</span>{/each}</span>
          {:else}
            <span class="safe-muted">No host yet</span>
          {/if}
        </dd>
        <dd class="safe-kv__actions">
          {#if !used.length}<button type="button" class="ewe-btn ewe-btn--ghost ewe-btn--sm" disabled={safe.readOnly} onclick={() => (ui.connect = { key: item.id })}>Connect…</button>{/if}
        </dd>
      </div>
      <div class="safe-kv__row">
        <dt class="safe-kv__label">Last used</dt>
        <dd class="safe-kv__value">{lastUsed(item.ssh?.last_used).replace(/^Last used /, "")}</dd>
        <dd class="safe-kv__actions"></dd>
      </div>
    {/if}
    {@render extras()}
  {:else if isCard}
    {@const c = item.card ?? {}}
    {#if c.has_number}{@render cardSecret("number", "Card number", masked(c.last4, c.brand))}{/if}
    {#if c.has_security_code}{@render cardSecret("security_code", "Security code", "•••")}{/if}
    {#if c.has_pin}{@render cardSecret("pin", "PIN", "••••")}{/if}
    {#if c.expiry}
      <div class="safe-kv__row">
        <dt class="safe-kv__label">Expiry date</dt>
        <dd class="safe-kv__value">
          <span class="mono-numeric">{expiryShort(c.expiry)}</span>
          {#if expired(c.expiry)}<span class="ewe-badge ewe-badge--warning"><span class="ewe-badge__label">Expired</span></span>{/if}
        </dd>
        <dd class="safe-kv__actions">{@render copyBtn("expiry", "Copy the expiry date")}</dd>
      </div>
    {/if}
    {#if c.holder}{@render text("Name on card", c.holder, "holder")}{/if}
    {#if !c.has_number && !c.has_security_code && !c.has_pin && !c.expiry && !c.holder}
      {@render nothing("No card details yet.")}
    {/if}
    {@render extras()}
  {:else if isAddress}
    {@const a = full ?? item.address ?? {}}
    {@const parts = ADDRESS_ROWS.filter(([k]) => a[k])}
    {#each parts as [field, label] (field)}
      {@render text(label, field === "country" ? countryName(a.country) : a[field], field)}
    {:else}
      {@render nothing("No address details yet.")}
    {/each}
    {@render extras()}
  {:else}
    {#if notes}
      <div class="safe-kv__row safe-kv__row--top">
        <dt class="safe-kv__label">Note</dt>
        <dd class="safe-kv__value safe-notes">{notes}</dd>
        <dd class="safe-kv__actions">{@render copyBtn("notes", "Copy the note")}</dd>
      </div>
    {:else}
      {@render nothing("This note is empty.")}
    {/if}
    {#if item.tags?.length}{@render tagsRow()}{/if}
  {/if}
</dl>

{#if foot}<div class="caption safe-muted safe-foot">{foot}</div>{/if}

{#if unkey}
  <Dialog
    title="Remove the passkey?"
    desc="You won’t be able to sign in to {item.passkey?.rp_id} with it. The login and its password stay. Remove the passkey on the site too."
    icon="key-round"
    tone="danger"
    onclose={() => (unkey = false)}
  >
    {#snippet foot()}
      <button type="button" class="ewe-btn ewe-btn--ghost" data-autofocus onclick={() => (unkey = false)}>Keep it</button>
      <button type="button" class="ewe-btn ewe-btn--danger" disabled={safe.busy === "edit"} onclick={removePasskey}>Remove passkey</button>
    {/snippet}
  </Dialog>
{/if}

{#snippet copyBtn(field, label)}
  <button type="button" class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm" aria-label={label} title={label} onclick={() => copy(field)}>
    <Icon name="copy" />
  </button>
{/snippet}

{#snippet text(label, value, field)}
  <div class="safe-kv__row">
    <dt class="safe-kv__label">{label}</dt>
    <dd class="safe-kv__value">{value}</dd>
    <dd class="safe-kv__actions">{@render copyBtn(field, `Copy the ${label.toLowerCase()}`)}</dd>
  </div>
{/snippet}

{#snippet secret(label, value, dots, toggle, field)}
  <div class="safe-kv__row">
    <dt class="safe-kv__label">{label}</dt>
    <dd class="safe-kv__value"><span class="mono safe-secret" class:is-hidden={!value}>{value || dots}</span></dd>
    <dd class="safe-kv__actions">
      <button
        type="button"
        class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm"
        aria-label={value ? `Hide the ${label.toLowerCase()}` : `Show the ${label.toLowerCase()}`}
        title={value ? "Hide" : "Show for 30 s"}
        onclick={toggle}><Icon name={value ? "eye-off" : "eye"} /></button
      >
      {@render copyBtn(field, `Copy the ${label.toLowerCase()}`)}
    </dd>
  </div>
{/snippet}

{#snippet cardSecret(field, label, dots)}
  {@render secret(label, revealed[field], dots, () => toggleCard(field), field)}
{/snippet}

{#snippet tagsRow()}
  <div class="safe-kv__row">
    <dt class="safe-kv__label">Tags</dt>
    <dd class="safe-kv__value"><span class="safe-chips">{#each item.tags as tag (tag)}<span class="ewe-tag">{tag}</span>{/each}</span></dd>
    <dd class="safe-kv__actions"></dd>
  </div>
{/snippet}

<!-- tags and notes, under every kind but a note -->
{#snippet extras()}
  {#if item.tags?.length}{@render tagsRow()}{/if}
  {#if notes}
    <div class="safe-kv__row safe-kv__row--top">
      <dt class="safe-kv__label">Notes</dt>
      <dd class="safe-kv__value safe-notes">{notes}</dd>
      <dd class="safe-kv__actions">{@render copyBtn("notes", "Copy the notes")}</dd>
    </div>
  {/if}
{/snippet}

<!-- an item with nothing in it: say so, and the way to fill it -->
{#snippet nothing(what)}
  <div class="safe-kv__row safe-kv__row--empty">
    <dt class="safe-kv__label">{what}</dt>
    <dd class="safe-kv__value"></dd>
    <dd class="safe-kv__actions">
      {#if !trash}<button type="button" class="ewe-btn ewe-btn--ghost ewe-btn--sm" disabled={safe.readOnly} onclick={edit}><Icon name="pencil" />Add details</button>{/if}
    </dd>
  </div>
{/snippet}
