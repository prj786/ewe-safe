<script>
  // One item (the mockup's Items screen, right half): its fields with the
  // password hidden until asked, copies through the daemon (the clipboard
  // clears itself), a live one-time code, websites, apps, tags, notes. An
  // SSH key shows its public key (Copy, kept on the clipboard), fingerprint,
  // type and whether the agent offers it.
  // A revealed value lives here for 30 s at most and goes with the item.
  import Icon from "./Icon.svelte";
  import { api } from "../api.js";
  import { safe } from "../safe.svelte.js";
  import { ui } from "../ui.svelte.js";
  import { toasts } from "../toast.svelte.js";
  import { day, hostOf, href, letter } from "../format.js";

  let { item, trash = false } = $props();

  let notes = $state("");
  let shown = $state(""); // the revealed password, briefly
  let otp = $state(null); // {code, left}
  let menu = $state(false);
  let unkey = $state(false); // asking before the passkey goes
  let hideTimer;

  const isLogin = $derived(item.kind === "login");
  const isKey = $derived(item.kind === "ssh-key");
  const sub = $derived(
    isLogin
      ? [item.urls?.[0] ? hostOf(item.urls[0]) : "", "Login"].filter(Boolean).join(" · ")
      : isKey
        ? ["SSH key", item.ssh?.key_type].filter(Boolean).join(" · ")
        : "Note"
  );
  const C = 2 * Math.PI * 11; // the ring's circumference (r = 11 in a 24 box)

  // a new item: drop what the last one showed, load this one's notes
  $effect(() => {
    const id = item.id;
    void safe.changes;
    shown = "";
    otp = null;
    menu = false;
    unkey = false;
    clearTimeout(hideTimer);
    notes = "";
    (async () => {
      const r = await api.show(id, item.kind !== "login");
      if (r?.ok && item.id === id) notes = r.item?.notes ?? "";
    })();
    if (item.has_otp) loadOtp(id);
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

  const WHAT = {
    password: "the password",
    username: "the username",
    otp: "the code",
    public_key: "the public key"
  };
  async function copy(field) {
    // a public key isn't a secret: it stays on the clipboard
    const r = await safe.copy(item.id, field, field === "public_key" ? 0 : undefined);
    if (!r?.ok) {
      toasts.show(r?.message ?? "Couldn't copy.", { icon: "circle-alert" });
      return;
    }
    const s = Number(r.cleared_after ?? 0);
    toasts.show(
      s > 0 ? `Copied ${WHAT[field]}. It clears in ${s} s.` : `Copied ${WHAT[field]}.`,
      { icon: "clipboard-copy", ms: s > 0 ? Math.min(s, 30) * 1000 : 3000, timer: s > 0 }
    );
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
    else toasts.show(r?.message ?? "Couldn't remove the passkey.", { icon: "circle-alert" });
  }

  async function restore() {
    const r = await safe.restore(item.id);
    if (r?.ok) {
      toasts.show(`Restored “${item.title}”.`, { icon: "rotate-ccw" });
      ui.selected = null;
    }
  }

  export function copyPassword() {
    if (isLogin && item.has_password) copy("password");
  }
  export function copyUsername() {
    if (isLogin && item.username) copy("username");
  }
</script>

<div class="safe-dhead">
  {#if isLogin}
    <span class="safe-letter safe-letter--lg">{letter(item.title)}</span>
  {:else if isKey}
    <span class="safe-letter safe-letter--lg"><Icon name="terminal" /></span>
  {:else}
    <span class="safe-letter safe-letter--lg"><Icon name="sticky-note" /></span>
  {/if}
  <div class="safe-dhead__titles">
    <div class="h3">{item.title}</div>
    <div class="caption">{trash ? `${sub} · in Trash` : sub}</div>
  </div>
  {#if trash}
    <button class="ewe-btn ewe-btn--secondary ewe-btn--sm" disabled={safe.readOnly} onclick={restore}>
      <Icon name="rotate-ccw" />Restore
    </button>
  {:else}
    <button
      class="ewe-btn ewe-btn--secondary ewe-btn--sm"
      disabled={safe.readOnly}
      onclick={() => (ui.editing = { mode: "edit", id: item.id, kind: item.kind })}
    >
      <Icon name="pencil" />Edit
    </button>
    <div class="safe-rel">
      <button
        class="ewe-iconbtn ewe-iconbtn--ghost"
        aria-label="More"
        aria-expanded={menu}
        onclick={() => (menu = !menu)}><Icon name="ellipsis" /></button
      >
      {#if menu}
        <div class="ewe-menu safe-menu" role="menu">
          <button
            class="ewe-menu__item ewe-menu__item--danger"
            role="menuitem"
            disabled={safe.readOnly}
            onclick={toTrash}><Icon name="trash-2" />Move to Trash</button
          >
        </div>
      {/if}
    </div>
  {/if}
</div>

{#if isLogin}
  <div class="ewe-list">
    <div class="ewe-row">
      <span class="ewe-row__text"><span class="ewe-row__title">Username</span></span>
      <span class="ewe-row__trail">
        <span class="safe-val">{item.username || "—"}</span>
        {#if item.username}
          <button class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm" aria-label="Copy username" onclick={() => copy("username")}>
            <Icon name="copy" />
          </button>
        {/if}
      </span>
    </div>
    {#if item.has_password}
      <div class="ewe-list__divider"></div>
      <div class="ewe-row">
        <span class="ewe-row__text"><span class="ewe-row__title">Password</span></span>
        <span class="ewe-row__trail">
          <span class="safe-val"><span class="mono safe-val--secret">{shown || "••••••••••••"}</span></span>
          <button
            class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm"
            aria-label={shown ? "Hide password" : "Show password"}
            onclick={toggleReveal}><Icon name={shown ? "eye-off" : "eye"} /></button
          >
          <button class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm" aria-label="Copy password" onclick={() => copy("password")}>
            <Icon name="copy" />
          </button>
        </span>
      </div>
    {/if}
    {#if item.has_otp}
      <div class="ewe-list__divider"></div>
      <div class="ewe-row">
        <span class="ewe-row__text">
          <span class="ewe-row__title">One-time code</span>
          <span class="ewe-row__desc">Changes every 30 seconds</span>
        </span>
        <span class="ewe-row__trail">
          <span class="safe-val"><span class="mono-numeric safe-otp">{otp?.code ?? "··· ···"}</span></span>
          <span class="ewe-ring" style="--size:var(--icon-lg)" aria-label="Seconds left">
            <svg viewBox="0 0 24 24"
              ><circle class="ewe-ring__track" cx="12" cy="12" r="11" stroke-width="2" /><circle
                class="ewe-ring__fill"
                cx="12"
                cy="12"
                r="11"
                stroke-width="2"
                stroke-dasharray={C}
                stroke-dashoffset={C * (1 - (otp?.left ?? 0) / 30)}
              /></svg
            >
          </span>
          <button class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm" aria-label="Copy code" onclick={() => copy("otp")}>
            <Icon name="copy" />
          </button>
        </span>
      </div>
    {/if}
    {#if item.passkey}
      <div class="ewe-list__divider"></div>
      <div class="ewe-row">
        <span class="ewe-row__lead ewe-row__lead--tile"><Icon name="key-round" /></span>
        <span class="ewe-row__text">
          <span class="ewe-row__title">Passkey</span>
          <span class="ewe-row__desc">{[item.passkey.rp_id, item.passkey.username].filter(Boolean).join(" · ")}</span>
        </span>
        {#if !trash}
          <span class="ewe-row__trail">
            <button class="ewe-btn ewe-btn--ghost ewe-btn--sm" disabled={safe.readOnly} onclick={() => (unkey = true)}>Remove</button>
          </span>
        {/if}
      </div>
    {/if}
  </div>

  <div class="ewe-list">
    <div class="ewe-row">
      <span class="ewe-row__text"><span class="ewe-row__title">Websites</span></span>
      <span class="ewe-row__trail">
        <span class="safe-chips">
          {#each item.urls ?? [] as url (url)}
            <button class="ewe-link" onclick={() => api.openUrl(href(url))}>{url.replace(/^https?:\/\//, "")}<Icon name="external-link" /></button>
          {:else}
            <span class="safe-muted">None</span>
          {/each}
        </span>
      </span>
    </div>
    <div class="ewe-list__divider"></div>
    <div class="ewe-row">
      <span class="ewe-row__text">
        <span class="ewe-row__title">Apps</span>
        <span class="ewe-row__desc">Super+P fills this login in these apps</span>
      </span>
      <span class="ewe-row__trail">
        <span class="safe-chips">
          {#each item.apps ?? [] as app (app)}
            <span class="ewe-tag"><Icon name="app-window" />{app}</span>
          {:else}
            <span class="safe-muted">None</span>
          {/each}
        </span>
      </span>
    </div>
    {#if item.tags?.length}
      <div class="ewe-list__divider"></div>
      <div class="ewe-row">
        <span class="ewe-row__text"><span class="ewe-row__title">Tags</span></span>
        <span class="ewe-row__trail">
          <span class="safe-chips">
            {#each item.tags as tag (tag)}<span class="ewe-tag">{tag}</span>{/each}
          </span>
        </span>
      </div>
    {/if}
    {#if notes}
      <div class="ewe-list__divider"></div>
      <div class="ewe-row">
        <span class="ewe-row__text">
          <span class="ewe-row__title">Notes</span>
          <span class="ewe-row__desc safe-notes">{notes}</span>
        </span>
      </div>
    {/if}
  </div>
{:else if isKey}
  <div class="ewe-list">
    <div class="ewe-row">
      <span class="ewe-row__text">
        <span class="ewe-row__title">Public key</span>
        <span class="ewe-row__desc mono safe-key">{item.ssh?.public_key || "—"}</span>
      </span>
      {#if item.ssh?.public_key}
        <span class="ewe-row__trail">
          <button class="ewe-btn ewe-btn--secondary ewe-btn--sm" onclick={() => copy("public_key")}>
            <Icon name="copy" />Copy
          </button>
        </span>
      {/if}
    </div>
    <div class="ewe-list__divider"></div>
    <div class="ewe-row">
      <span class="ewe-row__text"><span class="ewe-row__title">Fingerprint</span></span>
      <span class="ewe-row__trail"><span class="safe-val mono">{item.ssh?.fingerprint || "—"}</span></span>
    </div>
    <div class="ewe-list__divider"></div>
    <div class="ewe-row">
      <span class="ewe-row__text"><span class="ewe-row__title">Type</span></span>
      <span class="ewe-row__trail"><span class="safe-val">{item.ssh?.key_type || "—"}</span></span>
    </div>
    {#if item.has_password}
      <div class="ewe-list__divider"></div>
      <div class="ewe-row">
        <span class="ewe-row__text"><span class="ewe-row__title">Passphrase</span></span>
        <span class="ewe-row__trail">
          <span class="safe-val"><span class="mono safe-val--secret">{shown || "••••••••••••"}</span></span>
          <button
            class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm"
            aria-label={shown ? "Hide passphrase" : "Show passphrase"}
            onclick={toggleReveal}><Icon name={shown ? "eye-off" : "eye"} /></button
          >
        </span>
      </div>
    {/if}
    <div class="ewe-list__divider"></div>
    <div class="ewe-row">
      <span class="ewe-row__text">
        <span class="ewe-row__title">SSH agent</span>
        <span class="ewe-row__desc">{item.ssh?.agent ? "ssh and git can use this key through Safe" : "Agents may not use this key (its KeeAgent setting)"}</span>
      </span>
      <span class="ewe-row__trail"><Icon name={item.ssh?.agent ? "circle-check" : "circle-x"} /></span>
    </div>
  </div>
  {#if item.tags?.length || notes}
    <div class="ewe-list">
      {#if item.tags?.length}
        <div class="ewe-row">
          <span class="ewe-row__text"><span class="ewe-row__title">Tags</span></span>
          <span class="ewe-row__trail">
            <span class="safe-chips">
              {#each item.tags as tag (tag)}<span class="ewe-tag">{tag}</span>{/each}
            </span>
          </span>
        </div>
      {/if}
      {#if notes}
        {#if item.tags?.length}<div class="ewe-list__divider"></div>{/if}
        <div class="ewe-row">
          <span class="ewe-row__text">
            <span class="ewe-row__title">Notes</span>
            <span class="ewe-row__desc safe-notes">{notes}</span>
          </span>
        </div>
      {/if}
    </div>
  {/if}
{:else}
  <div class="ewe-list">
    <div class="ewe-row">
      <span class="ewe-row__text">
        <span class="ewe-row__title">Note</span>
        <span class="ewe-row__desc safe-notes">{notes || "—"}</span>
      </span>
    </div>
    {#if item.tags?.length}
      <div class="ewe-list__divider"></div>
      <div class="ewe-row">
        <span class="ewe-row__text"><span class="ewe-row__title">Tags</span></span>
        <span class="ewe-row__trail">
          <span class="safe-chips">
            {#each item.tags as tag (tag)}<span class="ewe-tag">{tag}</span>{/each}
          </span>
        </span>
      </div>
    {/if}
  </div>
{/if}

{#if item.modified}
  <div class="safe-foot caption"><span>Changed {day(item.modified)}</span>{#if item.folder}<span>In {item.folder}</span>{/if}</div>
{/if}

{#if unkey}
  <div class="safe-scrim">
    <div class="ewe-dialog" role="dialog" aria-modal="true" aria-label="Remove the passkey">
      <div class="ewe-dialog__head">
        <span class="ewe-dialog__icon"><Icon name="key-round" /></span>
        <div class="ewe-dialog__titles">
          <h3 class="ewe-dialog__title">Remove the passkey?</h3>
          <p class="ewe-dialog__desc">
            You won't be able to sign in to {item.passkey?.rp_id} with it. The login and its password stay. Remove the passkey on the
            site too.
          </p>
        </div>
      </div>
      <div class="ewe-dialog__foot">
        <button class="ewe-btn ewe-btn--ghost" onclick={() => (unkey = false)}>Keep it</button>
        <button class="ewe-btn ewe-btn--danger" disabled={safe.busy === "edit"} onclick={removePasskey}>Remove passkey</button>
      </div>
    </div>
  </div>
{/if}
