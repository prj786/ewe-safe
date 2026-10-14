<script>
  // One item (the mockup's Items screen, right half): its fields with the
  // password hidden until asked, copies through the daemon (the clipboard
  // clears itself), a live one-time code, websites, apps, tags, notes.
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
  let hideTimer;

  const isLogin = $derived(item.kind === "login");
  const sub = $derived(
    isLogin ? [item.urls?.[0] ? hostOf(item.urls[0]) : "", "Login"].filter(Boolean).join(" · ") : "Note"
  );
  const C = 2 * Math.PI * 11; // the ring's circumference (r = 11 in a 24 box)

  // a new item: drop what the last one showed, load this one's notes
  $effect(() => {
    const id = item.id;
    void safe.changes;
    shown = "";
    otp = null;
    menu = false;
    clearTimeout(hideTimer);
    notes = "";
    (async () => {
      const r = await api.show(id, item.kind === "note");
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

  const WHAT = { password: "the password", username: "the username", otp: "the code" };
  async function copy(field) {
    const r = await safe.copy(item.id, field);
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
