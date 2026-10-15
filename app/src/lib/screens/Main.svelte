<script>
  // The unlocked window (App shell card): side navigation, a header with
  // search, New and Lock, then the list and the item — or Settings, Import.
  // Keyboard first: type anywhere to search, arrows move, Enter or Ctrl+C
  // copies the password, Ctrl+Shift+C the username, Ctrl+N is a new login,
  // Ctrl+L locks, Esc steps back.
  import Icon from "../components/Icon.svelte";
  import Sidenav from "../components/Sidenav.svelte";
  import ItemDetail from "../components/ItemDetail.svelte";
  import ItemEdit from "../components/ItemEdit.svelte";
  import Toasts from "../components/Toasts.svelte";
  import Settings from "./Settings.svelte";
  import Import from "./Import.svelte";
  import { safe } from "../safe.svelte.js";
  import { ui } from "../ui.svelte.js";
  import { hostOf, letter } from "../format.js";

  let search = $state();
  let detail = $state();
  let listEl = $state();

  const f = $derived(ui.filter);
  const base = $derived.by(() => {
    if (f.trash) return safe.deleted;
    return safe.items.filter(
      (i) =>
        (!f.kind || i.kind === f.kind) &&
        (!f.tag || (i.tags ?? []).includes(f.tag)) &&
        (!f.folder || i.folder === f.folder || i.folder?.startsWith(f.folder + "/"))
    );
  });
  const shown = $derived.by(() => {
    const q = ui.query.trim().toLowerCase();
    if (!q) return base;
    const score = (i) => {
      const t = i.title.toLowerCase();
      if (t.startsWith(q)) return 0;
      if (t.includes(q)) return 1;
      if ((i.username ?? "").toLowerCase().includes(q)) return 2;
      if ((i.urls ?? []).some((u) => u.toLowerCase().includes(q))) return 3;
      if ([...(i.tags ?? []), ...(i.apps ?? [])].some((x) => x.toLowerCase().includes(q))) return 4;
      return 9;
    };
    return base
      .map((i) => [score(i), i])
      .filter(([s]) => s < 9)
      .sort((a, b) => a[0] - b[0] || a[1].title.localeCompare(b[1].title))
      .map(([, i]) => i);
  });
  const current = $derived(shown.find((i) => i.id === ui.selected) ?? shown[0] ?? null);
  const editItem = $derived(
    ui.editing?.mode === "edit" ? safe.items.find((i) => i.id === ui.editing.id) ?? null : null
  );
  const title = $derived(
    f.trash ? "Trash" : f.kind === "login" ? "Logins" : f.kind === "note" ? "Notes" : f.tag || f.folder.split("/").pop() || "All items"
  );
  const subtitle = $derived(
    `${base.length === 0 ? "Empty" : base.length === 1 ? "1 item" : `${base.length} items`}${safe.readOnly ? " · read-only" : ""}`
  );

  function newItem(kind = "login") {
    if (safe.readOnly) return;
    ui.view = "items";
    ui.filter = { ...ui.filter, trash: false };
    ui.editing = { mode: "new", kind };
  }

  function move(by) {
    if (!shown.length) return;
    const at = Math.max(0, shown.findIndex((i) => i.id === current?.id));
    const next = shown[Math.min(shown.length - 1, Math.max(0, at + by))];
    ui.selected = next.id;
    listEl?.querySelector(`[data-id="${next.id}"]`)?.scrollIntoView({ block: "nearest" });
  }

  function typing(t) {
    return t instanceof HTMLInputElement || t instanceof HTMLTextAreaElement;
  }

  function onkey(e) {
    if (ui.view !== "items") {
      if (e.key === "Escape") ui.go("items");
      return;
    }
    const ctrl = e.ctrlKey || e.metaKey;
    if (ctrl && e.key.toLowerCase() === "f") {
      e.preventDefault();
      search?.focus();
      search?.select();
    } else if (ctrl && e.key.toLowerCase() === "n") {
      e.preventDefault();
      newItem();
    } else if (ctrl && e.key.toLowerCase() === "l") {
      e.preventDefault();
      safe.lock();
    } else if (ui.editing) {
      if (e.key === "Escape") ui.editing = null;
    } else if (ctrl && e.key.toLowerCase() === "c" && !window.getSelection()?.toString() && !(typing(e.target) && e.target !== search)) {
      e.preventDefault();
      if (e.shiftKey) detail?.copyUsername();
      else detail?.copyPassword();
    } else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      if (typing(e.target) && e.target !== search) return;
      e.preventDefault();
      move(e.key === "ArrowDown" ? 1 : -1);
    } else if (e.key === "Enter" && (e.target === search || e.target?.dataset?.id)) {
      e.preventDefault();
      if (e.target === search) {
        if (current) {
          ui.selected = current.id;
          listEl?.querySelector(`[data-id="${current.id}"]`)?.focus();
        }
      } else detail?.copyPassword();
    } else if (e.key === "Escape") {
      if (ui.query) ui.query = "";
      else document.activeElement?.blur?.();
    } else if (e.key.length === 1 && !ctrl && !e.altKey && !typing(e.target) && e.key !== " ") {
      // type to search
      search?.focus();
    }
  }
</script>

<svelte:window onkeydown={onkey} />

<div class="ewe-appwin safe-win">
  <Sidenav />
  <div class="safe-pane">
    {#if ui.view === "settings"}
      <Settings />
    {:else if ui.view === "import"}
      <Import />
    {:else}
      <div class="ewe-headerbar">
        <div class="ewe-headerbar__titles">
          <div class="ewe-headerbar__title">{title}</div>
          <div class="ewe-headerbar__subtitle">{subtitle}</div>
        </div>
        <div class="ewe-headerbar__actions">
          <div class="safe-search">
            <label class="ewe-input ewe-input--sm">
              <Icon name="search" />
              <input bind:this={search} bind:value={ui.query} placeholder="Search Safe" aria-label="Search Safe" spellcheck="false" />
              <span class="ewe-kbd-combo"><kbd class="ewe-kbd">Ctrl</kbd><span>+</span><kbd class="ewe-kbd">F</kbd></span>
            </label>
          </div>
          <button class="ewe-btn ewe-btn--primary ewe-btn--sm" disabled={safe.readOnly || f.trash} onclick={() => newItem(f.kind === "note" ? "note" : "login")}>
            <Icon name="plus" />New
          </button>
          <button class="ewe-iconbtn ewe-iconbtn--ghost" aria-label="Lock Safe" title="Lock (Ctrl+L)" onclick={() => safe.lock()}>
            <Icon name="lock" />
          </button>
        </div>
      </div>

      {#if safe.readOnly}
        <div class="ewe-alert ewe-alert--warning" role="status" style="margin:0 calc(var(--space-md) + var(--space-s)) var(--space-s)">
          <Icon name="shield-alert" />
          <div class="ewe-alert__body">
            <div class="ewe-alert__title">Read-only: saving would lose data another app added</div>
            <div class="ewe-alert__desc">
              {(safe.status?.reasons ?? []).join(" ") || "This file holds something Safe can't save back."} You can read and copy. To change it, use the app that made it.
            </div>
          </div>
        </div>
      {/if}

      {#if safe.items.length === 0 && !f.trash && !ui.editing}
        <div class="safe-split" style="align-items:center;justify-content:center">
          <div class="ewe-empty">
            <span class="ewe-empty__icon"><Icon name="vault" /></span>
            <div class="ewe-empty__title">Your safe is empty</div>
            <div class="ewe-empty__desc">Add your first login, or bring your passwords from another password manager.</div>
            <div class="ewe-empty__actions">
              <button class="ewe-btn ewe-btn--primary" disabled={safe.readOnly} onclick={() => newItem("login")}><Icon name="plus" />Add a login</button>
              <button class="ewe-btn ewe-btn--secondary" disabled={safe.readOnly} onclick={() => ui.go("import")}><Icon name="file-down" />Import…</button>
            </div>
          </div>
        </div>
      {:else}
        <div class="safe-split">
          <div class="safe-listcol" bind:this={listEl}>
            {#if shown.length}
              <div class="ewe-list ewe-list--flush" role="listbox" aria-label={title}>
                {#each shown as i (i.id)}
                  <button
                    class="ewe-row ewe-row--interactive"
                    class:is-selected={current?.id === i.id && !ui.editing}
                    role="option"
                    aria-selected={current?.id === i.id}
                    data-id={i.id}
                    onclick={() => {
                      ui.selected = i.id;
                      ui.editing = null;
                    }}
                  >
                    <span class="ewe-row__lead">
                      {#if i.kind === "login"}<span class="safe-letter">{letter(i.title)}</span>{:else}<span class="safe-letter"><Icon name="sticky-note" /></span>{/if}
                    </span>
                    <span class="ewe-row__text">
                      <span class="ewe-row__title">{i.title}</span>
                      <span class="ewe-row__desc">{i.kind === "note" ? "Note" : i.username || (i.urls?.[0] ? hostOf(i.urls[0]) : "")}</span>
                    </span>
                    {#if i.has_otp || i.passkey}<span class="ewe-row__trail"
                        >{#if i.passkey}<Icon name="key-round" label="Has a passkey" />{/if}{#if i.has_otp}<Icon name="timer" />{/if}</span
                      >{/if}
                  </button>
                {/each}
              </div>
            {:else}
              <div class="ewe-empty" style="padding:var(--space-lg) var(--space-s)">
                <div class="ewe-empty__desc">{ui.query ? `Nothing matches “${ui.query}”.` : f.trash ? "Trash is empty." : "Nothing here yet."}</div>
              </div>
            {/if}
          </div>
          <div class="safe-detail">
            {#if ui.editing}
              {#if ui.editing.mode === "new" || editItem}
                {#key ui.editing}
                  <ItemEdit editing={ui.editing} item={editItem} />
                {/key}
              {/if}
            {:else if current}
              <ItemDetail bind:this={detail} item={current} trash={f.trash} />
            {/if}
          </div>
        </div>
      {/if}
    {/if}
    <Toasts />
  </div>
</div>
