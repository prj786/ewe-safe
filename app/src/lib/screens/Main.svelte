<script>
  // The unlocked pane (the frame is App's): Settings, Import, SSH (the gate,
  // services, keys, hosts: docs/GATE.md S28) — or the items: one header
  // (title, search, New, Lock), then the list and the item. SSH keys have
  // their own New (make one, or add a key file). The connect sheet opens
  // over any of them (the SSH page, an SSH key's Connect…). New on a list of
  // one kind makes that kind; elsewhere it asks which (a login, a note, a
  // card, an address…).
  // Keyboard first: type anywhere to search; the list is one Tab stop and
  // the arrows move the focus and the selection together (Home, End too);
  // Enter or Ctrl+C copies the password, Ctrl+Shift+C the username, Ctrl+N
  // is a new login, Ctrl+L locks, Esc steps back.
  import { tick } from "svelte";
  import Icon from "../components/Icon.svelte";
  import ItemDetail from "../components/ItemDetail.svelte";
  import ItemEdit from "../components/ItemEdit.svelte";
  import SshKeyNew from "../components/SshKeyNew.svelte";
  import SshConnect from "../components/SshConnect.svelte";
  import Settings from "./Settings.svelte";
  import Import from "./Import.svelte";
  import Ssh from "./Ssh.svelte";
  import { safe } from "../safe.svelte.js";
  import { ui } from "../ui.svelte.js";
  import { hostOf, letter } from "../format.js";
  import { addressLine, brandName, expired, expiryShort } from "../cards.js";
  import { arrowFocus } from "../trap.js";

  let search = $state();
  let detail = $state();
  let listEl = $state();
  let newMenu = $state(false);
  let menuEl = $state();
  const KINDS = [
    ["login", "key-round", "Login"],
    ["note", "file-text", "Note"],
    ["card", "credit-card", "Card"],
    ["address", "map-pin", "Address"],
    ["ssh-key", "terminal", "SSH key"]
  ];
  const KIND_ICON = { login: "key-round", note: "file-text", "ssh-key": "terminal", card: "credit-card", address: "map-pin" };
  // a list of one kind with nothing in it: what's missing, and the next step
  const NONE = {
    login: ["No logins yet", "Add one, or bring them over from 1Password.", "New login"],
    note: ["No notes yet", "A note keeps a secret that isn’t a login: a Wi-Fi password, recovery codes.", "New note"],
    card: ["No cards yet", "ewe Browser fills a card’s number and expiry for you.", "New card"],
    address: ["No addresses yet", "ewe Browser fills your name and address into forms.", "New address"]
  };

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
  const narrowed = $derived(!!(f.kind || f.tag || f.folder || f.trash));
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
      // a card's holder, brand and last digits; an address's name and town
      const c = i.card;
      if (c && [c.holder, c.brand, brandName(c.brand), c.last4].some((x) => (x ?? "").toLowerCase().includes(q))) return 5;
      const a = i.address;
      if (a && [a.name, a.line1, a.city, a.country].some((x) => (x ?? "").toLowerCase().includes(q))) return 5;
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
    f.trash
      ? "Trash"
      : f.kind === "login"
        ? "Logins"
        : f.kind === "note"
          ? "Notes"
          : f.kind === "ssh-key"
            ? "SSH keys"
            : f.kind === "card"
              ? "Cards"
              : f.kind === "address"
                ? "Addresses"
                : f.tag || f.folder.split("/").pop() || "All items"
  );
  const items = (n) => (n === 1 ? "1 item" : `${n} items`);
  const subtitle = $derived(
    [
      ui.query.trim() ? `${shown.length} of ${items(base.length)}` : base.length === 0 ? "Empty" : items(base.length),
      safe.readOnly ? "read-only" : ""
    ]
      .filter(Boolean)
      .join(" · ")
  );
  // the list and the item, or one empty state across both
  const empty = $derived(
    !ui.editing && !shown.length && !(f.kind === "ssh-key" && !f.trash && !ui.query.trim())
  );

  /** A list row's second line. */
  function desc(i) {
    if (i.kind === "note") return "Note";
    if (i.kind === "ssh-key") return ["SSH key", i.ssh?.key_type].filter(Boolean).join(" · ");
    if (i.kind === "address") return addressLine(i.address);
    if (i.kind === "card") {
      const c = i.card ?? {};
      const exp = expiryShort(c.expiry);
      const when = exp ? (expired(c.expiry) ? `Expired ${exp}` : `Expires ${exp}`) : "";
      // the number's end only when the title doesn't say it already
      const end = c.last4 && !i.title.includes(c.last4) ? `•••• ${c.last4}` : "";
      return [end, when].filter(Boolean).join(" · ") || brandName(c.brand);
    }
    const who = i.username || (i.urls?.[0] ? hostOf(i.urls[0]) : "") || "Login";
    return i.passkey ? `${who} · passkey` : who;
  }

  function newItem(kind = "login") {
    newMenu = false;
    if (safe.readOnly) return;
    ui.view = "items";
    ui.filter = { ...ui.filter, trash: false };
    ui.editing = { mode: "new", kind };
  }

  async function openMenu() {
    newMenu = !newMenu;
    if (newMenu) {
      await tick();
      menuEl?.querySelector(".ewe-menu__item")?.focus();
    }
  }

  async function focusRow(id) {
    await tick();
    const el = listEl?.querySelector(`[data-id="${CSS.escape(id)}"]`);
    el?.focus();
    el?.scrollIntoView({ block: "nearest" });
  }

  /** Move the selection by `by` rows (or to the first/last) and the focus with it. */
  function move(by, to = null) {
    if (!shown.length) return;
    const at = Math.max(0, shown.findIndex((i) => i.id === current?.id));
    const n = to === "first" ? 0 : to === "last" ? shown.length - 1 : Math.min(shown.length - 1, Math.max(0, at + by));
    const next = shown[n];
    ui.selected = next.id;
    ui.editing = null;
    focusRow(next.id);
  }

  function typing(t) {
    return t instanceof HTMLInputElement || t instanceof HTMLTextAreaElement || t instanceof HTMLSelectElement;
  }

  function searchAll() {
    const q = ui.query;
    ui.pick({});
    ui.query = q;
    search?.focus();
  }

  function onkey(e) {
    if (newMenu && e.key === "Escape") {
      newMenu = false;
      return;
    }
    if (ui.view !== "items") {
      if (e.key === "Escape") ui.go("items");
      return;
    }
    const ctrl = e.ctrlKey || e.metaKey;
    const inList = !!e.target?.dataset?.id;
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
    } else if (e.key === "ArrowDown" || e.key === "ArrowUp" || (inList && (e.key === "Home" || e.key === "End"))) {
      if (typing(e.target) && e.target !== search) return;
      if (e.target?.closest?.(".ewe-menu, .ewe-sidenav, .safe-detail")) return;
      e.preventDefault();
      // from the search, Down goes into the list at the selected item
      if (e.target === search) {
        if (e.key === "ArrowDown" && current) {
          ui.selected = current.id;
          focusRow(current.id);
        }
      } else if (e.key === "Home") move(0, "first");
      else if (e.key === "End") move(0, "last");
      else move(e.key === "ArrowDown" ? 1 : -1);
    } else if (e.key === "Enter" && (e.target === search || inList)) {
      e.preventDefault();
      if (e.target === search) {
        if (current) {
          ui.selected = current.id;
          focusRow(current.id);
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

<svelte:window
  onkeydown={onkey}
  onclick={(e) => {
    if (newMenu && !e.target.closest?.(".safe-rel")) newMenu = false;
  }}
/>

{#if ui.view === "settings"}
  <Settings />
{:else if ui.view === "import"}
  <Import />
{:else if ui.view === "ssh"}
  <Ssh />
{:else}
  <header class="ewe-headerbar safe-appbar">
    <div class="ewe-headerbar__titles">
      <h1 class="ewe-headerbar__title">{title}</h1>
      <div class="ewe-headerbar__subtitle">{subtitle}</div>
    </div>
    <div class="ewe-headerbar__actions">
      <label class="ewe-input safe-search">
        <Icon name="search" />
        <input bind:this={search} bind:value={ui.query} placeholder="Search ewe Safe" aria-label="Search ewe Safe" spellcheck="false" autocomplete="off" />
        {#if ui.query}
          <button type="button" class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm" aria-label="Clear the search" onclick={() => ((ui.query = ""), search?.focus())}><Icon name="x" /></button>
        {:else}
          <kbd class="ewe-kbd" aria-hidden="true">Ctrl+F</kbd>
        {/if}
      </label>
      <div class="safe-rel">
        <button
          type="button"
          class="ewe-btn ewe-btn--primary"
          disabled={safe.readOnly || f.trash}
          title={f.trash ? "Items in Trash can only be restored" : "New (Ctrl+N)"}
          aria-haspopup={f.kind ? undefined : "menu"}
          aria-expanded={f.kind ? undefined : newMenu}
          onclick={() => (f.kind ? newItem(f.kind) : openMenu())}
        >
          <Icon name="plus" />New
        </button>
        {#if newMenu}
          <div class="ewe-menu safe-menu" role="menu" aria-label="New" bind:this={menuEl} tabindex="-1" onkeydown={(e) => arrowFocus(e, menuEl, ".ewe-menu__item")}>
            {#each KINDS as [kind, icon, label] (kind)}
              <button type="button" class="ewe-menu__item" role="menuitem" onclick={() => newItem(kind)}><Icon name={icon} />{label}</button>
            {/each}
          </div>
        {/if}
      </div>
      <button type="button" class="ewe-iconbtn ewe-iconbtn--ghost" aria-label="Lock ewe Safe" title="Lock (Ctrl+L)" onclick={() => safe.lock()}>
        <Icon name="lock" />
      </button>
    </div>
  </header>

  {#if safe.readOnly}
    <div class="ewe-alert ewe-alert--warning safe-banner" role="status">
      <Icon name="shield-alert" />
      <div class="ewe-alert__body">
        <div class="ewe-alert__title">Read-only: saving would lose data another app added</div>
        <div class="ewe-alert__desc">
          {(safe.status?.reasons ?? []).join(" ") || "This file holds something ewe Safe can’t save back."} You can read and copy. To change it, use the app that made it.
        </div>
      </div>
    </div>
  {/if}

  {#if safe.items.length === 0 && !narrowed && !ui.editing && !ui.query.trim()}
    <div class="safe-stage">
      <div class="ewe-empty safe-col safe-col--narrow safe-col--center">
        <span class="ewe-empty__icon"><Icon name="vault" /></span>
        <div class="ewe-empty__title">Your safe is empty</div>
        <div class="ewe-empty__desc">Add your first login, or bring your passwords over from another password manager.</div>
        <div class="ewe-empty__actions">
          <button type="button" class="ewe-btn ewe-btn--primary" disabled={safe.readOnly} onclick={() => newItem("login")}><Icon name="plus" />Add a login</button>
          <button type="button" class="ewe-btn ewe-btn--secondary" disabled={safe.readOnly} onclick={() => ui.go("import")}><Icon name="file-down" />Import…</button>
        </div>
      </div>
    </div>
  {:else if empty}
    <div class="safe-stage">
      <div class="ewe-empty safe-col safe-col--narrow safe-col--center" role="status">
        {#if ui.query.trim()}
          <span class="ewe-empty__icon"><Icon name="search-x" /></span>
          <div class="ewe-empty__title">Nothing matches “{ui.query.trim()}”</div>
          <div class="ewe-empty__desc">{narrowed ? `Only ${title} were searched. Check the spelling, or search every item.` : "Check the spelling, or try a website or a username."}</div>
          <div class="ewe-empty__actions">
            {#if narrowed}<button type="button" class="ewe-btn ewe-btn--secondary" onclick={searchAll}><Icon name="search" />Search all items</button>{/if}
            <button type="button" class="ewe-btn ewe-btn--ghost" onclick={() => ((ui.query = ""), search?.focus())}>Clear the search</button>
          </div>
        {:else if f.trash}
          <span class="ewe-empty__icon"><Icon name="trash-2" /></span>
          <div class="ewe-empty__title">Trash is empty</div>
          <div class="ewe-empty__desc">Items you move to Trash stay here until you restore them.</div>
          <div class="ewe-empty__actions"><button type="button" class="ewe-btn ewe-btn--secondary" onclick={() => ui.pick({})}>Show all items</button></div>
        {:else if NONE[f.kind]}
          <span class="ewe-empty__icon"><Icon name={KIND_ICON[f.kind]} /></span>
          <div class="ewe-empty__title">{NONE[f.kind][0]}</div>
          <div class="ewe-empty__desc">{NONE[f.kind][1]}</div>
          <div class="ewe-empty__actions">
            <button type="button" class="ewe-btn ewe-btn--primary" disabled={safe.readOnly} onclick={() => newItem(f.kind)}><Icon name="plus" />{NONE[f.kind][2]}</button>
            {#if f.kind === "login"}<button type="button" class="ewe-btn ewe-btn--secondary" disabled={safe.readOnly} onclick={() => ui.go("import")}><Icon name="file-down" />Import…</button>{/if}
          </div>
        {:else}
          <span class="ewe-empty__icon"><Icon name="inbox" /></span>
          <div class="ewe-empty__title">Nothing here now</div>
          <div class="ewe-empty__desc">The items that were here moved or went to Trash.</div>
          <div class="ewe-empty__actions"><button type="button" class="ewe-btn ewe-btn--secondary" onclick={() => ui.pick({})}>Show all items</button></div>
        {/if}
      </div>
    </div>
  {:else}
    <div class="safe-split">
      <div class="safe-listcol" bind:this={listEl}>
        {#if shown.length}
          <div class="ewe-list ewe-list--flush" role="listbox" aria-label={title}>
            {#each shown as i (i.id)}
              {@const on = current?.id === i.id}
              {@const old = i.kind === "card" && expired(i.card?.expiry)}
              <button
                type="button"
                class="ewe-row ewe-row--interactive"
                class:is-selected={on && !ui.editing}
                class:is-active={on && !ui.editing}
                role="option"
                aria-selected={on}
                tabindex={on ? 0 : -1}
                data-id={i.id}
                onclick={() => {
                  ui.selected = i.id;
                  ui.editing = null;
                }}
              >
                <span class="ewe-row__lead ewe-row__lead--tile safe-letter">
                  {#if i.kind === "login"}{letter(i.title)}{:else}<Icon name={KIND_ICON[i.kind] ?? "file-text"} />{/if}
                </span>
                <span class="ewe-row__text">
                  <span class="ewe-row__title">{i.title}</span>
                  <span class="ewe-row__desc">{desc(i)}</span>
                </span>
                {#if old}<span class="ewe-badge ewe-badge--warning"><span class="ewe-badge__label">Expired</span></span>{/if}
              </button>
            {/each}
          </div>
          {#if f.trash}<div class="caption safe-muted safe-listnote">Items stay in Trash until you restore them.</div>{/if}
        {:else}
          <div class="ewe-empty ewe-empty--compact">
            <div class="ewe-empty__desc">{ui.query.trim() ? `Nothing matches “${ui.query.trim()}”.` : `No ${title.toLowerCase()} yet.`}</div>
          </div>
        {/if}
      </div>
      <div class="safe-detail">
        {#if ui.editing?.mode === "new" && ui.editing.kind === "ssh-key"}
          <SshKeyNew way={ui.editing.way ?? "new"} />
        {:else if ui.editing}
          {#if ui.editing.mode === "new" || editItem}
            {#key ui.editing}
              <ItemEdit editing={ui.editing} item={editItem} />
            {/key}
          {/if}
        {:else if current}
          <ItemDetail bind:this={detail} item={current} trash={f.trash} />
        {:else if f.kind === "ssh-key" && !f.trash}
          <SshKeyNew />
        {/if}
      </div>
    </div>
  {/if}
{/if}
{#if ui.connect}<SshConnect />{/if}
