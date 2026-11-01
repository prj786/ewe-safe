<script>
  // The rail (Side navigation card) of the window's frame: what the list
  // shows — every item, logins, notes, cards, addresses, a tag, a folder —
  // the SSH page (keys, hosts, the gate: docs/GATE.md S28), then Trash,
  // Settings and the sync state in ewe Sync's words at the foot. Counts come
  // from the item summaries. `mode`: "full" (unlocked), "locked" (the
  // sections are there but closed, so unlocking changes nothing around the
  // pane), "bare" (setup, loading, the service down: only the name).
  // Up and Down move between the sections.
  import Icon from "./Icon.svelte";
  import { safe } from "../safe.svelte.js";
  import { ui } from "../ui.svelte.js";
  import { syncLine } from "../format.js";
  import { arrowFocus, keys } from "../trap.js";

  let { mode = "full" } = $props();

  let navEl = $state();
  const open = $derived(mode === "full");
  const items = $derived(safe.items);
  const count = (f) => items.filter(f).length;
  const tags = $derived.by(() => {
    const m = new Map();
    for (const i of items) for (const t of i.tags ?? []) m.set(t, (m.get(t) ?? 0) + 1);
    return [...m].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 8);
  });
  // folders as a tree: every folder and its parents, each counting the items
  // in it and below it (the list shows the same), children indented
  const folders = $derived.by(() => {
    const m = new Map();
    for (const i of items) {
      if (!i.folder) continue;
      const parts = i.folder.split("/");
      for (let n = 1; n <= parts.length; n++) {
        const path = parts.slice(0, n).join("/");
        m.set(path, (m.get(path) ?? 0) + 1);
      }
    }
    return [...m]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([path, n]) => ({ path, n, depth: path.split("/").length - 1, label: path.split("/").pop() }));
  });
  let now = $state(new Date());
  $effect(() => {
    const t = setInterval(() => (now = new Date()), 30000);
    return () => clearInterval(t);
  });
  const sync = $derived(syncLine(safe.status?.sync, now));
  const version = $derived(safe.status?.version ?? "");
  // the SSH page, or its keys in the list ("Show the item")
  const sshHere = $derived(ui.view === "ssh" || ui.isFilter({ kind: "ssh-key" }));

  // Up/Down between the sections, Home/End to the first and last
  const onkeydown = (e) => document.activeElement?.closest?.(".ewe-navitem") && arrowFocus(e, navEl, "button.ewe-navitem");
</script>

<nav class="ewe-sidenav safe-rail" aria-label="ewe Safe" bind:this={navEl} use:keys={onkeydown}>
  <div class="ewe-sidenav__brand">
    <span class="ewe-appicon safe-tile safe-tile--sm" aria-hidden="true"><Icon name="vault" /></span>
    <span class="ewe-sidenav__name">ewe Safe</span>
  </div>

  {#if mode !== "bare"}
    <div class="ewe-sidenav__group">
      {@render nav("layout-grid", "All items", items.length, {})}
      {@render nav("key-round", "Logins", count((i) => i.kind === "login"), { kind: "login" })}
      {@render nav("file-text", "Notes", count((i) => i.kind === "note"), { kind: "note" })}
      <button
        type="button"
        class="ewe-navitem"
        class:is-selected={open && sshHere}
        class:is-disabled={!open}
        disabled={!open}
        title={open ? undefined : "SSH"}
        aria-current={open && sshHere ? "page" : undefined}
        onclick={() => ui.go("ssh")}
      >
        <Icon name="terminal" /><span class="ewe-navitem__label">SSH</span>
        {#if open}<span class="safe-count">{count((i) => i.kind === "ssh-key")}</span>{/if}
      </button>
      {@render nav("credit-card", "Cards", count((i) => i.kind === "card"), { kind: "card" })}
      {@render nav("map-pin", "Addresses", count((i) => i.kind === "address"), { kind: "address" })}
    </div>

    {#if open && tags.length}
      <div class="ewe-sidenav__group">
        <div class="ewe-sidenav__heading">Tags</div>
        {#each tags as [tag, n] (tag)}
          {@render nav("tag", tag, n, { tag })}
        {/each}
      </div>
    {/if}

    {#if open && folders.length}
      <div class="ewe-sidenav__group">
        <div class="ewe-sidenav__heading">Folders</div>
        {#each folders as f (f.path)}
          {@render nav("folder", f.label, f.n, { folder: f.path }, f.depth)}
        {/each}
      </div>
    {/if}
  {/if}

  <div class="ewe-sidenav__foot">
    {#if mode !== "bare"}
      {@render nav("trash-2", "Trash", safe.deleted.length || "", { trash: true })}
      <button
        type="button"
        class="ewe-navitem"
        class:is-selected={open && (ui.view === "settings" || ui.view === "import")}
        class:is-disabled={!open}
        disabled={!open}
        aria-current={open && ui.view === "settings" ? "page" : undefined}
        onclick={() => ui.go("settings")}
      >
        <Icon name="settings" /><span class="ewe-navitem__label">Settings</span>
      </button>
    {/if}
    {#if mode === "locked"}
      <div class="safe-state" title="Locked">
        <Icon name="lock" /><span class="safe-state__text">Locked</span>
      </div>
    {:else if open && sync}
      <div class="safe-state" title={sync.text}>
        <span class="safe-state__dot is-{sync.tone}" aria-hidden="true"></span><span class="safe-state__text">{sync.text}</span>
      </div>
    {/if}
    {#if version}<div class="ewe-sidenav__version">ewe Safe {version}</div>{/if}
  </div>
</nav>

{#snippet nav(icon, label, n, filter, depth = 0)}
  <button
    type="button"
    class="ewe-navitem"
    style={depth ? `padding-left:calc(var(--space-s) + ${depth} * var(--space-md))` : undefined}
    class:is-selected={open && ui.isFilter(filter)}
    class:is-disabled={!open}
    disabled={!open}
    title={label}
    aria-current={open && ui.isFilter(filter) ? "page" : undefined}
    onclick={() => ui.pick(filter)}
  >
    <Icon name={icon} /><span class="ewe-navitem__label">{label}</span>
    {#if open && n !== ""}<span class="safe-count">{n}</span>{/if}
  </button>
{/snippet}
