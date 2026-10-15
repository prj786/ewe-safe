<script>
  // The side navigation (Side navigation card): what the list shows — every
  // item, logins, notes, SSH keys, a tag, a folder — then Trash, Settings and the sync
  // line at the foot. Counts come from the item summaries.
  import Icon from "./Icon.svelte";
  import { safe } from "../safe.svelte.js";
  import { ui } from "../ui.svelte.js";
  import { syncLine } from "../format.js";

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
</script>

<nav class="ewe-sidenav" aria-label="Safe">
  <div class="ewe-sidenav__brand">
    <span class="ewe-appicon safe-tile safe-tile--sm"><Icon name="vault" /></span>
    <span class="ewe-sidenav__name">Safe</span>
  </div>

  <div class="ewe-sidenav__group">
    {@render nav("list", "All items", items.length, {})}
    {@render nav("key-round", "Logins", count((i) => i.kind === "login"), { kind: "login" })}
    {@render nav("sticky-note", "Notes", count((i) => i.kind === "note"), { kind: "note" })}
    {@render nav("terminal", "SSH keys", count((i) => i.kind === "ssh-key"), { kind: "ssh-key" })}
  </div>

  {#if tags.length}
    <div class="ewe-sidenav__group">
      <div class="ewe-sidenav__heading">Tags</div>
      {#each tags as [tag, n] (tag)}
        {@render nav("tag", tag, n, { tag })}
      {/each}
    </div>
  {/if}

  {#if folders.length}
    <div class="ewe-sidenav__group">
      <div class="ewe-sidenav__heading">Folders</div>
      {#each folders as f (f.path)}
        {@render nav("folder", f.label, f.n, { folder: f.path }, f.depth)}
      {/each}
    </div>
  {/if}

  <div class="ewe-sidenav__foot">
    {@render nav("trash-2", "Trash", safe.deleted.length || "", { trash: true })}
    <button
      class="ewe-navitem"
      class:is-selected={ui.view === "settings" || ui.view === "import"}
      aria-current={ui.view === "settings" ? "page" : undefined}
      onclick={() => ui.go("settings")}
    >
      <Icon name="settings" /><span class="ewe-navitem__label">Settings</span>
    </button>
    {#if sync}
      <div class="ewe-sidenav__version safe-sync {sync.tone}"><Icon name={sync.icon} />{sync.text}</div>
    {/if}
  </div>
</nav>

{#snippet nav(icon, label, n, filter, depth = 0)}
  <button
    class="ewe-navitem"
    style={depth ? `padding-left:calc(var(--space-s) + ${depth} * var(--space-md))` : undefined}
    class:is-selected={ui.isFilter(filter)}
    aria-current={ui.isFilter(filter) ? "page" : undefined}
    onclick={() => ui.pick(filter)}
  >
    <Icon name={icon} /><span class="ewe-navitem__label">{label}</span>
    {#if n !== ""}<span class="safe-count">{n}</span>{/if}
  </button>
{/snippet}
