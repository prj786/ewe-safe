<script>
  // The side navigation (Side navigation card): what the list shows — every
  // item, logins, notes, a tag, a folder — then Trash, Settings and the sync
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
  const folders = $derived.by(() => {
    const m = new Map();
    for (const i of items) if (i.folder) m.set(i.folder, (m.get(i.folder) ?? 0) + 1);
    return [...m].sort((a, b) => a[0].localeCompare(b[0]));
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
      {#each folders as [folder, n] (folder)}
        {@render nav("folder", folder.split("/").pop(), n, { folder })}
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

{#snippet nav(icon, label, n, filter)}
  <button
    class="ewe-navitem"
    class:is-selected={ui.isFilter(filter)}
    aria-current={ui.isFilter(filter) ? "page" : undefined}
    onclick={() => ui.pick(filter)}
  >
    <Icon name={icon} /><span class="ewe-navitem__label">{label}</span>
    {#if n !== ""}<span class="safe-count">{n}</span>{/if}
  </button>
{/snippet}
