<script>
  // The plumbing page: proves the wiring (status, unlock, list, reveal,
  // lock, events, the daemon's absence) before the screens exist. Not a
  // design — the screens replace it once the owner signs off the mockup.
  import { onMount } from "svelte";
  import { safe } from "$lib/safe.svelte.js";

  let password = $state("");
  let shown = $state({}); // id → revealed password, dropped after 10 s

  onMount(() => {
    safe.start();
    return () => safe.stop();
  });

  async function unlock(e) {
    e.preventDefault();
    const pw = password;
    password = "";
    await safe.unlock(pw);
  }

  async function reveal(id) {
    const v = await safe.reveal(id, "password");
    if (v == null) return;
    shown = { ...shown, [id]: v };
    setTimeout(() => {
      const { [id]: _, ...rest } = shown;
      shown = rest;
    }, 10000);
  }
</script>

<main>
  <h1>Safe — plumbing</h1>

  {#if !safe.daemon.available}
    <p role="alert">{safe.daemon.message ?? "Safe's service can't be reached."}</p>
    {#if safe.daemon.hint}<p><code>{safe.daemon.hint}</code></p>{/if}
  {:else if !safe.status}
    <p>Asking Safe's service…</p>
  {:else if !safe.setUp}
    <p>There's no safe on this computer yet.</p>
  {:else if safe.locked}
    <form onsubmit={unlock}>
      <label>Master password <input type="password" bind:value={password} autocomplete="off" /></label>
      <button disabled={safe.busy === "unlock"}>{safe.busy === "unlock" ? "Unlocking…" : "Unlock"}</button>
    </form>
  {:else}
    <p>
      {safe.items.length} items · sync {safe.status.sync?.state ?? "—"}
      <button onclick={() => safe.lock()}>Lock</button>
    </p>
    <ul>
      {#each safe.items as item (item.id)}
        <li>
          {item.kind} · {item.title}{item.username ? ` · ${item.username}` : ""}
          {#if item.has_password}
            <button onclick={() => reveal(item.id)}>Reveal</button>
            {#if shown[item.id]}<code>{shown[item.id]}</code>{/if}
          {/if}
        </li>
      {/each}
    </ul>
  {/if}

  {#if safe.error}
    <p role="status">{safe.error.error}: {safe.error.message}</p>
  {/if}

  <details>
    <summary>status</summary>
    <pre>{JSON.stringify(safe.status, null, 2)}</pre>
  </details>
</main>
