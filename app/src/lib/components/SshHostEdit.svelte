<script>
  // A host in ewe.conf (docs/GATE.md S24, `ssh host set`): its name for
  // ssh, the address, your user name there, the port, and which key from
  // Safe it uses (or any key). It follows the account to every computer.
  // The user's own lines in ~/.ssh/config are never edited here.
  import { untrack } from "svelte";
  import Icon from "./Icon.svelte";
  import Sheet from "./Sheet.svelte";
  import { safe } from "../safe.svelte.js";
  import { badAlias, keyTypeName } from "../ssh.js";

  let { host = null, onclose } = $props();

  // the form starts from the host as it was when the sheet opened
  const was = untrack(() => host);
  const editing = !!was;
  let alias = $state(was?.alias ?? "");
  let address = $state(was?.host_name ?? "");
  let user = $state(was?.user ?? "");
  let port = $state(was?.port ? String(was.port) : "");
  let key = $state(was?.key?.item_id ?? "");
  let error = $state("");
  let busy = $state(false);

  const keys = $derived(safe.items.filter((i) => i.kind === "ssh-key").sort((a, b) => a.title.localeCompare(b.title)));

  async function save(e) {
    e?.preventDefault();
    error = "";
    const a = alias.trim();
    if (!a) return (error = "Give the host a name. You type it after ssh.");
    if (badAlias(a)) return (error = "A name can't have a space, *, ? or !, and can't start with -.");
    if (!editing && safe.ssh.hosts.some((h) => h.alias === a)) return (error = `There is a host called ${a} already. Pick another name.`);
    const p = port.trim();
    if (p && !(Number.isInteger(Number(p)) && Number(p) > 0 && Number(p) < 65536)) return (error = "The port is a number from 1 to 65535.");
    busy = true;
    const r = await safe.sshHostSet({
      alias: a,
      host: address.trim(),
      user: user.trim(),
      port: p ? Number(p) : undefined,
      key: key || undefined,
      noKey: !key || undefined
    });
    busy = false;
    if (!r?.ok) return (error = r?.message ?? "Couldn't save the host.");
    onclose?.();
  }
</script>

<Sheet title={editing ? `Edit ${was.alias}` : "Add a host"} icon="server" {onclose}>
  <form id="safe-host-form" class="safe-form" onsubmit={save}>
    <label class="ewe-field">
      <span class="ewe-field__label"><span>Name</span></span>
      <span class="ewe-input"><input class="mono" bind:value={alias} readonly={editing} autocomplete="off" spellcheck="false" placeholder="my-server" /></span>
      <span class="ewe-field__helper">{editing ? "The name stays. To rename, add a new host and remove this one." : "You type it after ssh: ssh my-server."}</span>
    </label>
    <div class="safe-fields">
      <label class="ewe-field">
        <span class="ewe-field__label"><span>Address</span></span>
        <span class="ewe-input"><input class="mono" bind:value={address} data-autofocus={editing || undefined} autocomplete="off" spellcheck="false" placeholder="server.example.org" /></span>
      </label>
      <label class="ewe-field">
        <span class="ewe-field__label"><span>User</span></span>
        <span class="ewe-input"><input class="mono" bind:value={user} autocomplete="off" spellcheck="false" placeholder="sam" /></span>
      </label>
      <label class="ewe-field">
        <span class="ewe-field__label"><span>Port</span></span>
        <span class="ewe-input"><input class="mono" bind:value={port} inputmode="numeric" autocomplete="off" spellcheck="false" placeholder="22" /></span>
      </label>
    </div>
    <label class="ewe-field">
      <span class="ewe-field__label"><span>Key</span></span>
      <select class="ewe-input ewe-select" bind:value={key}>
        <option value="">Any key in Safe</option>
        {#each keys as k (k.id)}<option value={k.id}>{k.title} ({keyTypeName(k.ssh?.key_type)})</option>{/each}
      </select>
      <span class="ewe-field__helper">With one key, ssh tries only that key. The server never sees the others.</span>
    </label>
    {#if error}<div class="ewe-field__helper ewe-field__helper--error" role="alert"><Icon name="circle-x" /><span>{error}</span></div>{/if}
    <div class="caption safe-muted">This host is in your ewe settings, so all your computers get it.</div>
  </form>
  {#snippet foot()}
    <button type="button" class="ewe-btn ewe-btn--ghost" onclick={() => onclose?.()}>Cancel</button>
    <button type="submit" form="safe-host-form" class="ewe-btn ewe-btn--primary" disabled={busy}>{busy ? "Saving…" : "Save"}</button>
  {/snippet}
</Sheet>
