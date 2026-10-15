<script>
  // A new SSH key (TRIO.md S2): make one in Safe, or add a private key file
  // (~/.ssh/id_ed25519). The daemon reads the file itself; a key with a
  // passphrase needs it once, and keeps it in the item's password. The new
  // key's public line is shown to copy (GitHub → Settings → SSH keys).
  import Icon from "./Icon.svelte";
  import { api } from "../api.js";
  import { safe } from "../safe.svelte.js";
  import { ui } from "../ui.svelte.js";
  import { toasts } from "../toast.svelte.js";

  let way = $state("new"); // "new" | "file"
  let title = $state("");
  let keyType = $state("ed25519");
  let file = $state("");
  let passphrase = $state("");
  let showPass = $state(false);
  let needsPass = $state(false);
  let saving = $state(false);
  let error = $state("");

  const TYPES = [
    ["ed25519", "Ed25519", "Short and fast; every server today takes it"],
    ["ecdsa", "ECDSA P-256", "For servers that want a NIST curve"],
    ["rsa", "RSA 3072", "For old servers only"]
  ];

  async function pick() {
    const r = await api.pickFile("ssh-key");
    if (r?.ok && r.path) {
      file = r.path;
      error = "";
      needsPass = false;
    }
  }

  async function save(e) {
    e?.preventDefault();
    error = "";
    if (way === "new" && !title.trim()) {
      error = "A title is needed.";
      return;
    }
    if (way === "file" && !file) {
      error = "Choose the private key file first.";
      return;
    }
    saving = true;
    const pass = passphrase;
    passphrase = "";
    const r =
      way === "new"
        ? await safe.sshNew({ title: title.trim(), keyType })
        : await safe.sshAdd({ file, title: title.trim() || undefined, passphrase: pass || undefined });
    saving = false;
    if (!r?.ok) {
      // a key with a passphrase: ask for it
      if (/passphrase/i.test(r?.message ?? "")) needsPass = true;
      error = r?.message ?? "Couldn't add the key.";
      return;
    }
    toasts.show(way === "new" ? "Made a new SSH key." : "Added the SSH key.", { icon: "circle-check" });
    if (r.item_id) ui.selected = r.item_id;
    ui.editing = null;
  }
</script>

<form class="safe-stack" style="gap:var(--space-md)" onsubmit={save}>
  <div class="safe-dhead">
    <span class="safe-letter safe-letter--lg"><Icon name="terminal" /></span>
    <div class="safe-dhead__titles">
      <div class="h3">Add an SSH key</div>
      <div class="caption">ssh and git use it through Safe, the way they did through 1Password.</div>
    </div>
  </div>

  <div class="ewe-seg ewe-seg--block ewe-seg--sm" role="radiogroup" aria-label="How">
    <button type="button" class="ewe-seg__item" class:is-selected={way === "new"} role="radio" aria-checked={way === "new"} onclick={() => (way = "new")}>Make a new key</button>
    <button type="button" class="ewe-seg__item" class:is-selected={way === "file"} role="radio" aria-checked={way === "file"} onclick={() => (way = "file")}>Add a key file</button>
  </div>

  <div class="safe-form">
    {#if way === "file"}
      <div class="ewe-field">
        <div class="ewe-field__label"><span>Private key</span></div>
        <div class="safe-compact__row">
          <span class="ewe-input"><input class="mono" bind:value={file} placeholder="~/.ssh/id_ed25519" spellcheck="false" aria-label="Private key file" /></span>
          <button type="button" class="ewe-btn ewe-btn--secondary" onclick={pick}><Icon name="folder-open" />Choose…</button>
        </div>
        <span class="ewe-field__helper">OpenSSH or PEM (PKCS#8). The file stays where it is: delete it once the key is in Safe, if you like.</span>
      </div>
      {#if needsPass}
        <label class="ewe-field">
          <span class="ewe-field__label"><span>Passphrase</span></span>
          <span class="ewe-input">
            <input class="mono" type={showPass ? "text" : "password"} bind:value={passphrase} autocomplete="off" spellcheck="false" />
            <button type="button" class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm" aria-label={showPass ? "Hide passphrase" : "Show passphrase"} onclick={() => (showPass = !showPass)}>
              <Icon name={showPass ? "eye-off" : "eye"} />
            </button>
          </span>
          <span class="ewe-field__helper">Safe keeps it with the key, so ssh never asks.</span>
        </label>
      {/if}
    {/if}

    <label class="ewe-field">
      <span class="ewe-field__label"><span>Title</span>{#if way === "file"}<span class="ewe-field__optional">The key's comment if empty</span>{/if}</span>
      <span class="ewe-input"><input bind:value={title} autocomplete="off" spellcheck="false" placeholder="GitHub key" /></span>
    </label>

    {#if way === "new"}
      <div class="ewe-field">
        <div class="ewe-field__label"><span>Type</span></div>
        <div class="safe-stack" role="radiogroup" aria-label="Type">
          {#each TYPES as [id, name, desc] (id)}
            <button type="button" role="radio" aria-checked={keyType === id} class="ewe-check ewe-check--radio" class:is-checked={keyType === id} onclick={() => (keyType = id)}>
              <span class="ewe-check__box">{#if keyType === id}<span class="ewe-check__dot"></span>{/if}</span>
              <span class="ewe-check__text">
                <span class="ewe-check__label">{name}</span>
                <span class="ewe-check__desc">{desc}</span>
              </span>
            </button>
          {/each}
        </div>
      </div>
    {/if}

    {#if error}
      <div class="ewe-field__helper ewe-field__helper--error"><Icon name="circle-x" /><span>{error}</span></div>
    {/if}
  </div>

  <div class="safe-actions safe-actions--end">
    <button type="button" class="ewe-btn ewe-btn--ghost" onclick={() => (ui.editing = null)}>Cancel</button>
    <button type="submit" class="ewe-btn ewe-btn--primary" disabled={saving}>
      {saving ? (way === "new" ? "Making…" : "Adding…") : way === "new" ? "Make the key" : "Add the key"}
    </button>
  </div>
</form>
