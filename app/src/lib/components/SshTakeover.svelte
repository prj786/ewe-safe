<script>
  // Move SSH to Safe (docs/GATE.md S23, `ssh-takeover`): a dry run first —
  // the key files Safe brings in, a field for each one with a passphrase,
  // the ewe hosts that stop naming another agent, the keys only that agent
  // has (Import from 1Password) — then Move, then what happened. Files are
  // never changed. The passphrases are secrets: kept only until Move sends
  // them, never shown again.
  import { onMount } from "svelte";
  import Icon from "./Icon.svelte";
  import Sheet from "./Sheet.svelte";
  import { safe } from "../safe.svelte.js";
  import { ui } from "../ui.svelte.js";
  import { andList, count, gateOf } from "../ssh.js";

  let phase = $state("check"); // "check" | "plan" | "moving" | "done"
  let plan = $state(null); // the dry run's reply
  let done = $state(null); // the move's reply
  let error = $state("");
  let pass = $state({}); // file → passphrase (secrets)
  let showPass = $state({});

  const gate = $derived(gateOf(safe.ssh.status, safe.ssh.hosts));
  const base = (f) => f.split("/").pop();
  const tilde = (f) => f.replace(/^\/home\/[^/]+\//, "~/");

  onMount(() => {
    check();
    return () => (pass = {});
  });

  async function check() {
    phase = "check";
    error = "";
    const r = await safe.sshTakeover({ dryRun: true });
    if (!r?.ok) {
      error = r?.message ?? "Safe couldn't check your SSH setup.";
      phase = "plan";
      return;
    }
    plan = r;
    phase = "plan";
  }

  async function move() {
    phase = "moving";
    error = "";
    const passphrases = Object.fromEntries(Object.entries(pass).filter(([, v]) => v));
    pass = {};
    showPass = {};
    const r = await safe.sshTakeover({ dryRun: false, passphrases });
    if (!r?.ok) {
      error = r?.message ?? "Safe couldn't move SSH.";
      phase = "plan";
      return;
    }
    done = r;
    phase = "done";
  }

  function close() {
    pass = {};
    ui.takeover = false;
  }

  function toImport() {
    pass = {};
    ui.go("import");
  }

  // the hosts in your own lines: never changed, the gate answers for them
  const own = $derived((plan?.overridden ?? []).filter((o) => !(plan?.hosts_fixed ?? []).includes(o.host)));
  const agent = $derived(plan?.missing_from_safe?.[0]?.agent ?? gate?.agent ?? "1Password");
  const nothing = $derived(
    plan &&
      gate?.on &&
      !plan.imported?.length &&
      !plan.needs_passphrase?.length &&
      !plan.hosts_fixed?.length &&
      !plan.missing_from_safe?.length &&
      !plan.skipped?.length
  );
</script>

<Sheet title="Move SSH to Safe" icon="arrow-right" onclose={close}>
  {#if phase === "check"}
    <div class="safe-result safe-muted" role="status"><span class="ewe-spinner ewe-spinner--sm ewe-spinner--neutral"></span>Safe is looking at your SSH setup…</div>
  {:else if phase === "done" && done}
    <div class="ewe-alert ewe-alert--success" role="status">
      <Icon name="circle-check" />
      <div class="ewe-alert__body">
        <div class="ewe-alert__title">ssh asks Safe now</div>
        <div class="ewe-alert__desc">Every ssh and git on this computer asks Safe for keys.</div>
      </div>
    </div>
    <ul class="safe-points">
      {#if done.imported?.length}<li><Icon name="circle-check" /><span>Safe has {count(done.imported.length, "new key")}: {andList(done.imported.map((k) => k.title))}.</span></li>{/if}
      {#if done.hosts_fixed?.length}<li><Icon name="circle-check" /><span>{andList(done.hosts_fixed)} {done.hosts_fixed.length === 1 ? "asks" : "ask"} Safe now, on all your computers.</span></li>{/if}
      {#each done.skipped ?? [] as x (x.file)}<li><Icon name="circle-alert" /><span>{base(x.file)} stayed out: {x.reason}</span></li>{/each}
      {#if done.needs_passphrase?.length}<li><Icon name="circle-alert" /><span>{andList(done.needs_passphrase.map(base))} stayed out: no passphrase.</span></li>{/if}
    </ul>
    {#if done.missing_from_safe?.length}
      {@render missing(done.missing_from_safe)}
    {/if}
    {#if done.files_left?.length}
      <div class="safe-stack">
        <div class="label">Key files you can delete</div>
        <div class="caption safe-muted">These keys are in Safe now, and Safe signs for them. The files are still in ~/.ssh. Delete them when you are ready.</div>
        <div class="safe-chips safe-chips--start">{#each done.files_left as f (f)}<span class="ewe-tag mono">{tilde(f)}</span>{/each}</div>
      </div>
    {/if}
  {:else if plan || error}
    {#if error}
      <div class="ewe-alert ewe-alert--danger" role="alert">
        <Icon name="circle-x" />
        <div class="ewe-alert__body"><div class="ewe-alert__title">{error}</div></div>
      </div>
    {/if}
    {#if plan}
      {#if nothing}
        <div class="safe-gate" role="status"><Icon name="shield-check" /><span>Nothing to move. Safe already answers ssh here.</span></div>
      {:else}
        <p class="body safe-secondary" style="margin:0">Safe checked your SSH setup. Nothing changes until you press Move. Safe never deletes or changes your key files.</p>
        <ul class="safe-points">
          {#if !gate?.on}<li><Icon name="shield-check" /><span>Every ssh on this computer asks Safe first.</span></li>{/if}
          {#if plan.imported?.length}
            <li><Icon name="key-round" /><span>Safe brings in {count(plan.imported.length, "key file")}: {andList(plan.imported.map((k) => tilde(k.file)))}.</span></li>
          {/if}
          {#if plan.hosts_fixed?.length}
            <li><Icon name="server" /><span>{andList(plan.hosts_fixed)} stop{plan.hosts_fixed.length === 1 ? "s" : ""} asking {agent}, on all your computers.</span></li>
          {/if}
          {#if plan.already?.length}
            <li><Icon name="circle-check" /><span>Already in Safe: {andList(plan.already.map((k) => tilde(k.file)))}.</span></li>
          {/if}
          {#each plan.skipped ?? [] as x (x.file)}<li><Icon name="circle-alert" /><span>{tilde(x.file)} stays out: {x.reason}</span></li>{/each}
        </ul>
      {/if}
      {#if plan.needs_passphrase?.length}
        <div class="safe-stack">
          <div class="label">Key files with a passphrase</div>
          <div class="caption safe-muted">Type the passphrase to bring the key in. Safe keeps it with the key, so ssh never asks again. Leave it empty to skip the file.</div>
          {#each plan.needs_passphrase as f (f)}
            <label class="ewe-field">
              <span class="ewe-field__label"><span class="mono">{tilde(f)}</span><span class="ewe-field__optional">Passphrase</span></span>
              <span class="ewe-input">
                <input class="mono" type={showPass[f] ? "text" : "password"} bind:value={pass[f]} autocomplete="off" spellcheck="false" aria-label="Passphrase for {tilde(f)}" />
                <button type="button" class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm" aria-label={showPass[f] ? "Hide passphrase" : "Show passphrase"} onclick={() => (showPass = { ...showPass, [f]: !showPass[f] })}>
                  <Icon name={showPass[f] ? "eye-off" : "eye"} />
                </button>
              </span>
            </label>
          {/each}
        </div>
      {/if}
      {#if plan.missing_from_safe?.length}
        {@render missing(plan.missing_from_safe)}
      {/if}
      {#if own.length}
        <div class="caption safe-muted">Your own lines in ~/.ssh/config name another agent for {andList(own.map((o) => o.host))}. Safe never changes your lines, and answers for them anyway.</div>
      {/if}
    {/if}
  {/if}

  {#snippet foot()}
    {#if phase === "done" || nothing}
      <button class="ewe-btn ewe-btn--primary" data-autofocus onclick={close}>{nothing ? "Close" : "Done"}</button>
    {:else}
      <button class="ewe-btn ewe-btn--ghost" onclick={close}>Cancel</button>
      {#if error && !plan}
        <button class="ewe-btn ewe-btn--secondary" onclick={check}>Try again</button>
      {:else}
        <button class="ewe-btn ewe-btn--primary" disabled={phase !== "plan" || !plan || nothing} onclick={move}>{phase === "moving" ? "Moving…" : "Move"}</button>
      {/if}
    {/if}
  {/snippet}
</Sheet>

{#snippet missing(keys)}
  <div class="ewe-alert ewe-alert--warning" role="status">
    <Icon name="triangle-alert" />
    <div class="ewe-alert__body">
      <div class="ewe-alert__title">{count(keys.length, "key")} {keys.length === 1 ? "is" : "are"} only in {agent}</div>
      <div class="ewe-alert__desc">
        {andList(keys.map((k) => `${k.comment || "a key"} (${k.key_type})`))}. Safe can't take a key out of {agent}. Import {keys.length === 1 ? "it" : "them"} first, then move again.
      </div>
      <div class="ewe-alert__actions">
        <button class="ewe-btn ewe-btn--secondary ewe-btn--sm" onclick={toImport}><Icon name="file-down" />Import from {agent}</button>
      </div>
    </div>
  </div>
{/snippet}
