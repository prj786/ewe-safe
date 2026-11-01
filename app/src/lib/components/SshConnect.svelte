<script>
  // Connect to a service (docs/GATE.md S24, S28): three steps on one sheet.
  // 1. Key: a new key (recommended; RSA for Azure DevOps) or one you have.
  // 2. Add it there: the public key with Copy, the steps, Open <service> (in
  //    ewe browser); a server: its address and Open a terminal (ssh-copy-id);
  //    a cloud VM: its address when it is ready; GitHub and GitLab: also sign
  //    Git commits with it.
  // 3. Check: `ssh test`, and what to do next.
  // `ui.connect` = {service?, key?}: without a service, pick one first.
  import { onMount } from "svelte";
  import Icon from "./Icon.svelte";
  import Sheet from "./Sheet.svelte";
  import { api } from "../api.js";
  import { safe } from "../safe.svelte.js";
  import { ui } from "../ui.svelte.js";
  import { toasts } from "../toast.svelte.js";
  import { GROUP_ICON, GROUP_LABEL, badAlias, keyTypeName, shortFp } from "../ssh.js";

  // what a service asks for besides the key (the catalogue's `needs`)
  const FIELDS = {
    gitlab: [{ k: "host", label: "GitLab server", optional: true, placeholder: "gitlab.com", help: "Only for your own GitLab. Empty means gitlab.com." }],
    gitea: [{ k: "host", label: "Server", placeholder: "git.example.org", help: "The address of your Gitea or Forgejo." }],
    "azure-devops": [{ k: "org", label: "Organization", optional: true, placeholder: "my-company", help: "The name in dev.azure.com/my-company. Safe then opens the right page." }]
  };
  const SIGN_HINT = {
    github: "GitHub shows them as Verified when you add the key there once more, with Key type: Signing Key.",
    gitlab: "On GitLab, keep Usage type: Authentication & Signing."
  };

  const from = ui.connect ?? {};
  let svcId = $state(from.service ?? "");
  let step = $state(1);
  let way = $state(from.key ? "mine" : "new");
  let keyId = $state(from.key ?? "");
  let title = $state("");
  let f = $state({ host: "", org: "", user: "", port: "", alias: "" });
  let busy = $state(""); // "connect" | "test" | "save" | "open"
  let err = $state("");
  let conflict = $state(null); // {alias, title, yours}
  let second = $state("");
  let done = $state(null); // ssh-connect's reply
  let saved = $state(""); // a cloud host's name, once saved
  let terminal = $state(false); // the server's terminal opened
  let copied = $state(false);
  let test = $state(null); // ssh-test's reply
  let sign = $state({ on: false, busy: false, ask: false, email: "", error: "" });

  const svc = $derived(safe.ssh.services.find((s) => s.service === svcId) ?? null);
  const isServer = $derived(svc?.group === "server");
  const isCloud = $derived(svc?.group === "cloud");
  const rsaOnly = $derived(svc?.key_type === "rsa");
  const keys = $derived(safe.items.filter((i) => i.kind === "ssh-key").sort((a, b) => a.title.localeCompare(b.title)));
  const usable = $derived(keys.filter((k) => !rsaOnly || k.ssh?.key_type === "rsa"));
  const itemId = $derived(done?.item_id ?? (way === "mine" ? keyId : ""));
  const item = $derived(keys.find((k) => k.id === itemId) ?? null);
  const pubkey = $derived(done?.ssh?.public_key ?? item?.ssh?.public_key ?? "");
  const page = $derived(done?.page ?? svc?.page ?? null);
  const steps = $derived(done?.steps ?? svc?.steps ?? []);
  const target = $derived(done?.alias ?? (saved || null));
  const fields = $derived(
    FIELDS[svcId] ??
      (svc?.needs ?? [])
        .filter((n) => !isServer && n !== "user")
        .map((n) => ({ k: n, label: n === "host" ? "Server" : n[0].toUpperCase() + n.slice(1), placeholder: "" }))
  );
  const labels = $derived(["Key", isServer ? "Put it on the server" : `Add it to ${svc?.name ?? ""}`, "Check"]);
  const keyInfo = (k) => `${keyTypeName(k.ssh?.key_type)} · ${shortFp(k.ssh?.fingerprint)}`;

  onMount(() => {
    if (!safe.ssh.services.length) safe.loadSsh().then(() => svc && choose(svc));
    else if (svc) choose(svc);
  });

  function choose(s) {
    svcId = s.service;
    step = 1;
    err = "";
    title = s.service === "server" ? "My server" : s.name;
    f = { host: "", org: "", user: s.group === "cloud" && s.user !== "your name" ? s.user ?? "" : "", port: "", alias: "" };
    const ok = keys.filter((k) => s.key_type !== "rsa" || k.ssh?.key_type === "rsa");
    if (!ok.some((k) => k.id === keyId)) {
      // the key this service's host uses already, else one named after it
      const there = safe.ssh.hosts.find((h) => h.service === s.service && h.key)?.key?.item_id;
      keyId = (ok.find((k) => k.id === there) ?? ok.find((k) => k.title.toLowerCase().includes(s.name.toLowerCase())) ?? ok[0])?.id ?? "";
      if (!keyId) way = "new";
    }
  }

  function pickWay(w) {
    way = w;
    conflict = null;
    err = "";
  }

  async function connect(extra = {}) {
    err = "";
    conflict = null;
    busy = "connect";
    const r = await safe.sshConnect({
      service: svcId,
      key: itemId || undefined,
      title: itemId ? undefined : title.trim() || svc.name,
      host: f.host.trim() || undefined,
      user: isServer ? f.user.trim() : undefined,
      port: isServer && f.port.trim() ? Number(f.port) : undefined,
      org: f.org.trim() || undefined,
      alias: extra.alias,
      replace: extra.replace,
      // a server: Safe opens the terminal (ssh-copy-id); else the page opens
      // when the user presses Open
      noOpen: !isServer
    });
    busy = "";
    if (!r?.ok) {
      if (r?.error === "conflict") {
        const a = r.alias ?? (f.host.trim() || svc.host);
        const yours = safe.ssh.hosts.some((h) => h.alias === a && h.source === "yours") || /yourself/i.test(r.message ?? "");
        conflict = { alias: a, yours, title: /uses the key (.+?)\. /.exec(r.message ?? "")?.[1] ?? "" };
        second = `${svcId}-2`;
      } else err = r?.message ?? "Safe couldn't do that.";
      return false;
    }
    done = r;
    sign = { ...sign, on: safe.ssh.status?.signing?.item_id === r.item_id };
    return true;
  }

  async function next() {
    err = "";
    if (step === 1) {
      if (way === "mine" && !keyId) return (err = "Pick a key.");
      for (const x of fields) if (!x.optional && !f[x.k].trim()) return (err = `${x.label}: this is needed.`);
      if (isServer || done) {
        step = 2;
        return;
      }
      if (await connect()) step = 2;
    } else if (step === 2) {
      if (isServer && !done) return (err = "Open a terminal first, and put the key on the server.");
      step = 3;
    }
  }

  async function retry(extra) {
    if (extra.alias !== undefined) {
      const a = extra.alias.trim();
      if (!a || badAlias(a)) return (err = "A name can't be empty, or have a space, *, ? or !.");
      extra = { alias: a };
    }
    if ((await connect(extra)) && step === 1) step = 2;
    else if (isServer && done) terminal = true;
  }

  async function openTerminal() {
    if (!f.host.trim() || !f.user.trim()) return (err = "Type the server's address and your user name on it.");
    if (f.port.trim() && !(Number(f.port) > 0 && Number(f.port) < 65536)) return (err = "The port is a number from 1 to 65535.");
    if (await connect()) terminal = true;
  }

  async function copyKey() {
    if (!itemId) return;
    const r = await safe.copy(itemId, "public_key", 0);
    copied = !!r?.ok;
    if (!r?.ok) err = r?.message ?? "Couldn't copy.";
  }

  async function openPage() {
    busy = "open";
    await copyKey();
    const r = await api.openPage(page);
    busy = "";
    if (!r?.ok) err = r?.message ?? `Couldn't open ${svc.name}.`;
    else toasts.show(`Opened ${svc.name}. Your public key is copied: paste it there.`, { icon: "external-link", ms: 6000 });
  }

  async function saveAddress() {
    const a = (f.alias.trim() || f.host.trim());
    if (!f.host.trim()) return (err = "Type the address of your VM.");
    if (badAlias(a)) return (err = "A name can't have a space, *, ? or !.");
    busy = "save";
    err = "";
    const r = await safe.sshHostSet({ alias: a, host: f.host.trim(), user: f.user.trim(), key: itemId });
    busy = "";
    if (!r?.ok) return (err = r?.message ?? "Couldn't save the address.");
    saved = a;
  }

  async function toggleSign() {
    const on = !sign.on;
    sign = { ...sign, busy: true, error: "" };
    const r = await safe.sshSign(on ? { itemId } : { off: true });
    if (r?.ok) sign = { on, busy: false, ask: false, email: "", error: "" };
    else if (on && /email/i.test(r?.message ?? "")) sign = { ...sign, busy: false, ask: true };
    else sign = { ...sign, busy: false, error: r?.message ?? "Couldn't change it." };
  }

  async function signEmail() {
    if (!sign.email.includes("@")) return (sign = { ...sign, error: "Type the email you use in Git." });
    sign = { ...sign, busy: true, error: "" };
    const r = await safe.sshSign({ itemId, email: sign.email.trim() });
    sign = r?.ok ? { on: true, busy: false, ask: false, email: "", error: "" } : { ...sign, busy: false, error: r?.message ?? "Couldn't turn it on." };
  }

  async function check() {
    busy = "test";
    test = null;
    test = await safe.sshTest({ target, key: itemId || undefined });
    busy = "";
  }

  async function copyText(t) {
    try {
      await navigator.clipboard.writeText(t);
      toasts.show("Copied.", { icon: "clipboard-copy" });
    } catch {
      toasts.show(t, { icon: "info" });
    }
  }

  function close() {
    ui.connect = null;
  }
</script>

<Sheet title={!svc ? "Connect" : isServer ? "Connect to a server" : `Connect to ${svc.name}`} icon="link" onclose={close}>
  {#if !svc}
    <!-- pick a service -->
    <p class="body safe-secondary" style="margin:0">
      {#if from.key && item}Where do you want to use {item.title}?{:else}Where do you want to connect? Pick a place.{/if}
    </p>
    {#if safe.ssh.services.length}
      <div class="safe-services">
        {#each safe.ssh.services as s (s.service)}
          <button class="ewe-card ewe-card--interactive ewe-card--compact safe-service" onclick={() => choose(s)}>
            <span class="safe-service__icon"><Icon name={GROUP_ICON[s.group] ?? "link"} /></span>
            <span class="safe-service__text">
              <span class="safe-service__name">{s.name}</span>
              <span class="safe-service__group">{GROUP_LABEL[s.group] ?? ""}</span>
            </span>
          </button>
        {/each}
      </div>
    {:else}
      <div class="safe-result safe-muted" role="status"><span class="ewe-spinner ewe-spinner--sm ewe-spinner--neutral"></span>Loading…</div>
    {/if}
  {:else}
    <div class="ewe-steps" aria-label="Steps">
      {#each labels as label, n (n)}
        {#if n}<span class="ewe-steps__line" class:is-done={step > n}></span>{/if}
        <span class="ewe-step" class:is-done={step > n + 1} class:is-current={step === n + 1} aria-current={step === n + 1 ? "step" : undefined}>
          <span class="ewe-step__dot">{#if step > n + 1}<Icon name="check" />{:else}{n + 1}{/if}</span>{label}
        </span>
      {/each}
    </div>

    {#if step === 1}
      <div class="safe-stack" role="radiogroup" aria-label="Which key">
        <button type="button" class="ewe-choice" class:is-selected={way === "new"} role="radio" aria-checked={way === "new"} onclick={() => pickWay("new")}>
          <span class="ewe-check ewe-check--radio" class:is-checked={way === "new"}><span class="ewe-check__box">{#if way === "new"}<span class="ewe-check__dot"></span>{/if}</span></span>
          <span class="ewe-choice__text">
            <span class="ewe-choice__title">A new key (recommended)</span>
            <span class="ewe-choice__desc">{rsaOnly ? `${svc.name} takes only RSA keys, so Safe makes an RSA key.` : `One key just for ${svc.name}. Safe makes it and keeps it.`}</span>
          </span>
        </button>
        {#if way === "new"}
          <label class="ewe-field">
            <span class="ewe-field__label"><span>Name of the key</span></span>
            <span class="ewe-input"><input bind:value={title} autocomplete="off" spellcheck="false" placeholder={svc.name} /></span>
          </label>
        {/if}
        <button type="button" class="ewe-choice" class:is-selected={way === "mine"} class:is-disabled={!usable.length} role="radio" aria-checked={way === "mine"} disabled={!usable.length} onclick={() => pickWay("mine")}>
          <span class="ewe-check ewe-check--radio" class:is-checked={way === "mine"}><span class="ewe-check__box">{#if way === "mine"}<span class="ewe-check__dot"></span>{/if}</span></span>
          <span class="ewe-choice__text">
            <span class="ewe-choice__title">A key you have</span>
            <span class="ewe-choice__desc">{usable.length ? "Use a key that is in Safe already." : rsaOnly ? "You have no RSA key in Safe yet." : "You have no SSH key in Safe yet."}</span>
          </span>
        </button>
        {#if way === "mine" && usable.length}
          <label class="ewe-field">
            <span class="ewe-field__label"><span>Key</span></span>
            <select class="ewe-input ewe-select" bind:value={keyId}>
              {#each usable as k (k.id)}<option value={k.id}>{k.title} · {keyInfo(k)}</option>{/each}
            </select>
          </label>
        {/if}
      </div>
      {#each fields as x (x.k)}
        <label class="ewe-field">
          <span class="ewe-field__label"><span>{x.label}</span>{#if x.optional}<span class="ewe-field__optional">Optional</span>{/if}</span>
          <span class="ewe-input"><input class="mono" bind:value={f[x.k]} autocomplete="off" spellcheck="false" placeholder={x.placeholder} /></span>
          {#if x.help}<span class="ewe-field__helper">{x.help}</span>{/if}
        </label>
      {/each}
      {@render problems()}
    {:else if step === 2}
      {#if isServer}
        <p class="body safe-secondary" style="margin:0">Safe opens a terminal that puts your public key on the server. You need your password for the server once.</p>
        <div class="safe-fields">
          <label class="ewe-field">
            <span class="ewe-field__label"><span>Address</span></span>
            <span class="ewe-input"><input class="mono" bind:value={f.host} disabled={!!done} autocomplete="off" spellcheck="false" placeholder="server.example.org" /></span>
          </label>
          <label class="ewe-field">
            <span class="ewe-field__label"><span>User</span></span>
            <span class="ewe-input"><input class="mono" bind:value={f.user} disabled={!!done} autocomplete="off" spellcheck="false" placeholder="sam" /></span>
          </label>
          <label class="ewe-field">
            <span class="ewe-field__label"><span>Port</span></span>
            <span class="ewe-input"><input class="mono" bind:value={f.port} disabled={!!done} inputmode="numeric" autocomplete="off" spellcheck="false" placeholder="22" /></span>
          </label>
        </div>
        {#if pubkey}{@render key()}{/if}
        <ol class="safe-steps">{#each steps as s, n (n)}<li>{s}</li>{/each}</ol>
        <div class="safe-actions">
          <button class="ewe-btn ewe-btn--primary" disabled={busy === "connect"} onclick={openTerminal}><Icon name="square-terminal" />{busy === "connect" ? "Opening…" : terminal ? "Open the terminal again" : "Open a terminal"}</button>
        </div>
        {#if terminal}
          <div class="safe-note caption" role="status"><Icon name="circle-check" /><span>A terminal opened. Type your password for the server there. When it says the key was added, come back and press Continue.</span></div>
        {/if}
        {@render problems()}
      {:else}
        {@render key()}
        <ol class="safe-steps">{#each steps as s, n (n)}<li>{s}</li>{/each}</ol>
        {#if page}
          <div class="safe-actions">
            <button class="ewe-btn ewe-btn--primary" disabled={busy === "open"} onclick={openPage}><Icon name="external-link" />Open {svc.name}</button>
          </div>
        {/if}
        {#if isCloud}
          <div class="safe-stack">
            <div class="label">When your VM is ready</div>
            <div class="caption safe-muted">Add its address, and ssh knows which key to use. You can do this later in Hosts too.</div>
            <div class="safe-fields">
              <label class="ewe-field">
                <span class="ewe-field__label"><span>Address</span><span class="ewe-field__optional">Optional</span></span>
                <span class="ewe-input"><input class="mono" bind:value={f.host} disabled={!!saved} autocomplete="off" spellcheck="false" placeholder="20.61.14.2" /></span>
              </label>
              <label class="ewe-field">
                <span class="ewe-field__label"><span>User</span></span>
                <span class="ewe-input"><input class="mono" bind:value={f.user} disabled={!!saved} autocomplete="off" spellcheck="false" placeholder={svc.user || "sam"} /></span>
              </label>
              <label class="ewe-field">
                <span class="ewe-field__label"><span>Name</span><span class="ewe-field__optional">Optional</span></span>
                <span class="ewe-input"><input class="mono" bind:value={f.alias} disabled={!!saved} autocomplete="off" spellcheck="false" placeholder="my-vm" /></span>
              </label>
            </div>
            {#if saved}
              <div class="safe-note caption" role="status"><Icon name="circle-check" /><span>Saved. Use it with: <span class="mono">ssh {saved}</span></span></div>
            {:else}
              <div class="safe-actions"><button class="ewe-btn ewe-btn--secondary ewe-btn--sm" disabled={busy === "save" || !f.host.trim()} onclick={saveAddress}>{busy === "save" ? "Saving…" : "Save the address"}</button></div>
            {/if}
          </div>
        {/if}
        {#if svc.signing}
          <div class="safe-stack">
            <button type="button" class="ewe-check" class:is-checked={sign.on} role="checkbox" aria-checked={sign.on} disabled={sign.busy || !itemId} onclick={toggleSign}>
              <span class="ewe-check__box">{#if sign.on}<Icon name="check" />{/if}</span>
              <span class="ewe-check__text">
                <span class="ewe-check__label">Also sign my Git commits with this key</span>
                <span class="ewe-check__desc">{SIGN_HINT[svc.service] ?? "Others see that your commits really come from you."}</span>
              </span>
            </button>
            {#if sign.ask}
              <div class="ewe-field">
                <label class="ewe-field__label" for="safe-sign-mail"><span>Your Git email</span></label>
                <div class="safe-compact__row">
                  <span class="ewe-input"><input id="safe-sign-mail" type="email" bind:value={sign.email} autocomplete="email" spellcheck="false" placeholder="you@example.org" /></span>
                  <button class="ewe-btn ewe-btn--secondary" disabled={sign.busy} onclick={signEmail}>Save</button>
                </div>
                <span class="ewe-field__helper">Git puts this email on your signed commits. Use the one {svc.name} knows.</span>
              </div>
            {/if}
            {#if sign.error}<div class="ewe-field__helper ewe-field__helper--error" role="alert"><Icon name="circle-x" /><span>{sign.error}</span></div>{/if}
          </div>
        {/if}
        {@render problems()}
      {/if}
    {:else}
      {#if target}
        <p class="body safe-secondary" style="margin:0">Safe connects to <span class="mono">{target}</span> the way ssh does, to see that the key works.</p>
        <div class="safe-actions">
          <button class="ewe-btn ewe-btn--primary" disabled={busy === "test"} data-autofocus onclick={check}><Icon name="plug" />{busy === "test" ? "Checking…" : test ? "Check again" : "Check"}</button>
        </div>
        <div aria-live="polite">
          {#if test}
            {@const tone = !test.ok ? "warning" : test.host_key === "changed" ? "danger" : test.connected ? "success" : "warning"}
            <div class="ewe-alert ewe-alert--{tone}">
              <Icon name={tone === "success" ? "circle-check" : tone === "danger" ? "shield-alert" : "circle-alert"} />
              <div class="ewe-alert__body">
                <div class="ewe-alert__title">{test.message ?? "The check didn't run."}</div>
                {#if test.ok && !test.connected && test.host_key !== "changed"}
                  <div class="ewe-alert__desc">{isServer ? "Did the terminal say the key was added? Then check again." : `Did you add the key on the ${svc.name} page? Then check again.`}</div>
                {/if}
                {#if test.detail}
                  <details>
                    <summary class="caption">What ssh said</summary>
                    <pre class="safe-detailtext">{test.detail}</pre>
                  </details>
                {/if}
              </div>
            </div>
          {/if}
        </div>
        {#if done?.remote_hint}
          <div class="safe-stack">
            <div class="label">In git, use addresses like this</div>
            <div class="safe-pubkey">
              <span class="mono">{done.remote_hint}</span>
              <button class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm" aria-label="Copy the address" onclick={() => copyText(done.remote_hint)}><Icon name="copy" /></button>
            </div>
            {#if done.alias && svc.host && done.alias !== svc.host}
              <div class="caption safe-muted">{done.alias} is your second {svc.name} account. Use this name instead of {svc.host}.</div>
            {/if}
          </div>
        {/if}
      {:else}
        <div class="safe-gate"><Icon name="info" /><span>Add your VM's address first (step 2). You can also check it later in Hosts.</span></div>
      {/if}
    {/if}
  {/if}

  {#snippet foot()}
    {#if !svc}
      <button class="ewe-btn ewe-btn--ghost" onclick={close}>Cancel</button>
    {:else if step === 1}
      {#if !from.service}<button class="ewe-btn ewe-btn--ghost" onclick={() => (svcId = "")}><Icon name="chevron-left" />Back</button>{/if}
      <button class="ewe-btn ewe-btn--ghost" onclick={close}>Cancel</button>
      <button class="ewe-btn ewe-btn--primary" disabled={busy === "connect"} onclick={next}>{busy === "connect" ? (way === "new" && !done ? "Making the key…" : "Saving…") : "Continue"}</button>
    {:else if step === 2}
      {#if isServer && !done}<button class="ewe-btn ewe-btn--ghost" onclick={() => (step = 1)}><Icon name="chevron-left" />Back</button>{/if}
      <button class="ewe-btn ewe-btn--primary" disabled={isServer && !done} onclick={next}>Continue</button>
    {:else}
      <button class="ewe-btn ewe-btn--ghost" onclick={() => (step = 2)}><Icon name="chevron-left" />Back</button>
      <button class="ewe-btn ewe-btn--primary" onclick={close}>Done</button>
    {/if}
  {/snippet}
</Sheet>

{#snippet key()}
  {#if pubkey}
    <div class="safe-stack">
      <div class="label">Your public key{item ? ` · ${item.title}` : ""}</div>
      <div class="safe-pubkey">
        <span class="mono">{pubkey}</span>
        <button class="ewe-btn ewe-btn--secondary ewe-btn--sm" onclick={copyKey}><Icon name={copied ? "check" : "copy"} />{copied ? "Copied" : "Copy"}</button>
      </div>
      <div class="caption safe-muted">This part is safe to share. The private key stays in Safe.</div>
    </div>
  {/if}
{/snippet}

{#snippet problems()}
  {#if conflict}
    <div class="ewe-alert ewe-alert--warning" role="alert">
      <Icon name="triangle-alert" />
      <div class="ewe-alert__body">
        <div class="ewe-alert__title">
          {conflict.yours ? `You set up ${conflict.alias} yourself` : conflict.title ? `${conflict.alias} already uses the key ${conflict.title}` : `${conflict.alias} already uses another key`}
        </div>
        <div class="ewe-alert__desc">
          {conflict.yours
            ? "It is in your own lines in ~/.ssh/config, and Safe doesn't change them. Give this connection its own name:"
            : "Use this key for it instead. Or, for a second account, give this one its own name:"}
        </div>
        <div class="safe-compact__row">
          <span class="ewe-input ewe-input--sm"><input class="mono" bind:value={second} aria-label="Name for the second account" spellcheck="false" /></span>
          <button class="ewe-btn ewe-btn--secondary ewe-btn--sm" disabled={busy === "connect"} onclick={() => retry({ alias: second })}>Use this name</button>
        </div>
        {#if !conflict.yours}
          <div class="ewe-alert__actions">
            <button class="ewe-btn ewe-btn--secondary ewe-btn--sm" disabled={busy === "connect"} onclick={() => retry({ replace: true })}>Use this key instead</button>
          </div>
        {/if}
      </div>
    </div>
  {/if}
  {#if err}<div class="ewe-field__helper ewe-field__helper--error" role="alert"><Icon name="circle-x" /><span>{err}</span></div>{/if}
{/snippet}
