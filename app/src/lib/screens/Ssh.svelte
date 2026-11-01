<script>
  // The SSH page (docs/GATE.md S28): one scroll — the gate (is Safe the
  // agent every ssh asks?), Connect (the services), your keys, the hosts ssh
  // knows, your ewe computers, and where all this lives. The sheets: move
  // SSH to Safe, a host, a new key; connecting is Main's (an item opens it
  // too).
  import { untrack } from "svelte";
  import Icon from "../components/Icon.svelte";
  import Sheet from "../components/Sheet.svelte";
  import SshKeyNew from "../components/SshKeyNew.svelte";
  import SshTakeover from "../components/SshTakeover.svelte";
  import SshHostEdit from "../components/SshHostEdit.svelte";
  import { api } from "../api.js";
  import { safe } from "../safe.svelte.js";
  import { ui } from "../ui.svelte.js";
  import { toasts } from "../toast.svelte.js";
  import { CONFIRMS, GROUP_ICON, GROUP_LABEL, andList, count, gateOf, hostLine, keyTypeName, lastUsed, shortFp, usedBy } from "../ssh.js";

  let now = $state(new Date());
  let choice = $state("first-use"); // the approval choice before Turn on
  let checks = $state({}); // alias → {busy} | {r}
  let menu = $state(""); // "key:<id>" | "host:<alias>" | "gate"
  let hostEdit = $state(null); // {host?} — a new host, or one to change
  let removing = $state(null); // the host to remove
  let turningOff = $state(false);
  let signAsk = $state(null); // {item, email, error, busy}: signing needs the Git email

  // again when items change (here or merged in from another computer)
  $effect(() => {
    void safe.changes;
    untrack(() => safe.loadSsh({ remote: true }));
  });
  $effect(() => {
    const t = setInterval(() => (now = new Date()), 30000);
    return () => clearInterval(t);
  });

  const st = $derived(safe.ssh.status);
  const hosts = $derived(safe.ssh.hosts);
  const gate = $derived(gateOf(st, hosts));
  const services = $derived(safe.ssh.services);
  const keys = $derived(safe.items.filter((i) => i.kind === "ssh-key").sort((a, b) => a.title.localeCompare(b.title)));
  const remote = $derived(safe.ssh.remote);
  const signing = $derived(st?.signing ?? null);
  const confirm = $derived(st?.confirm ?? "first-use");
  const account = $derived(safe.status?.place?.kind === "nextcloud");
  const connected = (service) => hosts.some((h) => h.service === service && h.key);

  async function turnOn() {
    const r = await safe.sshEnable(choice);
    if (r?.ok) toasts.show("Safe is your SSH agent now.", { icon: "circle-check" });
    else toasts.show(r?.message ?? "Couldn't turn it on.", { icon: "circle-alert", ms: 7000 });
  }

  async function setConfirm(c) {
    if (c === confirm) return;
    const r = await safe.sshEnable(c);
    if (!r?.ok) toasts.show(r?.message ?? "Couldn't change it.", { icon: "circle-alert" });
  }

  async function turnOff() {
    turningOff = false;
    const r = await safe.sshDisable();
    if (r?.ok) toasts.show("Safe's SSH agent is off.", { icon: "circle-check" });
    else toasts.show(r?.message ?? "Couldn't turn it off.", { icon: "circle-alert" });
  }

  async function copyKey(k) {
    const r = await safe.copy(k.id, "public_key", 0);
    toasts.show(r?.ok ? `Copied the public key of ${k.title}.` : r?.message ?? "Couldn't copy.", { icon: r?.ok ? "clipboard-copy" : "circle-alert" });
  }

  async function sign(k, on) {
    menu = "";
    const r = await safe.sshSign(on ? { itemId: k.id } : { off: true });
    if (r?.ok) {
      toasts.show(on ? `Git signs your commits with ${k.title} now.` : "Git doesn't sign your commits now.", { icon: "signature" });
    } else if (on && /email/i.test(r?.message ?? "")) {
      signAsk = { item: k, email: "", error: "", busy: false };
    } else {
      toasts.show(r?.message ?? "Couldn't change it.", { icon: "circle-alert" });
    }
  }

  async function signWithEmail(e) {
    e.preventDefault();
    if (!signAsk.email.includes("@")) {
      signAsk = { ...signAsk, error: "Type the email you use in Git." };
      return;
    }
    signAsk = { ...signAsk, busy: true, error: "" };
    const r = await safe.sshSign({ itemId: signAsk.item.id, email: signAsk.email.trim() });
    if (r?.ok) {
      toasts.show(`Git signs your commits with ${signAsk.item.title} now.`, { icon: "signature" });
      signAsk = null;
    } else signAsk = { ...signAsk, busy: false, error: r?.message ?? "Couldn't turn it on." };
  }

  function showItem(k) {
    menu = "";
    ui.pick({ kind: "ssh-key" });
    ui.selected = k.id;
  }

  async function check(h) {
    checks = { ...checks, [h.alias]: { busy: true } };
    const r = await safe.sshTest({ target: h.alias });
    checks = { ...checks, [h.alias]: { r } };
  }

  async function terminal(h) {
    const r = await api.sshTerminal(h.alias);
    if (!r?.ok) toasts.show(r?.message ?? "Couldn't open a terminal.", { icon: "circle-alert" });
  }

  async function remoteTerminal(c) {
    const r = await api.remoteTerminal(c.id);
    if (!r?.ok) toasts.show(r?.message ? `${r.message}.`.replace(/\.\.$/, ".") : "Couldn't open a terminal.", { icon: "circle-alert" });
  }

  async function remove() {
    const h = removing;
    removing = null;
    const r = await safe.sshHostRemove(h.alias);
    if (r?.ok) toasts.show(`Removed ${h.alias}.`, { icon: "trash-2" });
    else toasts.show(r?.message ?? "Couldn't remove it.", { icon: "circle-alert" });
  }

  function resultOf(c) {
    const r = c?.r;
    if (!r) return null;
    if (!r.ok) return { tone: "is-bad", icon: "circle-alert", text: r.message ?? "The check didn't run." };
    if (r.host_key === "changed") return { tone: "is-danger", icon: "shield-alert", text: r.message };
    return r.connected ? { tone: "is-ok", icon: "circle-check", text: r.message } : { tone: "is-bad", icon: "circle-alert", text: r.message };
  }
</script>

<svelte:window
  onclick={(e) => {
    if (menu && !e.target.closest?.(".safe-rel")) menu = "";
  }}
  onkeydowncapture={(e) => {
    // Esc closes an open menu first (before the window goes back to the list)
    if (menu && e.key === "Escape") {
      e.stopPropagation();
      menu = "";
    }
  }}
/>

<div class="ewe-headerbar ewe-headerbar--page" style="padding:var(--space-md) calc(var(--space-md) + var(--space-s)) calc(var(--space-s) + var(--space-xs))">
  <div class="ewe-headerbar__titles">
    <h1 class="ewe-headerbar__title" style="margin:0">SSH</h1>
    <div class="ewe-headerbar__subtitle">Your SSH keys, and the places they open.</div>
  </div>
  <div class="ewe-headerbar__actions">
    <button class="ewe-btn ewe-btn--primary ewe-btn--sm" disabled={safe.readOnly} onclick={() => (ui.connect = {})}><Icon name="link" />Connect…</button>
  </div>
</div>

<div class="safe-page">
  <div class="safe-page__body">
    <!-- 1. the gate -->
    {#if gate?.kind === "off"}
      <div class="ewe-card">
        <div class="ewe-card__head">
          <span class="ewe-card__icon ewe-card__icon--accent"><Icon name="terminal" /></span>
          <div class="ewe-card__titles">
            <h2 class="ewe-card__title" style="margin:0">Make Safe your SSH agent</h2>
            <div class="ewe-card__desc">Then every ssh and git on this computer asks Safe for keys. Your private keys never leave Safe.</div>
          </div>
        </div>
        {@render approval(choice, (c) => (choice = c))}
        <div class="ewe-card__foot">
          <button class="ewe-btn ewe-btn--primary" disabled={safe.busy === "ssh-enable"} onclick={turnOn}>{safe.busy === "ssh-enable" ? "Turning on…" : "Turn on"}</button>
        </div>
      </div>
    {:else if gate?.kind === "move"}
      <div class="ewe-alert ewe-alert--warning" role="status">
        <Icon name="triangle-alert" />
        <div class="ewe-alert__body">
          <div class="ewe-alert__title">
            {#if !gate.on && gate.hosts.length}{gate.agent} still answers ssh for {andList(gate.hosts)}{:else if !gate.on}ssh doesn't ask Safe yet{:else}Finish moving SSH to Safe{/if}
          </div>
          <ul class="safe-points" style="gap:var(--space-xs)">
            {#if !gate.on && !gate.hosts.length}<li>Another program may still answer ssh on this computer.</li>{/if}
            {#if gate.on && gate.hosts.length}<li>{andList(gate.hosts)} still {gate.hosts.length === 1 ? "names" : "name"} {gate.agent}. Safe answers for {gate.hosts.length === 1 ? "it" : "them"} now.</li>{/if}
            {#if gate.missing}<li>{count(gate.missing, "key")} {gate.missing === 1 ? "is" : "are"} only in {gate.agent}. Safe doesn't have {gate.missing === 1 ? "it" : "them"} yet.</li>{/if}
            {#if gate.files.length}<li>{count(gate.files.length, "key file")} in ~/.ssh {gate.files.length === 1 ? "is" : "are"} not in Safe yet.</li>{/if}
          </ul>
          <div class="ewe-alert__actions">
            <button class="ewe-btn ewe-btn--primary ewe-btn--sm" disabled={safe.readOnly} onclick={() => (ui.takeover = true)}><Icon name="arrow-right" />Move SSH to Safe</button>
            {#if gate.missing}
              <button class="ewe-btn ewe-btn--secondary ewe-btn--sm" disabled={safe.readOnly} onclick={() => ui.go("import")}><Icon name="file-down" />Import from {gate.agent}</button>
            {/if}
          </div>
        </div>
      </div>
    {:else if gate?.kind === "good"}
      <div class="safe-gate" role="status">
        <Icon name="shield-check" />
        <span>Safe is your SSH agent. Every ssh and git on this computer asks Safe.</span>
      </div>
      {#if gate.ownLines.length}
        <div class="caption safe-muted">
          Your own lines in ~/.ssh/config name another agent for {andList(gate.ownLines.map((o) => o.host))}. Safe never changes your lines, and answers for them anyway.
        </div>
      {/if}
    {/if}
    {#if gate && gate.kind !== "off"}
      <div class="ewe-list">
        <div class="ewe-row">
          <span class="ewe-row__text">
            <span class="ewe-row__title">Ask before a key is used</span>
            <span class="ewe-row__desc">{confirm === "never" ? "Any app can use your keys without a question while Safe is open." : "Safe asks you, and names the app."}</span>
          </span>
          <span class="ewe-row__trail">
            {@render approvalSeg(confirm, setConfirm)}
            <span class="safe-rel">
              <button class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm" aria-label="More for the SSH agent" aria-haspopup="menu" aria-expanded={menu === "gate"} onclick={() => (menu = menu === "gate" ? "" : "gate")}><Icon name="ellipsis" /></button>
              {#if menu === "gate"}
                <div class="ewe-menu safe-menu" role="menu">
                  <button class="ewe-menu__item ewe-menu__item--danger" role="menuitem" onclick={() => ((menu = ""), (turningOff = true))}><Icon name="x" />Turn off Safe's SSH agent…</button>
                </div>
              {/if}
            </span>
          </span>
        </div>
      </div>
    {/if}

    <!-- 2. connect -->
    <div class="ewe-section" style="margin-top:var(--space-s)">
      <div class="ewe-section__text">
        <h2 class="ewe-section__title" style="margin:0">Connect</h2>
        <div class="ewe-section__desc">Pick a place. Safe makes a key and shows you where to add it.</div>
      </div>
    </div>
    <div class="safe-services">
      {#each services as s (s.service)}
        <button class="ewe-card ewe-card--interactive ewe-card--compact safe-service" disabled={safe.readOnly} onclick={() => (ui.connect = { service: s.service })}>
          <span class="safe-service__icon"><Icon name={GROUP_ICON[s.group] ?? "link"} /></span>
          <span class="safe-service__text">
            <span class="safe-service__name">{s.name}</span>
            <span class="safe-service__group">{#if connected(s.service)}<Icon name="circle-check" />Connected{:else}{GROUP_LABEL[s.group] ?? ""}{/if}</span>
          </span>
        </button>
      {:else}
        <div class="caption safe-muted">Loading…</div>
      {/each}
    </div>

    <!-- 3. keys -->
    <div class="ewe-section" style="margin-top:var(--space-s)">
      <div class="ewe-section__text">
        <h2 class="ewe-section__title" style="margin:0">Keys</h2>
        <div class="ewe-section__desc">The private keys stay in Safe. ssh asks Safe each time it needs one.</div>
      </div>
      <button class="ewe-btn ewe-btn--ghost ewe-btn--sm" disabled={safe.readOnly} onclick={() => (ui.editing = { mode: "new", kind: "ssh-key", way: "file" })}><Icon name="file-key" />Add a key</button>
      <button class="ewe-btn ewe-btn--secondary ewe-btn--sm" disabled={safe.readOnly} onclick={() => (ui.editing = { mode: "new", kind: "ssh-key", way: "new" })}><Icon name="plus" />New key</button>
    </div>
    <div class="ewe-list">
      {#each keys as k, n (k.id)}
        {@const used = usedBy(hosts, k.id)}
        {@const signs = signing?.item_id === k.id}
        {#if n}<div class="ewe-list__divider"></div>{/if}
        <div class="ewe-row" style="align-items:flex-start;padding-block:var(--space-s)">
          <span class="ewe-row__lead ewe-row__lead--tile"><Icon name="terminal" /></span>
          <span class="safe-rowtext">
            <span class="safe-rowtitle">
              <span class="ewe-row__title">{k.title}</span>
              {#if signs}<span class="ewe-badge ewe-badge--accent"><Icon name="signature" /><span class="ewe-badge__label">Signs commits</span></span>{/if}
            </span>
            <span class="ewe-row__desc">{keyTypeName(k.ssh?.key_type)} · <span class="mono">{shortFp(k.ssh?.fingerprint)}</span></span>
            <span class="ewe-row__desc">{lastUsed(k.ssh?.last_used, now)}</span>
            {#if used.length}
              <span class="safe-chips safe-chips--start"><span class="caption">Used by</span>{#each used as h (h.alias)}<span class="ewe-tag">{h.alias}</span>{/each}</span>
            {/if}
          </span>
          <span class="ewe-row__trail">
            <button class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm" aria-label="Copy the public key of {k.title}" title="Copy public key" onclick={() => copyKey(k)}><Icon name="copy" /></button>
            <button class="ewe-btn ewe-btn--secondary ewe-btn--sm" disabled={safe.readOnly} onclick={() => (ui.connect = { key: k.id })}>Connect…</button>
            <span class="safe-rel">
              <button class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm" aria-label="More for {k.title}" aria-haspopup="menu" aria-expanded={menu === `key:${k.id}`} onclick={() => (menu = menu === `key:${k.id}` ? "" : `key:${k.id}`)}><Icon name="ellipsis" /></button>
              {#if menu === `key:${k.id}`}
                <div class="ewe-menu safe-menu" role="menu">
                  {#if signs}
                    <button class="ewe-menu__item" role="menuitem" onclick={() => sign(k, false)}><Icon name="signature" />Stop signing commits</button>
                  {:else}
                    <button class="ewe-menu__item" role="menuitem" onclick={() => sign(k, true)}><Icon name="signature" />Sign Git commits with this key</button>
                  {/if}
                  <button class="ewe-menu__item" role="menuitem" onclick={() => showItem(k)}><Icon name="arrow-right" />Show the item</button>
                </div>
              {/if}
            </span>
          </span>
        </div>
      {:else}
        <div class="ewe-row"><span class="ewe-row__text"><span class="ewe-row__desc">No SSH keys yet. Make one, or connect to a place above.</span></span></div>
      {/each}
    </div>

    <!-- 4. hosts -->
    <div class="ewe-section" style="margin-top:var(--space-s)">
      <div class="ewe-section__text">
        <h2 class="ewe-section__title" style="margin:0">Hosts</h2>
        <div class="ewe-section__desc">The names you use with ssh, and the key each one uses.</div>
      </div>
      <button class="ewe-btn ewe-btn--secondary ewe-btn--sm" disabled={safe.readOnly} onclick={() => (hostEdit = {})}><Icon name="plus" />Add a host</button>
    </div>
    <div class="ewe-list">
      {#each hosts as h, n (h.alias)}
        {@const res = resultOf(checks[h.alias])}
        {#if n}<div class="ewe-list__divider"></div>{/if}
        <div class="ewe-row" style="align-items:flex-start;padding-block:var(--space-s)">
          <span class="ewe-row__lead ewe-row__lead--tile"><Icon name="server" /></span>
          <span class="safe-rowtext">
            <span class="safe-rowtitle">
              <span class="ewe-row__title mono">{h.alias}</span>
              {#if h.source === "yours"}<span class="ewe-badge" title="Your own line in ~/.ssh/config. Safe doesn't change it."><span class="ewe-badge__label">yours</span></span>{/if}
            </span>
            <span class="ewe-row__desc mono">{hostLine(h)}</span>
            <span class="safe-chips safe-chips--start">
              {#if h.key}<span class="ewe-tag"><Icon name="key-round" />{h.key.title}</span>{:else if h.file}<span class="ewe-tag" title="A key file, not in Safe"><Icon name="file-key" />{h.file.split("/").pop()}</span>{:else}<span class="caption">Any key</span>{/if}
              {#if h.agent && h.agent !== "safe"}<span class="caption">· asks {h.agent.includes("1password") ? "1Password" : h.agent}</span>{/if}
            </span>
            <span aria-live="polite">
              {#if checks[h.alias]?.busy}
                <span class="safe-result safe-muted"><span class="ewe-spinner ewe-spinner--sm ewe-spinner--neutral"></span>Checking {h.alias}…</span>
              {:else if res}
                <span class="safe-result {res.tone}"><Icon name={res.icon} /><span>{res.text}</span></span>
              {/if}
            </span>
          </span>
          <span class="ewe-row__trail">
            <button class="ewe-btn ewe-btn--ghost ewe-btn--sm" title="Open a terminal: ssh {h.alias}" onclick={() => terminal(h)}><Icon name="square-terminal" />Open</button>
            <button class="ewe-btn ewe-btn--secondary ewe-btn--sm" disabled={checks[h.alias]?.busy} onclick={() => check(h)}>Check</button>
            {#if h.source === "ewe"}
              <span class="safe-rel">
                <button class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm" aria-label="More for {h.alias}" aria-haspopup="menu" aria-expanded={menu === `host:${h.alias}`} onclick={() => (menu = menu === `host:${h.alias}` ? "" : `host:${h.alias}`)}><Icon name="ellipsis" /></button>
                {#if menu === `host:${h.alias}`}
                  <div class="ewe-menu safe-menu" role="menu">
                    <button class="ewe-menu__item" role="menuitem" disabled={safe.readOnly} onclick={() => ((menu = ""), (hostEdit = { host: h }))}><Icon name="pencil" />Edit</button>
                    <button class="ewe-menu__item ewe-menu__item--danger" role="menuitem" disabled={safe.readOnly} onclick={() => ((menu = ""), (removing = h))}><Icon name="trash-2" />Remove</button>
                  </div>
                {/if}
              </span>
            {:else}
              <span class="ewe-iconbtn ewe-iconbtn--sm" aria-hidden="true"></span>
            {/if}
          </span>
        </div>
      {:else}
        <div class="ewe-row"><span class="ewe-row__text"><span class="ewe-row__desc">No hosts yet. Connect to a place, or add a host.</span></span></div>
      {/each}
    </div>

    <!-- 5. your ewe computers (only with ewe-remote) -->
    {#if remote}
      <div class="ewe-section" style="margin-top:var(--space-s)">
        <div class="ewe-section__text">
          <h2 class="ewe-section__title" style="margin:0">Your ewe computers</h2>
          <div class="ewe-section__desc">Each computer has its own key. It stays on that computer, so you can lock out one computer alone.</div>
        </div>
      </div>
      <div class="ewe-list">
        {#each remote.computers ?? [] as c, n (c.id)}
          {#if n}<div class="ewe-list__divider"></div>{/if}
          <div class="ewe-row">
            <span class="ewe-row__lead ewe-row__lead--tile"><Icon name="laptop" /></span>
            <span class="ewe-row__text">
              <span class="ewe-row__title">{c.name || "A computer"}</span>
              <span class="ewe-row__desc" style="display:flex;align-items:center;gap:var(--space-xs)">
                <span class="safe-dot" class:safe-dot--off={!c.online}></span>{c.online ? "Online" : c.online === false ? "Offline" : "Not seen yet"}{c.paired ? "" : " · not paired with this computer"}
              </span>
            </span>
            {#if c.paired}
              <span class="ewe-row__trail">
                <button class="ewe-btn ewe-btn--ghost ewe-btn--sm" title="Open a terminal on {c.name}" onclick={() => remoteTerminal(c)}><Icon name="square-terminal" />Open terminal</button>
              </span>
            {/if}
          </div>
        {:else}
          <div class="ewe-row"><span class="ewe-row__text"><span class="ewe-row__desc">No other ewe computers yet.</span></span></div>
        {/each}
      </div>
    {/if}

    <!-- 6. where this lives -->
    <div class="safe-note caption" style="margin-top:var(--space-s)">
      <Icon name={account ? "cloud" : "laptop"} />
      <span>{account ? "Your keys, hosts and these settings follow your ewe account to every computer you sign in to." : "This safe is only on this computer."}</span>
    </div>
  </div>
</div>

{#snippet approvalSeg(value, pick)}
  <div class="ewe-seg ewe-seg--sm" style="align-self:flex-start" role="radiogroup" aria-label="Ask before a key is used">
    {#each CONFIRMS as [c, label] (c)}
      <button class="ewe-seg__item" class:is-selected={value === c} role="radio" aria-checked={value === c} disabled={safe.busy === "ssh-enable"} onclick={() => pick(c)}>{label}</button>
    {/each}
  </div>
{/snippet}

{#snippet approval(value, pick)}
  <div class="safe-stack">
    <div class="label">Ask before a key is used</div>
    {@render approvalSeg(value, pick)}
    <div class="caption safe-muted">
      {value === "first-use"
        ? "Safe asks the first time each app uses a key, and names the app."
        : value === "every-time"
          ? "Safe asks every time a key is used."
          : "Safe never asks. Any app can use your keys while Safe is open."}
    </div>
  </div>
{/snippet}

{#if ui.takeover}<SshTakeover />{/if}

{#if hostEdit}<SshHostEdit host={hostEdit.host ?? null} onclose={() => (hostEdit = null)} />{/if}

{#if ui.editing?.kind === "ssh-key"}
  <Sheet title={ui.editing.way === "file" ? "Add a key" : "New key"} icon="terminal" onclose={() => (ui.editing = null)}>
    <SshKeyNew way={ui.editing.way} inSheet />
  </Sheet>
{/if}

{#if removing}
  <Sheet title="Remove {removing.alias}?" icon="trash-2" onclose={() => (removing = null)}>
    <p class="body safe-secondary" style="margin:0">ssh forgets this name on all your computers. The key stays in Safe.</p>
    {#snippet foot()}
      <button class="ewe-btn ewe-btn--ghost" onclick={() => (removing = null)}>Keep it</button>
      <button class="ewe-btn ewe-btn--danger" data-autofocus onclick={remove}>Remove</button>
    {/snippet}
  </Sheet>
{/if}

{#if turningOff}
  <Sheet title="Turn off Safe's SSH agent?" icon="terminal" onclose={() => (turningOff = false)}>
    <p class="body safe-secondary" style="margin:0">ssh and git stop asking Safe, on all your computers. Your keys stay in Safe.</p>
    {#snippet foot()}
      <button class="ewe-btn ewe-btn--ghost" data-autofocus onclick={() => (turningOff = false)}>Keep it on</button>
      <button class="ewe-btn ewe-btn--danger" onclick={turnOff}>Turn off</button>
    {/snippet}
  </Sheet>
{/if}

{#if signAsk}
  <Sheet title="Your Git email" icon="signature" onclose={() => (signAsk = null)}>
    <form id="safe-sign-email" class="safe-form" onsubmit={signWithEmail}>
      <p class="body safe-secondary" style="margin:0">Git puts this email on your signed commits. Use the one GitHub or GitLab knows.</p>
      <label class="ewe-field">
        <span class="ewe-field__label"><span>Email</span></span>
        <span class="ewe-input" class:is-error={!!signAsk.error}><input type="email" bind:value={signAsk.email} autocomplete="email" spellcheck="false" placeholder="you@example.org" /></span>
        {#if signAsk.error}<span class="ewe-field__helper ewe-field__helper--error"><Icon name="circle-x" /><span>{signAsk.error}</span></span>{/if}
      </label>
    </form>
    {#snippet foot()}
      <button class="ewe-btn ewe-btn--ghost" onclick={() => (signAsk = null)}>Cancel</button>
      <button class="ewe-btn ewe-btn--primary" type="submit" form="safe-sign-email" disabled={signAsk.busy}>{signAsk.busy ? "Turning on…" : "Sign my commits"}</button>
    {/snippet}
  </Sheet>
{/if}
