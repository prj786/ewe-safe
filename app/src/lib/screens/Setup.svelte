<script>
  // A machine with no safe yet (the mockup's Welcome, Place, Master password
  // and Emergency Kit screens): create a safe in a place, or open one — the
  // safe ewe.conf already names (a machine restored from the ewe account) or
  // any .kdbx file. Places this version can't use yet say so instead of
  // failing later.
  import Icon from "../components/Icon.svelte";
  import Kit from "../components/Kit.svelte";
  import { api } from "../api.js";
  import { safe } from "../safe.svelte.js";
  import { ui } from "../ui.svelte.js";
  import { PLACES, placeLabel, strength } from "../format.js";

  let step = $state(ui.setupStep ?? "welcome"); // welcome | place | password | open | kit
  let choice = $state("nextcloud");
  let more = $state(false);
  let cloud = $state(null);
  let openPlace = $state(null); // {place, location} for "open"
  let pw = $state("");
  let pw2 = $state("");
  let show = $state(false);
  let error = $state("");
  let wrong = $state(false);

  $effect(() => {
    safe.loadSettings();
    api.cloudStatus().then((c) => {
      cloud = c;
      if (!c?.signed_in) choice = "local";
    });
  });

  const known = $derived(safe.settings.place ? { place: safe.settings.place, location: safe.settings.location } : null);
  const signedIn = $derived(!!cloud?.signed_in);
  const host = $derived((cloud?.server ?? "").replace(/^https?:\/\//, ""));
  const meter = $derived(strength(pw));
  const same = $derived(pw && pw === pw2);

  function stepsOf(at) {
    const order = ["place", "password", "kit"];
    const names = { place: "Place", password: "Master password", kit: "Emergency Kit" };
    const i = order.indexOf(at);
    return order.map((s, n) => ({ n: n + 1, name: names[s], done: n < i, current: n === i }));
  }

  async function openFile() {
    const r = await api.pickFile("kdbx");
    if (r?.ok && r.path) {
      openPlace = { place: "local", location: r.path };
      step = "open";
    }
  }

  function openKnown() {
    openPlace = { ...known };
    step = "open";
  }

  async function suggest() {
    const r = await safe.generate({ words: Number(safe.settings.generator_words ?? 5) });
    if (r?.ok) {
      pw = r.value;
      pw2 = r.value;
      show = true;
    }
  }

  async function create(e) {
    e.preventDefault();
    if (!same) {
      error = "The two passwords are not the same.";
      return;
    }
    error = "";
    ui.setup = true;
    const p = pw;
    pw = "";
    pw2 = "";
    const r = await safe.create({ place: choice }, p);
    if (!r?.ok) {
      ui.setup = false;
      error = r?.message ?? "Couldn't create the safe.";
      return;
    }
    step = "kit";
  }

  async function open(e) {
    e.preventDefault();
    error = "";
    wrong = false;
    const p = pw;
    pw = "";
    const r = await safe.openSafe(openPlace, p);
    if (!r?.ok) {
      if (r?.error === "wrong-key") wrong = true;
      else error = r?.message ?? "Couldn't open the safe.";
    }
  }
</script>

{#snippet steps(at)}
  <div class="ewe-steps">
    {#each stepsOf(at) as s, i (s.n)}
      {#if i > 0}<span class="ewe-steps__line" class:is-done={s.done || s.current}></span>{/if}
      <span class="ewe-step" class:is-done={s.done} class:is-current={s.current}>
        <span class="ewe-step__dot">{#if s.done}<Icon name="check" />{:else}{s.n}{/if}</span><span>{s.name}</span>
      </span>
    {/each}
  </div>
{/snippet}

{#snippet pwField(value, set, label, ok)}
  <label class="ewe-field">
    <span class="ewe-field__label"><span>{label}</span></span>
    <span class="ewe-input ewe-input--lg" class:is-error={wrong}>
      <input
        class="mono"
        type={show ? "text" : "password"}
        {value}
        oninput={(e) => set(e.currentTarget.value)}
        autocomplete={step === "open" ? "current-password" : "new-password"}
        spellcheck="false"
      />
      {#if ok}<Icon name="check" />{/if}
      <button type="button" class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm" aria-label={show ? "Hide password" : "Show password"} onclick={() => (show = !show)}>
        <Icon name={show ? "eye-off" : "eye"} />
      </button>
    </span>
  </label>
{/snippet}

<div class="safe-win">
  <div class="safe-solo">
    {#if step === "welcome"}
      <div class="safe-col safe-col--center">
        <span class="ewe-appicon safe-tile safe-tile--lg"><Icon name="vault" /></span>
        <div class="safe-head">
          <div class="h1">Safe</div>
          <div class="body-lg">Your passwords in one file that only you can open.</div>
        </div>
        {#if known?.place === "local"}
          <div class="ewe-alert ewe-alert--info" role="status">
            <Icon name="info" />
            <div class="ewe-alert__body">
              <div class="ewe-alert__title">Your other computer keeps its safe on that computer only</div>
              <div class="ewe-alert__desc">Move it to your ewe account there to use it here, or make a new safe.</div>
            </div>
          </div>
        {/if}
        {#if known && known.place !== "local"}
          <div class="safe-stack">
            <div class="ewe-choice is-selected">
              <span class="ewe-choice__icon"><Icon name={PLACES[known.place]?.icon ?? "cloud"} /></span>
              <span class="ewe-choice__text">
                <span class="ewe-choice__title">Open your safe from {placeLabel({ kind: known.place })}</span>
                <span class="ewe-choice__desc">{[host, known.location].filter(Boolean).join(" · ")}</span>
              </span>
              <button class="ewe-btn ewe-btn--primary" onclick={openKnown}>Open</button>
            </div>
            <div class="safe-actions">
              <button class="ewe-btn ewe-btn--ghost" onclick={() => (step = "place")}><Icon name="plus" />Create a new safe</button>
              <button class="ewe-btn ewe-btn--ghost" onclick={openFile}><Icon name="folder" />Open a safe file…</button>
            </div>
          </div>
        {:else}
          <ul class="safe-points body">
            <li><Icon name="lock-keyhole" /><span>Encrypted on this computer, before it goes anywhere.</span></li>
            <li><Icon name="cloud" /><span>Keep it in your own Nextcloud, or only on this computer.</span></li>
            <li><Icon name="key-round" /><span>A standard KeePass file. KeePassXC and phone apps open it too.</span></li>
          </ul>
          <div class="safe-actions">
            <button class="ewe-btn ewe-btn--primary ewe-btn--lg" onclick={() => (step = "place")}><Icon name="plus" />Create a new safe</button>
            <button class="ewe-btn ewe-btn--secondary ewe-btn--lg" onclick={openFile}><Icon name="folder" />Open a safe file…</button>
          </div>
        {/if}
      </div>
    {:else if step === "place"}
      <div class="safe-col">
        {@render steps("place")}
        <div class="safe-head">
          <div class="h2">Where should Safe keep the file?</div>
          <div class="body">The file is encrypted on this computer first. Wherever it lives, only your master password opens it.</div>
        </div>
        <div class="safe-stack" role="radiogroup" aria-label="Place">
          {@render place("nextcloud", signedIn ? `Your Nextcloud, ${host}. Your other computers get it too.` : "Sign in to your Nextcloud in ewe-sync first.", !signedIn, signedIn ? "Recommended" : "")}
          {@render place("local", "No sync. Back up the file yourself.", false, "")}
          {@render place("webdav", "ownCloud, Seafile, Synology, Apache or any WebDAV server.", true, "Coming soon")}
          {@render place("folder", "Syncthing, or a folder another app keeps in sync.", true, "Coming soon")}
          {@render place("sftp", "A file on your own server, reached with your SSH key.", true, "Coming soon")}
          {#if !more}
            <button class="ewe-btn ewe-btn--ghost ewe-btn--sm safe-more" aria-expanded="false" onclick={() => (more = true)}>
              <Icon name="chevron-right" />More places: Dropbox, Google Drive
            </button>
          {:else}
            <div class="safe-more label"><Icon name="chevron-down" />More places</div>
            {@render place("dropbox", "Needs your own Dropbox app key. You add it in ewe-sync.", true, "Coming soon")}
            {@render place("gdrive", "Needs your own Google client file. You add it in ewe-sync.", true, "Coming soon")}
          {/if}
        </div>
        {#if !signedIn}
          <div class="safe-actions">
            <button class="ewe-btn ewe-btn--secondary ewe-btn--sm" onclick={() => api.openEweSync()}><Icon name="user" />Sign in with ewe-sync</button>
            <button class="ewe-btn ewe-btn--ghost ewe-btn--sm" onclick={() => api.cloudStatus().then((c) => (cloud = c))}><Icon name="refresh-cw" />Check again</button>
          </div>
        {/if}
        <div class="safe-actions safe-actions--split">
          <button class="ewe-btn ewe-btn--ghost" onclick={() => (step = "welcome")}>Back</button>
          <button class="ewe-btn ewe-btn--primary" onclick={() => (step = "password")}>Continue</button>
        </div>
      </div>
    {:else if step === "password"}
      <form class="safe-col" onsubmit={create}>
        {@render steps("password")}
        <div class="safe-head">
          <div class="h2">Choose a master password</div>
          <div class="body">It opens your safe on every computer and phone. Four or more random words work well.</div>
        </div>
        <div class="safe-form">
          {@render pwField(pw, (v) => (pw = v), "Master password", false)}
          {#if pw}
            <div class="ewe-meter ewe-meter--{meter.tone}">
              <div class="ewe-meter__head"><Icon name="shield-check" /><span>Strength</span><span class="ewe-meter__value">{meter.label}</span></div>
              <div class="ewe-meter__track"><div class="ewe-meter__fill" style="--value:{meter.pct}%"></div></div>
            </div>
          {/if}
          {@render pwField(pw2, (v) => (pw2 = v), "Type it again", same)}
          <button type="button" class="ewe-btn ewe-btn--ghost ewe-btn--sm" style="align-self:flex-start" onclick={suggest}><Icon name="dices" />Suggest a passphrase</button>
        </div>
        <div class="ewe-alert ewe-alert--warning" role="status">
          <Icon name="triangle-alert" />
          <div class="ewe-alert__body"><div class="ewe-alert__title">If you forget this password, nobody can open your safe. There is no reset.</div></div>
        </div>
        <div class="ewe-check is-disabled" aria-disabled="true">
          <span class="ewe-check__box"></span>
          <span class="ewe-check__text">
            <span class="ewe-check__label">Unlock with my login password on this computer</span>
            <span class="ewe-check__desc">Comes in a later version. Your master password always works.</span>
          </span>
        </div>
        {#if error}<div class="ewe-field__helper ewe-field__helper--error"><Icon name="circle-x" /><span>{error}</span></div>{/if}
        <div class="safe-actions safe-actions--split">
          <button type="button" class="ewe-btn ewe-btn--ghost" onclick={() => (step = "place")}>Back</button>
          <button class="ewe-btn ewe-btn--primary" disabled={!same || safe.busy === "init"}>{safe.busy === "init" ? "Creating…" : "Create safe"}</button>
        </div>
      </form>
    {:else if step === "open"}
      <form class="safe-col safe-col--narrow safe-col--center safe-center" onsubmit={open}>
        <span class="ewe-appicon safe-tile safe-tile--lg"><Icon name="lock" /></span>
        <div class="safe-head safe-center">
          <div class="h2">Open your safe</div>
          <div class="caption safe-muted">
            {openPlace?.place === "local" ? openPlace.location : [placeLabel({ kind: openPlace?.place }), openPlace?.location].filter(Boolean).join(" · ")}
          </div>
        </div>
        <div style="width:100%">{@render pwField(pw, (v) => ((pw = v), (wrong = false)), "Master password", false)}</div>
        {#if wrong}
          <div class="ewe-field__helper ewe-field__helper--error"><Icon name="circle-x" /><span>Wrong password. Check Caps Lock and try again.</span></div>
        {:else if error}
          <div class="ewe-field__helper ewe-field__helper--error"><Icon name="circle-x" /><span>{error}</span></div>
        {/if}
        <button class="ewe-btn ewe-btn--primary ewe-btn--lg ewe-btn--block" disabled={!pw || safe.busy === "open"}>{safe.busy === "open" ? "Opening…" : "Open safe"}</button>
        <button type="button" class="ewe-btn ewe-btn--ghost" onclick={() => ((step = "welcome"), (error = ""))}>Back</button>
      </form>
    {:else if step === "kit"}
      <div class="safe-col">
        {@render steps("kit")}
        <div class="safe-head">
          <div class="h2">Print your Emergency Kit</div>
          <div class="body">Write your master password on it and keep it somewhere safe, away from this computer.</div>
        </div>
        <Kit />
        <div class="safe-actions safe-actions--split">
          <button class="ewe-btn ewe-btn--secondary" onclick={() => api.print()}><Icon name="printer" />Print…</button>
          <button class="ewe-btn ewe-btn--primary" onclick={() => (ui.setup = false)}>I've kept it safe</button>
        </div>
      </div>
    {/if}
  </div>
</div>

{#snippet place(kind, desc, disabled, badge)}
  <button
    class="ewe-choice"
    class:is-selected={choice === kind && !disabled}
    class:is-disabled={disabled}
    role="radio"
    aria-checked={choice === kind}
    aria-disabled={disabled}
    onclick={() => !disabled && (choice = kind)}
  >
    <span class="ewe-check ewe-check--radio" class:is-checked={choice === kind && !disabled}
      ><span class="ewe-check__box">{#if choice === kind && !disabled}<span class="ewe-check__dot"></span>{/if}</span></span
    >
    <span class="ewe-choice__icon"><Icon name={PLACES[kind].icon} /></span>
    <span class="ewe-choice__text"><span class="ewe-choice__title">{PLACES[kind].label}</span><span class="ewe-choice__desc">{desc}</span></span>
    {#if badge}
      <span class="ewe-badge {badge === 'Recommended' ? 'ewe-badge--accent' : 'ewe-badge--neutral'}"><span class="ewe-badge__label">{badge}</span></span>
    {/if}
  </button>
{/snippet}
