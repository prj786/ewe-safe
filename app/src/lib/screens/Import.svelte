<script>
  // Import (PROTOCOL.md `import`): from 1Password — its export file, its CSV,
  // or straight from the app through `op`. Check first (a dry run with the
  // report: counts, duplicates, what is skipped and why), then import in one
  // save. The export file holds every password in plain text, so the end
  // says to delete it.
  import Icon from "../components/Icon.svelte";
  import { api } from "../api.js";
  import { safe } from "../safe.svelte.js";
  import { ui } from "../ui.svelte.js";
  import { tick } from "svelte";

  const SOURCES = [
    {
      format: "1pux",
      icon: "file-down",
      title: "1Password export file (.1pux)",
      desc: "In 1Password: File → Export → your account, as 1PUX. Keeps one-time codes and attachments."
    },
    {
      format: "op",
      icon: "app-window",
      title: "Straight from the 1Password app",
      desc: "Reads your vaults through the 1Password CLI. In 1Password, turn on Settings → Developer → Integrate with 1Password CLI."
    },
    {
      format: "1password-csv",
      icon: "list",
      title: "1Password CSV",
      desc: "A plainer export: logins and notes, without attachments."
    }
  ];

  let format = $state("1pux");
  let file = $state("");
  let vault = $state("");
  let folder = $state("");
  let skipDuplicates = $state(false);
  let report = $state(null); // the dry run's
  let done = $state(null); // the import's reply
  let error = $state("");
  let importBtn = $state();

  const needsFile = $derived(format !== "op");
  const ready = $derived(!needsFile || !!file);
  const total = (r) => Number(r?.logins ?? 0) + Number(r?.notes ?? 0);

  function reset() {
    report = null;
    done = null;
    error = "";
  }

  async function choose() {
    const r = await api.pickFile(format === "1pux" ? "1pux" : "csv");
    if (r?.ok && r.path) {
      file = r.path;
      reset();
    }
  }

  function explain(r) {
    if (r?.error === "bad-request" && /no verb/i.test(r?.message ?? ""))
      return "This version of Safe's service can't import yet. Update Safe and try again.";
    // source-error: not a 1PUX/CSV export, unreadable, or op's own words
    if (r?.error === "source-error")
      return format === "op" ? `The 1Password app didn't answer: ${r.message}` : `Safe can't read that file: ${r.message}`;
    return r?.message ?? "The import didn't work.";
  }

  async function run(dryRun) {
    error = "";
    const r = await safe.importItems({
      format,
      file: needsFile ? file : undefined,
      dryRun,
      folder: folder.trim() || undefined,
      skipDuplicates,
      vault: format === "op" && vault.trim() ? vault.trim() : undefined
    });
    if (!r?.ok) {
      error = explain(r);
      return;
    }
    if (dryRun) {
      report = r.report ?? {};
      // keyboard first: the "Check first" button is gone, Enter imports
      await tick();
      importBtn?.focus();
    } else done = r;
  }
</script>

<div class="ewe-headerbar ewe-headerbar--page" style="padding:var(--space-md) calc(var(--space-md) + var(--space-s)) calc(var(--space-s) + var(--space-xs))">
  <div class="ewe-headerbar__titles">
    <div class="ewe-headerbar__title">Import</div>
    <div class="ewe-headerbar__subtitle">Bring your passwords from 1Password. Bitwarden, browsers, KeePass and pass come later.</div>
  </div>
  <div class="ewe-headerbar__actions">
    <button class="ewe-btn ewe-btn--ghost ewe-btn--sm" onclick={() => ui.go("settings")}><Icon name="chevron-left" />Settings</button>
  </div>
</div>

<div class="safe-page">
  <div class="safe-page__body">
    {#if done}
      <div class="ewe-alert ewe-alert--success" role="status">
        <Icon name="circle-check" />
        <div class="ewe-alert__body">
          <div class="ewe-alert__title">Imported {total(done.report)} items</div>
          <div class="ewe-alert__desc">
            {done.report?.logins ?? 0} logins and {done.report?.notes ?? 0} notes are in your safe{done.report?.folders?.length ? `, in ${done.report.folders.join(", ")}` : ""}.
          </div>
        </div>
      </div>
      {#if needsFile}
        <div class="ewe-alert ewe-alert--warning" role="status">
          <Icon name="triangle-alert" />
          <div class="ewe-alert__body">
            <div class="ewe-alert__title">Delete the export file now</div>
            <div class="ewe-alert__desc">{done.hint ?? "Anyone who gets it can read every password."} <span class="mono">{file}</span></div>
          </div>
        </div>
      {/if}
      <div class="safe-actions">
        <button class="ewe-btn ewe-btn--primary" onclick={() => ui.pick({})}>Show my items</button>
        <button class="ewe-btn ewe-btn--ghost" onclick={() => ((file = ""), reset())}>Import more</button>
      </div>
    {:else}
      <div class="ewe-section"><div class="ewe-section__text"><div class="ewe-section__title ewe-section__title--overline">From</div></div></div>
      <div class="safe-stack" role="radiogroup" aria-label="Import from">
        {#each SOURCES as s (s.format)}
          <button
            class="ewe-choice"
            class:is-selected={format === s.format}
            role="radio"
            aria-checked={format === s.format}
            onclick={() => {
              format = s.format;
              file = "";
              reset();
            }}
          >
            <span class="ewe-check ewe-check--radio" class:is-checked={format === s.format}
              ><span class="ewe-check__box">{#if format === s.format}<span class="ewe-check__dot"></span>{/if}</span></span
            >
            <span class="ewe-choice__icon"><Icon name={s.icon} /></span>
            <span class="ewe-choice__text"><span class="ewe-choice__title">{s.title}</span><span class="ewe-choice__desc">{s.desc}</span></span>
          </button>
        {/each}
      </div>

      {#if needsFile}
        <div class="ewe-list">
          <div class="ewe-row">
            <span class="ewe-row__lead ewe-row__lead--tile"><Icon name="file-down" /></span>
            <span class="ewe-row__text">
              <span class="ewe-row__title">{file ? file.split("/").pop() : "No file chosen"}</span>
              <span class="ewe-row__desc">{file || (format === "1pux" ? "A .1pux file from 1Password" : "A .csv file from 1Password")}</span>
            </span>
            <span class="ewe-row__trail"><button class="ewe-btn ewe-btn--secondary ewe-btn--sm" onclick={choose}><Icon name="folder-open" />Choose file…</button></span>
          </div>
        </div>
      {:else}
        <label class="ewe-field">
          <span class="ewe-field__label"><span>Vault</span><span class="ewe-field__optional">Empty = every vault</span></span>
          <span class="ewe-input"><input bind:value={vault} placeholder="Personal" spellcheck="false" oninput={reset} /></span>
        </label>
      {/if}

      <div class="caption safe-muted">
        1Password's export leaves passkeys out. Sign in to each site once with the password, then add a Safe passkey there.
      </div>

      <label class="ewe-field">
        <span class="ewe-field__label"><span>Put them in a folder</span><span class="ewe-field__optional">Optional</span></span>
        <span class="ewe-input"><input bind:value={folder} placeholder="From 1Password" spellcheck="false" oninput={reset} /></span>
      </label>
      <label class="ewe-check" class:is-checked={skipDuplicates}>
        <input type="checkbox" hidden bind:checked={skipDuplicates} onchange={reset} />
        <span class="ewe-check__box">{#if skipDuplicates}<Icon name="check" />{/if}</span>
        <span class="ewe-check__text">
          <span class="ewe-check__label">Skip logins Safe already has</span>
          <span class="ewe-check__desc">Same website and username as an item in your safe.</span>
        </span>
      </label>

      {#if error}
        <div class="ewe-alert ewe-alert--danger" role="alert">
          <Icon name="circle-x" />
          <div class="ewe-alert__body"><div class="ewe-alert__title">{error}</div></div>
        </div>
      {/if}

      {#if report}
        <div class="ewe-section"><div class="ewe-section__text"><div class="ewe-section__title ewe-section__title--overline">What will come in</div></div></div>
        <div class="safe-report">
          {@render stat(report.logins, "Logins")}
          {@render stat(report.notes, "Notes")}
          {@render stat(report.otps, "One-time codes")}
          {@render stat(report.attachments, "Attachments")}
          {@render stat(report.duplicates, skipDuplicates ? "Duplicates, skipped" : "Duplicates, kept")}
          {@render stat(report.skipped?.length ?? 0, "Skipped")}
        </div>
        {#if report.skipped?.length}
          <div class="ewe-list">
            {#each report.skipped.slice(0, 20) as s, n (n)}
              <div class="ewe-row">
                <span class="ewe-row__text"><span class="ewe-row__title">{s.title}</span><span class="ewe-row__desc">{s.reason}</span></span>
              </div>
            {/each}
          </div>
        {/if}
      {/if}

      <div class="safe-actions safe-actions--end">
        {#if report}
          <button class="ewe-btn ewe-btn--ghost" onclick={() => (report = null)}>Back</button>
          <button bind:this={importBtn} class="ewe-btn ewe-btn--primary" disabled={!ready || safe.busy === "import" || total(report) === 0} onclick={() => run(false)}>
            {safe.busy === "import" ? "Importing…" : `Import ${total(report)} items`}
          </button>
        {:else}
          <button class="ewe-btn ewe-btn--primary" disabled={!ready || safe.busy === "import-check"} onclick={() => run(true)}>
            {safe.busy === "import-check" ? "Checking…" : "Check first"}
          </button>
        {/if}
      </div>
      {#if format === "op" && safe.busy.startsWith("import")}
        <div class="caption safe-muted">If 1Password asks, approve Safe there. Reading many items takes a while.</div>
      {/if}
    {/if}
  </div>
</div>

{#snippet stat(n, label)}
  <div class="safe-stat"><span class="mono-numeric">{n ?? 0}</span><span class="caption">{label}</span></div>
{/snippet}
