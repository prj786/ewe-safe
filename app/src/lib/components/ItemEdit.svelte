<script>
  // A new login or note, or an edit (the mockup's Edit screen): title,
  // username, password with the generator, websites, apps for Super+P,
  // tags, notes. Edits send only what changed (PROTOCOL.md `edit`: websites
  // are replaced, apps and tags are added and removed).
  import Icon from "./Icon.svelte";
  import Generator from "./Generator.svelte";
  import { api } from "../api.js";
  import { safe } from "../safe.svelte.js";
  import { ui } from "../ui.svelte.js";
  import { toasts } from "../toast.svelte.js";
  import { letter } from "../format.js";
  import { untrack } from "svelte";

  let { editing, item = null } = $props();

  // the form starts from the item as it is now (Main re-keys this component
  // for every new edit, so later changes to `item` are not ours to follow)
  const start = untrack(() => ({
    isNew: editing.mode === "new",
    kind: item?.kind ?? editing.kind ?? "login",
    item: item ? $state.snapshot(item) : null
  }));
  const isNew = start.isNew;
  const kind = start.kind;
  const isLogin = kind === "login";
  const was = start.item;

  let title = $state(was?.title ?? "");
  let username = $state(was?.username ?? "");
  let password = $state("");
  let showPw = $state(isNew);
  let urls = $state([...(was?.urls ?? [])]);
  let apps = $state([...(was?.apps ?? [])]);
  let tags = $state([...(was?.tags ?? [])]);
  let notes = $state("");
  let urlText = $state("");
  let tagText = $state("");
  let gen = $state((isNew && isLogin) || ui.genOpen);
  ui.genOpen = false;
  let picker = $state(null); // the open windows, while picking
  let saving = $state(false);
  let error = $state("");
  let original = { password: "", notes: "" };

  // an edit starts from what is there (the password only on this click)
  $effect(() => {
    if (isNew || !was) return;
    (async () => {
      const r = await api.show(was.id, !isLogin);
      if (r?.ok) {
        notes = r.item?.notes ?? "";
        original.notes = notes;
      }
      if (isLogin && was.has_password) {
        const v = await safe.reveal(was.id, "password");
        if (v != null) {
          password = v;
          original.password = v;
        }
      }
    })();
  });

  function addUrl() {
    const u = urlText.trim();
    if (u && !urls.includes(u)) urls = [...urls, u];
    urlText = "";
  }
  function addTag() {
    const t = tagText.trim();
    if (t && !tags.some((x) => x.toLowerCase() === t.toLowerCase())) tags = [...tags, t];
    tagText = "";
  }
  async function openPicker() {
    const r = await api.windowClasses();
    picker = (r?.classes ?? []).filter((c) => !apps.includes(c));
  }
  function addApp(c) {
    if (!apps.includes(c)) apps = [...apps, c];
    picker = null;
  }

  async function save(e) {
    e?.preventDefault();
    if (urlText.trim()) addUrl();
    if (tagText.trim()) addTag();
    if (!title.trim()) {
      error = "A title is needed.";
      return;
    }
    saving = true;
    error = "";
    let r;
    if (isNew) {
      const it = { kind, title: title.trim(), tag: tags };
      if (isLogin) {
        it.username = username;
        it.url = urls;
        it.app = apps;
        if (password) it.password_value = password;
      }
      if (notes) it.notes = notes;
      r = await safe.add(it);
    } else {
      const it = {};
      if (title.trim() !== was.title) it.title = title.trim();
      const before = new Set(was.tags ?? []);
      const addT = tags.filter((t) => !before.has(t));
      const remT = [...before].filter((t) => !tags.includes(t));
      if (addT.length) it.tag = addT;
      if (remT.length) it.remove_tag = remT;
      if (isLogin) {
        if (username !== (was.username ?? "")) it.username = username;
        if (password && password !== original.password) it.password_value = password;
        const sameUrls = urls.length === (was.urls ?? []).length && urls.every((u, i) => u === was.urls[i]);
        if (!sameUrls) {
          it.clear_url = true;
          it.url = urls;
        }
        const hadApps = new Set(was.apps ?? []);
        const addA = apps.filter((a) => !hadApps.has(a));
        const remA = [...hadApps].filter((a) => !apps.includes(a));
        if (addA.length) it.app = addA;
        if (remA.length) it.remove_app = remA;
      }
      if (notes !== original.notes) it.notes = notes;
      r = Object.keys(it).length ? await safe.edit(was.id, it) : { ok: true };
    }
    saving = false;
    password = "";
    if (!r?.ok) {
      error = r?.message ?? "Couldn't save.";
      return;
    }
    toasts.show(isNew ? `Added “${title.trim()}”.` : "Saved.", { icon: "circle-check" });
    // add answers `item_id`; `id` is the socket's own request id
    if (isNew && r.item_id) ui.selected = r.item_id;
    ui.editing = null;
  }

  function cancel() {
    password = "";
    ui.editing = null;
  }
</script>

<form class="safe-stack" style="gap:var(--space-md)" onsubmit={save}>
  <div class="safe-dhead">
    {#if isLogin}
      <span class="safe-letter safe-letter--lg">{title ? letter(title) : "?"}</span>
    {:else}
      <span class="safe-letter safe-letter--lg"><Icon name={kind === "ssh-key" ? "terminal" : "sticky-note"} /></span>
    {/if}
    <div class="safe-dhead__titles">
      <div class="h3">{isNew ? (isLogin ? "New login" : "New note") : isLogin ? "Edit login" : kind === "ssh-key" ? "Edit SSH key" : "Edit note"}</div>
      <div class="caption">Changes are saved and synced when you press Save.</div>
    </div>
  </div>

  <div class="safe-form">
    <label class="ewe-field">
      <span class="ewe-field__label"><span>Title</span></span>
      <span class="ewe-input"><input bind:value={title} autocomplete="off" spellcheck="false" placeholder={isLogin ? "GitHub" : "Home Wi-Fi"} /></span>
    </label>

    {#if isLogin}
      <label class="ewe-field">
        <span class="ewe-field__label"><span>Username</span></span>
        <span class="ewe-input"><input bind:value={username} autocomplete="off" spellcheck="false" /></span>
      </label>

      <div class="safe-pwrow">
        <label class="ewe-field">
          <span class="ewe-field__label"><span>Password</span></span>
          <span class="ewe-input">
            <input class="mono" type={showPw ? "text" : "password"} bind:value={password} autocomplete="new-password" spellcheck="false" />
            <button
              type="button"
              class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm"
              aria-label={showPw ? "Hide password" : "Show password"}
              onclick={() => (showPw = !showPw)}><Icon name={showPw ? "eye-off" : "eye"} /></button
            >
          </span>
        </label>
        <button type="button" class="ewe-btn ewe-btn--secondary" class:is-pressed={gen} onclick={() => (gen = !gen)}>
          <Icon name="dices" />Generate
        </button>
        {#if gen}
          <Generator
            onuse={(v) => {
              password = v;
              showPw = true;
              gen = false;
            }}
            onclose={() => (gen = false)}
          />
        {/if}
      </div>

      <div class="ewe-field">
        <div class="ewe-field__label"><span>Websites</span></div>
        <div class="ewe-input ewe-input--chips">
          {#each urls as u (u)}
            <span class="ewe-tag ewe-tag--removable">{u.replace(/^https?:\/\//, "")}<button
                type="button"
                class="ewe-link"
                aria-label="Remove {u}"
                onclick={() => (urls = urls.filter((x) => x !== u))}><Icon name="x" /></button
              ></span>
          {/each}
          <input
            class="ewe-input__text"
            bind:value={urlText}
            placeholder="Add a website"
            spellcheck="false"
            onkeydown={(e) => e.key === "Enter" && (e.preventDefault(), addUrl())}
            onblur={addUrl}
          />
        </div>
      </div>

      <div class="ewe-field safe-rel">
        <div class="ewe-field__label"><span>Apps</span><span class="ewe-field__optional">Super+P fills this login here</span></div>
        <div class="ewe-input ewe-input--chips">
          {#each apps as a (a)}
            <span class="ewe-tag ewe-tag--removable"><Icon name="app-window" />{a}<button
                type="button"
                class="ewe-link"
                aria-label="Remove {a}"
                onclick={() => (apps = apps.filter((x) => x !== a))}><Icon name="x" /></button
              ></span>
          {/each}
          <button type="button" class="ewe-link ewe-input__placeholder" onclick={openPicker}>Pick a window…</button>
        </div>
        {#if picker}
          <div class="ewe-menu safe-pick" role="menu">
            {#each picker as c (c)}
              <button type="button" class="ewe-menu__item" role="menuitem" onclick={() => addApp(c)}><Icon name="app-window" />{c}</button>
            {:else}
              <div class="ewe-menu__item" role="none">No other windows are open.</div>
            {/each}
          </div>
        {/if}
      </div>
    {/if}

    <div class="ewe-field">
      <div class="ewe-field__label"><span>Tags</span><span class="ewe-field__optional">Optional</span></div>
      <div class="ewe-input ewe-input--chips">
        {#each tags as t (t)}
          <span class="ewe-tag ewe-tag--removable">{t}<button
              type="button"
              class="ewe-link"
              aria-label="Remove {t}"
              onclick={() => (tags = tags.filter((x) => x !== t))}><Icon name="x" /></button
            ></span>
        {/each}
        <input
          class="ewe-input__text"
          bind:value={tagText}
          placeholder="Add a tag"
          spellcheck="false"
          onkeydown={(e) => e.key === "Enter" && (e.preventDefault(), addTag())}
          onblur={addTag}
        />
      </div>
    </div>

    <label class="ewe-field">
      <span class="ewe-field__label"><span>{isLogin || kind === "ssh-key" ? "Notes" : "Note"}</span>{#if isLogin}<span class="ewe-field__optional">Optional</span>{/if}</span>
      <span class="ewe-input ewe-input--multiline"><textarea bind:value={notes} rows="4" spellcheck="false"></textarea></span>
    </label>

    {#if error}
      <div class="ewe-field__helper ewe-field__helper--error"><Icon name="circle-x" /><span>{error}</span></div>
    {/if}
  </div>

  <div class="safe-actions safe-actions--end">
    <button type="button" class="ewe-btn ewe-btn--ghost" onclick={cancel}>Cancel</button>
    <button type="submit" class="ewe-btn ewe-btn--primary" disabled={saving}>{saving ? "Saving…" : "Save"}</button>
  </div>
</form>
