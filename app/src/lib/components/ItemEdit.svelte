<script>
  // A new login or note, or an edit (the mockup's Edit screen): title,
  // username, password with the generator, websites, apps for Super+P,
  // tags, notes. Edits send only what changed (PROTOCOL.md `edit`: websites
  // are replaced, apps and tags are added and removed). A card: its number
  // in groups as typed with the brand found from it, the expiry as MM/YY,
  // the security code and the PIN; an address: its parts and a country.
  // Only the parts that changed go in the `card` or `address` object.
  import Icon from "./Icon.svelte";
  import Generator from "./Generator.svelte";
  import { api } from "../api.js";
  import { safe } from "../safe.svelte.js";
  import { ui } from "../ui.svelte.js";
  import { toasts } from "../toast.svelte.js";
  import { letter } from "../format.js";
  import { BRANDS, ENCRYPTED_NOTE, brandName, brandOf, check, countries, countryName, digits, expiryShort, expiryTyped, grouped } from "../cards.js";
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
  const isCard = kind === "card";
  const isAddress = kind === "address";
  const was = start.item;
  const NAMES = { login: "login", note: "note", "ssh-key": "SSH key", card: "card", address: "address" };

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

  // a card (the secrets only once the editor asks for them)
  let number = $state("");
  let code = $state("");
  let pin = $state("");
  let holder = $state(was?.card?.holder ?? "");
  let expiry = $state(expiryShort(was?.card?.expiry ?? ""));
  // "" = from the number
  let brand = $state("");
  let showNumber = $state(isNew);
  let showCode = $state(isNew);
  let showPin = $state(false);
  let originalCard = { number: "", security_code: "", pin: "", brand: "" };
  const typedDigits = $derived(digits(number));
  const brandNow = $derived(brand || (typedDigits ? brandOf(typedDigits) : ""));
  const numberWarning = $derived(typedDigits.length >= 12 ? check(typedDigits) : "");
  const cardTitle = $derived(
    typedDigits.length >= 10 ? `${brandName(brandNow)} •• ${typedDigits.slice(-4)}` : brandName(brandNow)
  );

  // an address
  const PARTS = ["full_name", "organization", "line1", "line2", "city", "region", "postal_code", "country", "phone", "email"];
  const blank = () => Object.fromEntries(PARTS.map((k) => [k, ""]));
  let addr = $state({ ...blank(), ...(was?.address ? { full_name: was.address.name, line1: was.address.line1, city: was.address.city, country: was.address.country } : {}) });
  let originalAddr = blank();
  const COUNTRIES = countries();

  // an edit starts from what is there (the password only on this click)
  $effect(() => {
    if (isNew || !was) return;
    (async () => {
      const r = await api.show(was.id, !isLogin);
      if (r?.ok) {
        notes = r.item?.notes ?? "";
        original.notes = notes;
        if (isAddress && r.item?.address) {
          addr = Object.fromEntries(PARTS.map((k) => [k, r.item.address[k] ?? ""]));
          originalAddr = { ...addr };
        }
      }
      if (isCard) {
        const c = was.card ?? {};
        const [n, sc, p] = await Promise.all([
          c.has_number ? safe.reveal(was.id, "number") : "",
          c.has_security_code ? safe.reveal(was.id, "security_code") : "",
          c.has_pin ? safe.reveal(was.id, "pin") : ""
        ]);
        number = grouped(n ?? "");
        code = sc ?? "";
        pin = p ?? "";
        // a brand that isn't the number's own was chosen: keep it chosen
        brand = c.brand && c.brand !== brandOf(digits(n ?? "")) ? c.brand : "";
        originalCard = { number: digits(n ?? ""), security_code: code, pin, brand };
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
    if (!title.trim() && !isCard && !isAddress) {
      error = "A title is needed.";
      return;
    }
    if (isCard && expiry && !/^\d{2}\/\d{2}$/.test(expiry)) {
      error = "The expiry is a month and a year: MM/YY.";
      return;
    }
    saving = true;
    error = "";
    let r;
    if (isNew) {
      const it = { kind, tag: tags };
      if (title.trim()) it.title = title.trim();
      if (isCard) {
        const c = { holder: holder.trim(), number: typedDigits, expiry, security_code: code.trim(), pin: pin.trim(), brand };
        it.card = Object.fromEntries(Object.entries(c).filter(([, v]) => v));
      }
      if (isAddress) it.address = Object.fromEntries(Object.entries(addr).filter(([, v]) => v.trim()));
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
      if (title.trim() && title.trim() !== was.title) it.title = title.trim();
      if (isCard) {
        const c = {};
        if (holder.trim() !== (was.card?.holder ?? "")) c.holder = holder.trim();
        if (typedDigits !== originalCard.number) c.number = typedDigits;
        if (expiry !== expiryShort(was.card?.expiry ?? "")) c.expiry = expiry;
        if (code.trim() !== originalCard.security_code) c.security_code = code.trim();
        if (pin.trim() !== originalCard.pin) c.pin = pin.trim();
        if (brand !== originalCard.brand) c.brand = brand;
        if (Object.keys(c).length) it.card = c;
      }
      if (isAddress) {
        const a = Object.fromEntries(PARTS.filter((k) => addr[k].trim() !== originalAddr[k]).map((k) => [k, addr[k].trim()]));
        if (Object.keys(a).length) it.address = a;
      }
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
    code = "";
    pin = "";
    if (!r?.ok) {
      error = r?.message ?? "Couldn't save.";
      return;
    }
    const named = title.trim() || (isCard ? cardTitle : isAddress ? "Home" : "");
    if (r.warning) toasts.show(r.warning, { icon: "triangle-alert", ms: 6000 });
    else toasts.show(isNew ? `Added “${named}”.` : "Saved.", { icon: "circle-check" });
    number = "";
    // add answers `item_id`; `id` is the socket's own request id
    if (isNew && r.item_id) ui.selected = r.item_id;
    ui.editing = null;
  }

  function cancel() {
    password = "";
    number = "";
    code = "";
    pin = "";
    ui.editing = null;
  }
</script>

<form class="safe-stack" style="gap:var(--space-md)" onsubmit={save}>
  <div class="safe-dhead">
    {#if isLogin}
      <span class="safe-letter safe-letter--lg">{title ? letter(title) : "?"}</span>
    {:else}
      <span class="safe-letter safe-letter--lg"><Icon name={kind === "ssh-key" ? "terminal" : isCard ? "credit-card" : isAddress ? "map-pin" : "sticky-note"} /></span>
    {/if}
    <div class="safe-dhead__titles">
      <div class="h3">{isNew ? `New ${NAMES[kind] ?? "item"}` : `Edit ${NAMES[kind] ?? "item"}`}</div>
      <div class="caption">Changes are saved and synced when you press Save.</div>
    </div>
  </div>

  <div class="safe-form">
    <label class="ewe-field">
      <span class="ewe-field__label"><span>Title</span></span>
      <span class="ewe-input"><input bind:value={title} autocomplete="off" spellcheck="false" placeholder={isLogin ? "GitHub" : isCard ? cardTitle : isAddress ? "Home" : "Home Wi-Fi"} /></span>
    </label>

    {#if isCard}
      <div class="ewe-field">
        <label class="ewe-field__label" for="safe-card-number"><span>Card number</span>{#if brandNow}<span class="ewe-badge ewe-badge--accent"><span class="ewe-badge__label">{brandName(brandNow)}</span></span>{/if}</label>
        <span class="ewe-input">
          <Icon name="credit-card" />
          <input
            id="safe-card-number"
            class="mono"
            type={showNumber ? "text" : "password"}
            inputmode="numeric"
            value={number}
            oninput={(e) => (number = grouped(e.currentTarget.value, brand))}
            autocomplete="off"
            spellcheck="false"
            placeholder="1234 5678 9012 3456"
          />
          <button type="button" class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm" aria-label={showNumber ? "Hide the number" : "Show the number"} onclick={() => (showNumber = !showNumber)}
            ><Icon name={showNumber ? "eye-off" : "eye"} /></button
          >
        </span>
        {#if numberWarning}
          <div class="ewe-field__helper safe-warn"><Icon name="triangle-alert" /><span>{numberWarning} Safe saves it anyway.</span></div>
        {/if}
      </div>
      <div class="safe-pair">
        <label class="ewe-field">
          <span class="ewe-field__label"><span>Expiry date</span></span>
          <span class="ewe-input"
            ><input class="mono" inputmode="numeric" value={expiry} oninput={(e) => (expiry = expiryTyped(e.currentTarget.value))} autocomplete="off" placeholder="MM/YY" /></span
          >
        </label>
        <label class="ewe-field">
          <span class="ewe-field__label"><span>Security code</span></span>
          <span class="ewe-input">
            <input class="mono" type={showCode ? "text" : "password"} inputmode="numeric" bind:value={code} autocomplete="off" spellcheck="false" placeholder="CVC" />
            <button type="button" class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm" aria-label={showCode ? "Hide the code" : "Show the code"} onclick={() => (showCode = !showCode)}
              ><Icon name={showCode ? "eye-off" : "eye"} /></button
            >
          </span>
        </label>
      </div>
      <div class="safe-pair">
        <label class="ewe-field">
          <span class="ewe-field__label"><span>Name on card</span></span>
          <span class="ewe-input"><input bind:value={holder} autocomplete="off" spellcheck="false" /></span>
        </label>
        <label class="ewe-field">
          <span class="ewe-field__label"><span>PIN</span><span class="ewe-field__optional">Optional</span></span>
          <span class="ewe-input">
            <input class="mono" type={showPin ? "text" : "password"} inputmode="numeric" bind:value={pin} autocomplete="off" spellcheck="false" />
            <button type="button" class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm" aria-label={showPin ? "Hide the PIN" : "Show the PIN"} onclick={() => (showPin = !showPin)}
              ><Icon name={showPin ? "eye-off" : "eye"} /></button
            >
          </span>
        </label>
      </div>
      <label class="ewe-field">
        <span class="ewe-field__label"><span>Brand</span></span>
        <select class="ewe-input ewe-select" bind:value={brand}>
          <option value="">From the number{typedDigits ? ` (${brandName(brandOf(typedDigits))})` : ""}</option>
          {#each BRANDS as [id, name] (id)}<option value={id}>{name}</option>{/each}
        </select>
      </label>
    {/if}

    {#if isAddress}
      <label class="ewe-field">
        <span class="ewe-field__label"><span>Full name</span></span>
        <span class="ewe-input"><input bind:value={addr.full_name} autocomplete="off" spellcheck="false" /></span>
      </label>
      <label class="ewe-field">
        <span class="ewe-field__label"><span>Organization</span><span class="ewe-field__optional">Optional</span></span>
        <span class="ewe-input"><input bind:value={addr.organization} autocomplete="off" spellcheck="false" /></span>
      </label>
      <label class="ewe-field">
        <span class="ewe-field__label"><span>Address line 1</span></span>
        <span class="ewe-input"><input bind:value={addr.line1} autocomplete="off" spellcheck="false" placeholder="Street and number" /></span>
      </label>
      <label class="ewe-field">
        <span class="ewe-field__label"><span>Address line 2</span><span class="ewe-field__optional">Optional</span></span>
        <span class="ewe-input"><input bind:value={addr.line2} autocomplete="off" spellcheck="false" placeholder="Flat, floor, building" /></span>
      </label>
      <div class="safe-pair">
        <label class="ewe-field">
          <span class="ewe-field__label"><span>City</span></span>
          <span class="ewe-input"><input bind:value={addr.city} autocomplete="off" spellcheck="false" /></span>
        </label>
        <label class="ewe-field">
          <span class="ewe-field__label"><span>Postal code</span></span>
          <span class="ewe-input"><input class="mono" bind:value={addr.postal_code} autocomplete="off" spellcheck="false" /></span>
        </label>
      </div>
      <div class="safe-pair">
        <label class="ewe-field">
          <span class="ewe-field__label"><span>Region</span><span class="ewe-field__optional">Optional</span></span>
          <span class="ewe-input"><input bind:value={addr.region} autocomplete="off" spellcheck="false" placeholder="State, province" /></span>
        </label>
        <label class="ewe-field">
          <span class="ewe-field__label"><span>Country</span></span>
          <select class="ewe-input ewe-select" bind:value={addr.country}>
            <option value="">—</option>
            {#if addr.country && !COUNTRIES.some((c) => c.code === addr.country)}<option value={addr.country}>{countryName(addr.country)}</option>{/if}
            {#each COUNTRIES as c (c.code)}<option value={c.code}>{c.name}</option>{/each}
          </select>
        </label>
      </div>
      <div class="safe-pair">
        <label class="ewe-field">
          <span class="ewe-field__label"><span>Phone</span></span>
          <span class="ewe-input"><input type="tel" bind:value={addr.phone} autocomplete="off" spellcheck="false" /></span>
        </label>
        <label class="ewe-field">
          <span class="ewe-field__label"><span>Email</span></span>
          <span class="ewe-input"><input type="email" bind:value={addr.email} autocomplete="off" spellcheck="false" /></span>
        </label>
      </div>
    {/if}

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
      <span class="ewe-field__label"><span>{kind === "note" ? "Note" : "Notes"}</span>{#if kind !== "note" && kind !== "ssh-key"}<span class="ewe-field__optional">Optional</span>{/if}</span>
      <span class="ewe-input ewe-input--multiline"><textarea bind:value={notes} rows="4" spellcheck="false"></textarea></span>
    </label>

    {#if error}
      <div class="ewe-field__helper ewe-field__helper--error"><Icon name="circle-x" /><span>{error}</span></div>
    {/if}
    {#if isCard || isAddress}
      <div class="caption safe-note"><Icon name="shield-check" /><span>{ENCRYPTED_NOTE}</span></div>
    {/if}
  </div>

  <div class="safe-actions safe-actions--end">
    <button type="button" class="ewe-btn ewe-btn--ghost" onclick={cancel}>Cancel</button>
    <button type="submit" class="ewe-btn ewe-btn--primary" disabled={saving}>{saving ? "Saving…" : "Save"}</button>
  </div>
</form>
