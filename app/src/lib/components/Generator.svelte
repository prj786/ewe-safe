<script>
  // The password generator, a panel right under the password field (it
  // pushes the form down, never covers it): characters or words, a preview
  // from the daemon's `generate` (ewe Safe's own generator, never the
  // page's), the dice for another one, "Use password" to fill the field.
  // It sits inside the editor's form, so every button here is
  // type="button": choosing Words, the dice or Close never saves the item.
  import Icon from "./Icon.svelte";
  import { safe } from "../safe.svelte.js";
  import { keys } from "../trap.js";

  let { onuse = () => {}, onclose = () => {} } = $props();

  const LEN = { min: 8, max: 64 };
  const WORDS = { min: 3, max: 10 };
  let kind = $state("chars");
  let length = $state(Number(safe.settings.generator_length ?? 20));
  let words = $state(Number(safe.settings.generator_words ?? 5));
  let digits = $state(true);
  let symbols = $state(true);
  let value = $state("");
  let bits = $state(0);

  async function roll() {
    const r =
      kind === "chars"
        ? await safe.generate({ length, noDigits: !digits, noSymbols: !symbols })
        : await safe.generate({ words });
    if (r?.ok) {
      value = r.value;
      bits = Number(r.bits ?? 0);
    }
  }

  $effect(() => {
    // a new preview whenever a setting changes
    void [kind, length, words, digits, symbols];
    roll();
  });

  const pct = (v, r) => `${Math.round(((v - r.min) / (r.max - r.min)) * 100)}%`;
  const label = $derived(
    bits >= 100 ? "Very strong" : bits >= 80 ? "Strong" : bits >= 60 ? "Good" : bits >= 40 ? "Fair" : "Weak"
  );
</script>

<div
  class="ewe-popover safe-gen"
  role="group"
  aria-label="Password generator"
  use:keys={(e) => {
    // Esc closes the generator, not the editor; Enter on its controls never submits the form
    if (e.key === "Escape") (e.stopPropagation(), e.preventDefault(), onclose());
    else if (e.key === "Enter" && e.target instanceof HTMLInputElement) e.preventDefault();
  }}
>
  <div class="ewe-popover__head">
    <span class="ewe-popover__title">Generate a password</span>
    <button type="button" class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm" aria-label="Close the generator" onclick={onclose}><Icon name="x" /></button>
  </div>
  <div class="ewe-seg ewe-seg--block ewe-seg--sm" role="radiogroup" aria-label="Kind">
    <button type="button" class="ewe-seg__item" class:is-selected={kind === "chars"} role="radio" aria-checked={kind === "chars"} onclick={() => (kind = "chars")}>Characters</button>
    <button type="button" class="ewe-seg__item" class:is-selected={kind === "words"} role="radio" aria-checked={kind === "words"} onclick={() => (kind = "words")}>Words</button>
  </div>
  <div class="safe-gen__preview">
    <span class="mono" aria-live="polite">{value}</span>
    <button type="button" class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm" aria-label="Another password" title="Another one" onclick={roll}><Icon name="dices" /></button>
  </div>
  {#if kind === "chars"}
    <div class="safe-gen__line">
      <span class="label">Length</span>
      <div class="safe-range">
        <div class="ewe-slider" style="--value:{pct(length, LEN)}">
          <div class="ewe-slider__track"><div class="ewe-slider__fill"></div><div class="ewe-slider__thumb"></div></div>
        </div>
        <input type="range" min={LEN.min} max={LEN.max} bind:value={length} aria-label="Length" />
      </div>
      <span class="mono-numeric">{length}</span>
    </div>
    <div class="safe-gen__switches">
      <div class="ewe-switch-row">
        <span class="ewe-check__text"><span class="ewe-check__label">Digits</span></span>
        <button type="button" role="switch" aria-checked={digits} aria-label="Digits" class="ewe-switch" class:is-on={digits} onclick={() => (digits = !digits)}>
          <span class="ewe-switch__thumb"><Icon name={digits ? "check" : "x"} /></span>
        </button>
      </div>
      <div class="ewe-switch-row">
        <span class="ewe-check__text"><span class="ewe-check__label">Symbols</span></span>
        <button type="button" role="switch" aria-checked={symbols} aria-label="Symbols" class="ewe-switch" class:is-on={symbols} onclick={() => (symbols = !symbols)}>
          <span class="ewe-switch__thumb"><Icon name={symbols ? "check" : "x"} /></span>
        </button>
      </div>
    </div>
  {:else}
    <div class="safe-gen__line">
      <span class="label">Words</span>
      <div class="safe-range">
        <div class="ewe-slider" style="--value:{pct(words, WORDS)}">
          <div class="ewe-slider__track"><div class="ewe-slider__fill"></div><div class="ewe-slider__thumb"></div></div>
        </div>
        <input type="range" min={WORDS.min} max={WORDS.max} bind:value={words} aria-label="Words" />
      </div>
      <span class="mono-numeric">{words}</span>
    </div>
  {/if}
  <div class="ewe-popover__foot safe-gen__foot">
    <span class="caption safe-muted">{bits ? `${label} · about ${bits} bits` : ""}</span>
    <button type="button" class="ewe-btn ewe-btn--secondary ewe-btn--sm" disabled={!value} onclick={() => onuse(value)}><Icon name="check" />Use this password</button>
  </div>
</div>
