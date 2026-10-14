<script>
  // The generator popover (under the password field): characters or words,
  // a preview from the daemon's `generate` (Safe's own generator, never the
  // page's), the dice for another one, "Use password" to fill the field.
  import Icon from "./Icon.svelte";
  import { safe } from "../safe.svelte.js";

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
  role="dialog"
  aria-label="Password generator"
  tabindex="-1"
  onkeydown={(e) => e.key === "Escape" && (e.stopPropagation(), onclose())}
>
  <div class="ewe-popover__head">
    <span class="ewe-popover__title">New password</span>
    <button class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm" aria-label="Close" onclick={onclose}><Icon name="x" /></button>
  </div>
  <div class="ewe-seg ewe-seg--block ewe-seg--sm" role="radiogroup" aria-label="Kind">
    <button class="ewe-seg__item" class:is-selected={kind === "chars"} role="radio" aria-checked={kind === "chars"} onclick={() => (kind = "chars")}>Characters</button>
    <button class="ewe-seg__item" class:is-selected={kind === "words"} role="radio" aria-checked={kind === "words"} onclick={() => (kind = "words")}>Words</button>
  </div>
  <div class="safe-gen__preview">
    <span class="mono">{value}</span>
    <button class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm" aria-label="New password" onclick={roll}><Icon name="dices" /></button>
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
  {#if bits}<div class="caption safe-muted">{label} · about {bits} bits</div>{/if}
  <div class="ewe-popover__foot">
    <button class="ewe-btn ewe-btn--ghost" onclick={onclose}>Cancel</button>
    <button class="ewe-btn ewe-btn--primary" disabled={!value} onclick={() => onuse(value)}>Use password</button>
  </div>
</div>
