<script>
  /**
   * A sheet over the window (the Sheet card): a title, a body that scrolls,
   * a foot for the buttons. The scrim dims the whole window, the rail too.
   * Keyboard (lib/trap.js): focus moves into it (`[data-autofocus]`, the
   * first field, or the first button of the body), Tab stays inside, Esc
   * closes, and focus goes back to where it was.
   */
  import Icon from "./Icon.svelte";
  import { trap } from "../trap.js";

  let { title, onclose, children, foot, wide = false, icon = "" } = $props();

  const id = `sheet-${Math.random().toString(36).slice(2, 9)}`;
</script>

<div class="safe-scrim">
  <div class="ewe-sheet safe-sheet" class:safe-sheet--wide={wide} role="dialog" aria-modal="true" aria-labelledby={id} tabindex="-1" use:trap={{ onclose }}>
    <div class="ewe-sheet__head">
      {#if icon}<span class="safe-sheet__icon"><Icon name={icon} /></span>{/if}
      <h2 class="ewe-sheet__title" {id}>{title}</h2>
      <button type="button" class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm" aria-label="Close" onclick={() => onclose?.()}><Icon name="x" /></button>
    </div>
    <div class="ewe-sheet__body">{@render children()}</div>
    {#if foot}<div class="ewe-sheet__foot">{@render foot()}</div>{/if}
  </div>
</div>
