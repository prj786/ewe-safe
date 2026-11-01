<script>
  /**
   * A sheet over the pane (the Sheet card): a title, a body that scrolls, a
   * foot for the buttons. Keyboard: focus moves into it (the first field or
   * button of the body, or `[data-autofocus]`), Tab stays inside, Esc
   * closes, and focus goes back to where it was.
   */
  import Icon from "./Icon.svelte";

  let { title, onclose, children, foot, wide = false, icon = "" } = $props();

  const id = `sheet-${Math.random().toString(36).slice(2, 9)}`;
  let el = $state();

  const FOCUSABLE = 'button:not([disabled]), [href], input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
  const focusables = () => [...(el?.querySelectorAll(FOCUSABLE) ?? [])].filter((x) => x.offsetParent !== null || x === document.activeElement);

  $effect(() => {
    const before = document.activeElement;
    const first = el?.querySelector("[data-autofocus]") ?? el?.querySelector(`.ewe-sheet__body :is(${FOCUSABLE})`) ?? el?.querySelector(FOCUSABLE);
    (first ?? el)?.focus();
    return () => {
      if (before instanceof HTMLElement && before.isConnected) before.focus();
    };
  });

  function onkeydown(e) {
    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      onclose?.();
    } else if (e.key === "Tab") {
      const f = focusables();
      if (!f.length) return;
      const at = f.indexOf(document.activeElement);
      if (e.shiftKey && at <= 0) {
        e.preventDefault();
        f[f.length - 1].focus();
      } else if (!e.shiftKey && at === f.length - 1) {
        e.preventDefault();
        f[0].focus();
      }
    }
    // keys typed in a sheet never reach the window's shortcuts
    e.stopPropagation();
  }
</script>

<div class="safe-scrim">
  <div bind:this={el} class="ewe-sheet safe-sheet" class:safe-sheet--wide={wide} role="dialog" aria-modal="true" aria-labelledby={id} tabindex="-1" {onkeydown}>
    <div class="ewe-sheet__head">
      {#if icon}<span class="safe-sheet__icon"><Icon name={icon} /></span>{/if}
      <h2 class="ewe-sheet__title" {id}>{title}</h2>
      <button type="button" class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm" aria-label="Close" onclick={() => onclose?.()}><Icon name="x" /></button>
    </div>
    <div class="ewe-sheet__body">{@render children()}</div>
    {#if foot}<div class="ewe-sheet__foot">{@render foot()}</div>{/if}
  </div>
</div>
