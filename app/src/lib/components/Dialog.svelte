<script>
  /**
   * A dialog (the Dialog card) over the whole window: the scrim dims the
   * rail and the pane alike, the keyboard stays inside (lib/trap.js), Esc
   * cancels. `onsubmit` makes the card a form — Enter runs the primary
   * action. `tone: "danger"` is an alert dialog. Without a `title` there is
   * no head (the Emergency Kit carries its own); `label` names it then.
   */
  import Icon from "./Icon.svelte";
  import { trap } from "../trap.js";

  let { title = "", desc = "", icon = "", tone = "", size = "", label = "", onclose, onsubmit = null, children, foot } = $props();

  const id = `dialog-${Math.random().toString(36).slice(2, 9)}`;
</script>

<div class="safe-scrim">
  <svelte:element
    this={onsubmit ? "form" : "div"}
    class="ewe-dialog safe-dialog {size ? `ewe-dialog--${size}` : ''}"
    role={tone === "danger" ? "alertdialog" : "dialog"}
    aria-modal="true"
    aria-labelledby={title ? id : undefined}
    aria-describedby={desc ? `${id}-desc` : undefined}
    aria-label={title ? undefined : label}
    tabindex="-1"
    use:trap={{ onclose }}
    onsubmit={onsubmit ?? undefined}
  >
    {#if title}
      <div class="ewe-dialog__head">
        {#if icon}<span class="ewe-dialog__icon" class:ewe-dialog__icon--danger={tone === "danger"}><Icon name={icon} /></span>{/if}
        <div class="ewe-dialog__titles">
          <h2 class="ewe-dialog__title" {id}>{title}</h2>
          {#if desc}<p class="ewe-dialog__desc" id="{id}-desc">{desc}</p>{/if}
        </div>
      </div>
    {/if}
    {#if children}<div class="ewe-dialog__body">{@render children()}</div>{/if}
    {#if foot}<div class="ewe-dialog__foot">{@render foot()}</div>{/if}
  </svelte:element>
</div>
