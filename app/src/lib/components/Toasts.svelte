<script>
  import Icon from "./Icon.svelte";
  import { toasts } from "../toast.svelte.js";
</script>

<div class="safe-toasts" aria-live="polite">
  {#each toasts.list as t (t.id)}
    <div class="ewe-toast" role="status">
      <Icon name={t.icon} />
      <span class="ewe-toast__text">{t.text}</span>
      <span class="ewe-toast__sep"></span>
      <button class="ewe-iconbtn ewe-iconbtn--ghost ewe-iconbtn--sm" aria-label="Close" onclick={() => toasts.close(t.id)}>
        <Icon name="x" />
      </button>
      {#if t.timer}<span class="ewe-toast__timer" style="width:100%;animation-duration:{t.ms}ms"></span>{/if}
    </div>
  {/each}
</div>
