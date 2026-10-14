<script>
  /** The Switch card: a button with the switch role, .ewe-switch, a small
   *  check or x on the thumb so the state never rests on colour alone. */
  import Icon from "./Icon.svelte";
  let { on = false, disabled = false, label = "", toggled = () => {} } = $props();
</script>

<button
  type="button"
  role="switch"
  aria-checked={on}
  aria-label={label || undefined}
  {disabled}
  class="ewe-switch"
  class:is-on={on}
  class:is-disabled={disabled}
  onclick={() => toggled(!on)}
>
  <span class="ewe-switch__thumb"><Icon name={on ? "check" : "x"} /></span>
</button>
