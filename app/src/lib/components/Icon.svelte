<script>
  /**
   * One glyph of the vendored Lucide font inside an .ewe-icon box (the
   * ewe-sync runtime). The box takes its size from the component it sits in
   * (an .ewe-btn sets 16px, an .ewe-empty__icon 24px …) or from `size`
   * (xs, sm, lg, xl); the glyph fills it. `name` is a Lucide name from
   * ../icons.js.
   */
  import { ICONS } from "../icons.js";
  let { name, size = "", class: className = "", label = "" } = $props();
  const cp = $derived(ICONS[name] ?? 0x3f);
  const sizeClass = $derived(size ? `ewe-icon--${size}` : "");
</script>

<span
  class="ewe-icon ewe-glyph {sizeClass} {className}"
  role={label ? "img" : undefined}
  aria-label={label || undefined}
  aria-hidden={label ? undefined : "true"}><i>{String.fromCodePoint(cp)}</i></span
>
