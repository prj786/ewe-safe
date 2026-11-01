// Keyboard for a dialog or a sheet over the window (the Dialog card):
// focus moves in — `[data-autofocus]`, else the first field, else the
// first button of the body, else the card — Tab stays inside, Esc closes,
// and focus goes back to where it was. Keys typed inside never reach the
// window's shortcuts. Used as `use:trap={{ onclose }}`.

const FOCUSABLE =
  'button:not([disabled]), [href], input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function trap(el, opts = {}) {
  let onclose = opts.onclose;
  const before = document.activeElement;
  const focusables = () => [...el.querySelectorAll(FOCUSABLE)].filter((x) => x.offsetParent !== null || x === document.activeElement);
  const first =
    el.querySelector("[data-autofocus]") ??
    el.querySelector('input:not([disabled]):not([type="hidden"]), textarea:not([disabled]), select:not([disabled])') ??
    el.querySelector(`:is(.ewe-sheet__body, .ewe-dialog__body) :is(${FOCUSABLE})`) ??
    focusables()[0];
  queueMicrotask(() => (first ?? el).focus());

  function onkeydown(e) {
    if (e.key === "Escape") {
      e.preventDefault();
      onclose?.();
    } else if (e.key === "Tab") {
      const f = focusables();
      if (f.length) {
        const at = f.indexOf(document.activeElement);
        if (e.shiftKey && at <= 0) {
          e.preventDefault();
          f[f.length - 1].focus();
        } else if (!e.shiftKey && at === f.length - 1) {
          e.preventDefault();
          f[0].focus();
        }
      }
    }
    e.stopPropagation();
  }
  el.addEventListener("keydown", onkeydown);

  return {
    update(o = {}) {
      onclose = o.onclose;
    },
    destroy() {
      el.removeEventListener("keydown", onkeydown);
      if (before instanceof HTMLElement && before.isConnected) before.focus();
    }
  };
}

/**
 * Up and Down (Home, End) move the focus between the `selector` elements
 * inside `root` — a menu's items, the rail's sections. True when it moved.
 */
export function arrowFocus(e, root, selector) {
  if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(e.key)) return false;
  const all = [...(root?.querySelectorAll(selector) ?? [])].filter((x) => !x.disabled && x.offsetParent !== null);
  if (!all.length) return false;
  const at = all.indexOf(document.activeElement);
  const n = all.length;
  const next =
    e.key === "Home" ? 0 : e.key === "End" ? n - 1 : at < 0 ? (e.key === "ArrowDown" ? 0 : n - 1) : (at + (e.key === "ArrowDown" ? 1 : -1) + n) % n;
  e.preventDefault();
  e.stopPropagation();
  all[next].focus();
  return true;
}

/** `use:keys={fn}`: a keydown listener on a group that isn't a control itself. */
export function keys(el, fn) {
  let f = fn;
  const on = (e) => f?.(e);
  el.addEventListener("keydown", on);
  return {
    update(next) {
      f = next;
    },
    destroy() {
      el.removeEventListener("keydown", on);
    }
  };
}

/** `use:edge` on a page's scroller: its header gets a line once the page scrolls under it. */
export function edge(el) {
  const head = el.previousElementSibling;
  const on = () => head?.classList.toggle("is-scrolled", el.scrollTop > 0);
  el.addEventListener("scroll", on, { passive: true });
  on();
  return { destroy: () => el.removeEventListener("scroll", on) };
}
