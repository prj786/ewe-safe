// Cards and addresses in the window (docs/SYSTEM.md §4): the brand from
// the number as it is typed (the daemon decides again when it saves), the
// check that warns about a typo (never refuses), the number in groups, the
// expiry as MM/YY, and country names. Nothing here keeps a value.

/** Every brand Safe names, with how people write it. */
export const BRANDS = [
  ["visa", "Visa"],
  ["mastercard", "Mastercard"],
  ["amex", "Amex"],
  ["discover", "Discover"],
  ["jcb", "JCB"],
  ["unionpay", "UnionPay"],
  ["diners", "Diners Club"],
  ["maestro", "Maestro"],
  ["mir", "Mir"],
  ["other", "Other card"]
];

/** "visa" → "Visa"; an unknown brand is a card. */
export const brandName = (b) => (b && b !== "other" ? BRANDS.find(([id]) => id === b)?.[1] : null) ?? "Card";

/** The one line on the Card form and in Settings (the owner's worry). */
export const ENCRYPTED_NOTE = "Encrypted on this computer before it leaves it. Nextcloud only sees a locked file.";

export const digits = (t) => String(t ?? "").replace(/\D/g, "");

/** The brand of a number from its first digits (safe_core::card::brand_of). */
export function brandOf(d) {
  const p = (n) => (d.length >= n ? Number(d.slice(0, n)) : 0);
  const [p2, p3, p4, p6] = [p(2), p(3), p(4), p(6)];
  if (!d) return "other";
  if (d.startsWith("4")) return "visa";
  if (p4 >= 2200 && p4 <= 2204) return "mir";
  if ((p2 >= 51 && p2 <= 55) || (p4 >= 2221 && p4 <= 2720)) return "mastercard";
  if (p2 === 34 || p2 === 37) return "amex";
  if (p4 === 6011 || (p3 >= 644 && p3 <= 649) || p2 === 65 || (p6 >= 622126 && p6 <= 622925)) return "discover";
  if (p4 >= 3528 && p4 <= 3589) return "jcb";
  if (p2 === 62 || p2 === 81) return "unionpay";
  if ((p3 >= 300 && p3 <= 305) || p4 === 3095 || [36, 38, 39].includes(p2)) return "diners";
  if ([50, 56, 57, 58, 67].includes(p2) || p4 === 6304 || p4 === 6390) return "maestro";
  return "other";
}

/** The Luhn check every card number passes. */
export function luhn(d) {
  if (!/^\d+$/.test(d)) return false;
  let sum = 0;
  for (let i = 0; i < d.length; i++) {
    let n = Number(d[d.length - 1 - i]);
    if (i % 2 === 1) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
  }
  return sum % 10 === 0;
}

/** A warning for a number that looks mistyped, or "" (Safe keeps it anyway). */
export function check(d) {
  if (!d) return "";
  if (d.length < 12 || d.length > 19) return "A card number has 12 to 19 digits. Check it for a typo.";
  if (!luhn(d)) return "The card number doesn't pass the card check. Check it for a typo.";
  return "";
}

/** The number in the groups its card prints: Amex 4-6-5, others by four. */
export function grouped(text, brand = "") {
  const d = digits(text).slice(0, 19);
  const b = brand || brandOf(d);
  const sizes = b === "amex" ? [4, 6, 5] : b === "diners" && d.length === 14 ? [4, 6, 4] : null;
  const out = [];
  let at = 0;
  for (const n of sizes ?? []) {
    if (at >= d.length) break;
    out.push(d.slice(at, at + n));
    at += n;
  }
  for (; at < d.length; at += 4) out.push(d.slice(at, at + 4));
  return out.join(" ");
}

/** "•••• 4242" in the card's own groups. */
export function masked(last4, brand = "") {
  if (!last4) return "••••";
  return brand === "amex" ? `•••• •••••• •${last4}` : `•••• •••• •••• ${last4}`;
}

/** What the expiry field shows while typing: digits, a "/" after the month. */
export function expiryTyped(text) {
  let d = digits(text);
  // "8" is August, and so is the "1" of "13" only when it can't be a month
  if (d && (d[0] > "1" || (d[0] === "1" && d.length > 1 && d[1] > "2"))) d = `0${d}`;
  d = d.slice(0, 4);
  return d.length > 2 ? `${d.slice(0, 2)}/${d.slice(2)}` : d;
}

/** "08/2029" → "08/29"; anything else as it is. */
export function expiryShort(e) {
  const m = /^(\d{2})\/\d{2}(\d{2})$/.exec(e ?? "");
  return m ? `${m[1]}/${m[2]}` : e ?? "";
}

/** True when an "MM/YYYY" expiry is in the past. */
export function expired(e, now = new Date()) {
  const m = /^(\d{2})\/(\d{4})$/.exec(e ?? "");
  if (!m) return false;
  const y = Number(m[2]);
  const mo = Number(m[1]);
  return y < now.getFullYear() || (y === now.getFullYear() && mo < now.getMonth() + 1);
}

// countries: ISO 3166-1 alpha-2 codes, named by the system's own data
const NOT_COUNTRIES = new Set(["EU", "EZ", "UN", "QO", "ZZ", "XA", "XB"]);
let names;
function regionNames() {
  if (names !== undefined) return names;
  try {
    names = new Intl.DisplayNames(["en"], { type: "region", fallback: "none" });
  } catch {
    names = null;
  }
  return names;
}

/** "GE" → "Georgia"; a value that isn't a code stays as it is. */
export function countryName(code) {
  if (!code) return "";
  if (!/^[A-Z]{2}$/.test(code)) return code;
  return regionNames()?.of(code) ?? code;
}

let list;
/** Every country as {code, name}, by name. */
export function countries() {
  if (list) return list;
  const n = regionNames();
  const out = [];
  if (n) {
    for (let a = 65; a <= 90; a++)
      for (let b = 65; b <= 90; b++) {
        const code = String.fromCharCode(a, b);
        if (NOT_COUNTRIES.has(code)) continue;
        const name = n.of(code);
        if (name && name !== code) out.push({ code, name });
      }
  }
  list = out.sort((x, y) => x.name.localeCompare(y.name));
  return list;
}

/** An address as it goes on an envelope, one line each. */
export function addressLines(a) {
  if (!a) return [];
  const cityLine = [a.postal_code, a.city].filter(Boolean).join(" ");
  return [a.full_name ?? a.name, a.organization, a.line1, a.line2, cityLine, a.region, countryName(a.country)].filter(
    (l) => l && l.trim()
  );
}

/** A list row's second line. */
export function cardLine(c) {
  if (!c) return "Card";
  return [`${brandName(c.brand)} ${c.last4 ? `•••• ${c.last4}` : ""}`.trim(), expiryShort(c.expiry)].filter(Boolean).join(" · ");
}

export function addressLine(a) {
  if (!a) return "Address";
  return [a.line1, a.city].filter(Boolean).join(", ") || a.name || "Address";
}
