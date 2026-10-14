// Words and numbers the screens show: place names, times, the sync
// messages, password strength. The copy is the mockup's
// (design-mockups/safe.html), plain and short.

export const PLACES = {
  nextcloud: { label: "Your ewe account", icon: "cloud" },
  local: { label: "This computer only", icon: "laptop" },
  webdav: { label: "Your own server (WebDAV)", icon: "server" },
  folder: { label: "A synced folder", icon: "folder-sync" },
  sftp: { label: "SSH server", icon: "terminal" },
  dropbox: { label: "Dropbox", icon: "cloud" },
  gdrive: { label: "Google Drive", icon: "cloud" }
};

export const placeLabel = (p) => PLACES[p?.kind]?.label ?? "Your safe";
export const placeIcon = (p) => PLACES[p?.kind]?.icon ?? "vault";

/** "cloud.example.org · ewe/safe/passwords.kdbx", or the file alone. */
export function placeLine(p, server = "") {
  if (!p) return "";
  const host = server ? server.replace(/^https?:\/\//, "").replace(/\/+$/, "") : "";
  return [host, p.location].filter(Boolean).join(" · ");
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const LONG_MONTHS = [
  "January", "February", "March", "April", "May", "June",
  "July", "August", "September", "October", "November", "December"
];

function toDate(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d;
}

const sameDay = (a, b) =>
  a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
const hm = (d) => `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;

/** "12 Sep 2026" */
export function day(iso) {
  const d = toDate(iso);
  return d ? `${d.getDate()} ${MONTHS[d.getMonth()]} ${d.getFullYear()}` : "";
}

/** "14 October 2026" — the Emergency Kit */
export function longDay(d = new Date()) {
  return `${d.getDate()} ${LONG_MONTHS[d.getMonth()]} ${d.getFullYear()}`;
}

/** "today, 16:02" · "yesterday, 9:14" · "12 Sep 2026" */
export function when(iso, now = new Date()) {
  const d = toDate(iso);
  if (!d) return "";
  if (sameDay(d, now)) return `today, ${hm(d)}`;
  const y = new Date(now);
  y.setDate(now.getDate() - 1);
  if (sameDay(d, y)) return `yesterday, ${hm(d)}`;
  return day(iso);
}

/** "just now" · "2 min ago" · "3 h ago" · "yesterday" · "12 Sep 2026" */
export function ago(iso, now = new Date()) {
  const d = toDate(iso);
  if (!d) return "";
  const s = Math.max(0, Math.round((now - d) / 1000));
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (sameDay(d, now)) return `${Math.floor(s / 3600)} h ago`;
  const y = new Date(now);
  y.setDate(now.getDate() - 1);
  if (sameDay(d, y)) return "yesterday";
  return day(iso);
}

/** The side navigation's last line: {icon, tone, text}. */
export function syncLine(sync, now = new Date()) {
  if (!sync) return null;
  if (sync.warning === "rollback" || sync.warning === "single-writer")
    return { icon: "triangle-alert", tone: "is-warning", text: "Needs a look" };
  switch (sync.state) {
    case "in-sync":
      return { icon: "cloud", tone: "", text: sync.last ? `In sync · ${ago(sync.last, now)}` : "In sync" };
    case "pending":
      return { icon: "upload", tone: "is-info", text: "Not uploaded yet" };
    case "offline":
      return { icon: "cloud-off", tone: "is-warning", text: "Offline" };
    case "local":
      return { icon: "laptop", tone: "", text: "On this computer" };
    case "error":
      return { icon: "triangle-alert", tone: "is-warning", text: "Can't reach your server" };
    default:
      return null;
  }
}

/** The Settings alert for the sync state (the mockup's five messages). */
export function syncAlert(sync, place, server = "", now = new Date()) {
  if (!sync) return null;
  const host = server ? server.replace(/^https?:\/\//, "").replace(/\/+$/, "") : "Your server";
  if (sync.warning === "rollback")
    return {
      tone: "warning",
      icon: "triangle-alert",
      title: "Your server gave an older copy",
      desc: "Safe kept your newer passwords and uploaded them again. If this happens again, check your server's backups."
    };
  if (sync.warning === "single-writer")
    return {
      tone: "warning",
      icon: "triangle-alert",
      title: "This server can't stop two saves at once",
      desc: "Use Safe on one computer at a time with it, or move the safe to your ewe account."
    };
  switch (sync.state) {
    case "in-sync":
      return {
        tone: "success",
        icon: "circle-check",
        title: "In sync",
        desc: sync.last ? `Saved to ${placeLabel(place)} ${ago(sync.last, now)}.` : `Saved to ${placeLabel(place)}.`
      };
    case "pending":
      return {
        tone: "info",
        icon: "upload",
        title: "Changes not uploaded yet",
        desc: "They are saved on this computer. Safe uploads them as soon as your server answers."
      };
    case "offline":
      return {
        tone: "warning",
        icon: "cloud-off",
        title: "Offline",
        desc: `${host} can't be reached. You can still read and change your safe; changes upload later.`
      };
    case "error":
      return {
        tone: "warning",
        icon: "triangle-alert",
        title: "Safe can't reach your server",
        desc: "Your passwords are still here. Check your account in ewe-sync."
      };
    case "local":
      return {
        tone: "info",
        icon: "laptop",
        title: "This computer only",
        desc: "Nothing is uploaded. Back up the file yourself."
      };
    default:
      return null;
  }
}

/** The Settings badge next to "Last saved". */
export function syncBadge(sync) {
  if (!sync) return null;
  if (sync.warning === "rollback") return { tone: "warning", text: "Older copy" };
  if (sync.warning === "single-writer") return { tone: "warning", text: "One at a time" };
  switch (sync.state) {
    case "in-sync":
      return { tone: "success", text: "In sync" };
    case "pending":
      return { tone: "info", text: "Waiting" };
    case "offline":
      return { tone: "warning", text: "Offline" };
    case "error":
      return { tone: "warning", text: "Error" };
    case "local":
      return { tone: "neutral", text: "This computer" };
    default:
      return null;
  }
}

/** "github.com" from "https://github.com/login". */
export function hostOf(url) {
  try {
    return new URL(url.includes("://") ? url : `https://${url}`).host.replace(/^www\./, "");
  } catch {
    return url;
  }
}

/** The address an item's website opens at. */
export const href = (url) => (url.includes("://") ? url : `https://${url}`);

/** The tile letter of an item. */
export const letter = (title) => (title?.trim()?.[0] ?? "?").toUpperCase();

/**
 * A rough strength for a password the user types (generated ones carry the
 * daemon's `bits`): the size of the character set it draws from times its
 * length, less for repeats and runs. Honest enough for a meter; not a
 * guarantee.
 */
export function strength(pw) {
  if (!pw) return { bits: 0, label: "", tone: "", pct: 0 };
  const words = pw.split(/[\s\-_.]+/).filter((w) => w.length >= 3);
  let set = 0;
  if (/[a-z]/.test(pw)) set += 26;
  if (/[A-Z]/.test(pw)) set += 26;
  if (/[0-9]/.test(pw)) set += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) set += 32;
  let bits = pw.length * Math.log2(Math.max(set, 2));
  // a passphrase: about 12.9 bits a word from a 7776-word list
  if (words.length >= 4 && /^[a-z]+([\s\-_.][a-z]+)+$/i.test(pw)) bits = Math.max(bits * 0.5, words.length * 12.9);
  const repeats = pw.length - new Set(pw).size;
  bits -= repeats * 2;
  if (/(.)\1\1/.test(pw)) bits -= 10;
  if (/(012|123|234|345|456|567|678|789|abc|bcd|qwe|asd|password)/i.test(pw)) bits -= 15;
  bits = Math.max(0, Math.round(bits));
  const label = bits < 40 ? "Weak" : bits < 60 ? "Fair" : bits < 80 ? "Good" : "Strong";
  const tone = bits < 40 ? "danger" : bits < 60 ? "warning" : "success";
  return { bits, label, tone, pct: Math.min(100, Math.round((bits / 100) * 100)) };
}
