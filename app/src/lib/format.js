// Words and numbers the screens show: place names, times, the sync
// states (ewe Sync's words), password strength. Plain and short.

export const PLACES = {
  nextcloud: { label: "Your ewe account", name: "your ewe account", icon: "cloud" },
  local: { label: "This computer only", name: "this computer", icon: "laptop" },
  webdav: { label: "Your own server (WebDAV)", name: "your own server", icon: "server" },
  folder: { label: "A synced folder", name: "a synced folder", icon: "folder-sync" },
  sftp: { label: "SSH server", name: "your SSH server", icon: "terminal" },
  dropbox: { label: "Dropbox", name: "Dropbox", icon: "cloud" },
  gdrive: { label: "Google Drive", name: "Google Drive", icon: "cloud" }
};

/** The place as a label ("Your ewe account"), on its own line. */
export const placeLabel = (p) => PLACES[p?.kind]?.label ?? "Your safe";
/** The place inside a sentence ("Open your safe from your ewe account"). */
export const placeName = (p) => PLACES[p?.kind]?.name ?? "your safe";
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

/** "12 Sep" this year, "12 Sep 2025" before. */
export function shortDay(iso, now = new Date()) {
  const d = toDate(iso);
  if (!d) return "";
  return d.getFullYear() === now.getFullYear() ? `${d.getDate()} ${MONTHS[d.getMonth()]}` : day(iso);
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

/**
 * The sync state in ewe Sync's own words, one table for every place that
 * shows it (the side navigation's foot, Settings, an item's foot): the
 * word, a Badge/alert tone and an icon. ewe Sync says "Up to date",
 * "Syncing…", "Waiting to upload", "Offline", "Couldn’t sync"; Safe's two
 * warnings (the server gave an older copy, a server that can't stop two
 * saves at once) are "Needs attention".
 */
export const SYNC_WORDS = {
  "in-sync": { word: "Up to date", tone: "success", icon: "cloud-check" },
  pending: { word: "Waiting to upload", tone: "info", icon: "upload" },
  offline: { word: "Offline", tone: "warning", icon: "cloud-off" },
  error: { word: "Couldn’t sync", tone: "warning", icon: "triangle-alert" },
  local: { word: "On this computer only", tone: "neutral", icon: "laptop" },
  attention: { word: "Needs attention", tone: "warning", icon: "triangle-alert" }
};

/** `{key, word, tone, icon}` for a `status.sync`, or null. */
export function syncState(sync) {
  if (!sync) return null;
  const key = sync.warning === "rollback" || sync.warning === "single-writer" ? "attention" : sync.state;
  return SYNC_WORDS[key] ? { key, ...SYNC_WORDS[key] } : null;
}

/** The side navigation's last line: "Up to date · 2 min ago", "Offline"… */
export function syncLine(sync, now = new Date()) {
  const st = syncState(sync);
  if (!st) return null;
  return { ...st, text: st.key === "in-sync" && sync.last ? `${st.word} · ${ago(sync.last, now)}` : st.word };
}

/**
 * Settings' sync row: the word, and one sentence that says what it means
 * and what to do (`action: "ewe-sync"`: an Open ewe Sync button);
 * `server` is the account's host.
 */
export function syncDetail(sync, place, server = "", now = new Date()) {
  const st = syncState(sync);
  if (!st) return null;
  const host = server ? server.replace(/^https?:\/\//, "").replace(/\/+$/, "") : "Your server";
  const saved = [sync.by_machine ? `Saved by ${sync.by_machine}` : "Saved", when(sync.last, now)].filter(Boolean).join(" · ");
  if (sync.warning === "rollback")
    return { ...st, desc: "Your server gave an older copy. ewe Safe kept your newer passwords and uploaded them again. If this happens again, check your server’s backups." };
  if (sync.warning === "single-writer")
    return { ...st, desc: "This server can’t stop two saves at once. Use ewe Safe on one computer at a time with it, or move the safe to your ewe account." };
  switch (st.key) {
    case "in-sync":
      return { ...st, desc: sync.last ? saved : `Saved to ${placeName(place)}.` };
    case "pending":
      return { ...st, desc: "Your changes are saved on this computer. ewe Safe uploads them as soon as your server answers." };
    case "offline":
      return { ...st, desc: `${host} can’t be reached. You can still read and change your safe; changes upload later.` };
    case "error":
      return { ...st, desc: "ewe Safe can’t reach your server. Your passwords are still here. Check your account in ewe Sync.", action: "ewe-sync" };
    case "local":
      return { ...st, desc: "Nothing is uploaded. Back up the file yourself." };
    default:
      return { ...st, desc: "" };
  }
}

/** An item's foot: "Up to date in your account", "Waiting to upload"… */
export function syncWhere(sync, place) {
  const st = syncState(sync);
  if (!st) return "";
  return st.key === "in-sync" && place?.kind && place.kind !== "local" ? `${st.word} in ${placeName(place)}` : st.word;
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
