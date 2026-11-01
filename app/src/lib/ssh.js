// Words and small facts for the SSH page (docs/GATE.md S28): the gate's
// state from `ssh-status`, a host's address line, a key's short
// fingerprint, the hosts that use a key. Plain, short English: the owner
// is not a native speaker.

import { ago } from "./format.js";

/** The approval choice (`ssh_confirm`), in the window's words. */
export const CONFIRMS = [
  ["first-use", "Once per app"],
  ["every-time", "Every time"],
  ["never", "Never"]
];

/** A service's group glyph (no brand logos). */
export const GROUP_ICON = { git: "git-branch", cloud: "cloud", server: "server" };
export const GROUP_LABEL = { git: "Git", cloud: "Cloud", server: "Server" };

/** "1Password" for its socket, else the socket's file name. */
export function agentName(sock) {
  if (!sock) return "another agent";
  if (/\.1password\/agent\.sock$/.test(sock)) return "1Password";
  return sock.split("/").pop() || sock;
}

/** "a", "a and b", "a, b and c". */
export function andList(xs) {
  const a = [...xs];
  if (a.length <= 1) return a.join("");
  return `${a.slice(0, -1).join(", ")} and ${a[a.length - 1]}`;
}

/** "1 key" / "2 keys". */
export const count = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/**
 * The gate card's state: `off` (the agent is off), `move` (on, but ssh may
 * still go elsewhere: the gate isn't in place, ewe hosts name another
 * agent, keys only another agent has, key files Safe doesn't have yet) or
 * `good`. Hosts in the user's own lines that name another agent don't make
 * it `move`: Safe never edits them and answers for them anyway (`ownLines`).
 */
export function gateOf(st, hosts = []) {
  if (!st) return null;
  if (!st.enabled) return { kind: "off" };
  const g = st.gate;
  // the gate can't go on (a symlinked ~/.ssh/ewe-safe, …): moving won't help
  if (g?.problem) return { kind: "problem", problem: g.problem, on: false, hosts: [], ownLines: [], missing: 0, files: [], agent: "" };
  // a daemon before the gate: only whether ssh reaches the agent
  if (!g) {
    const others = (st.ssh_config_agents ?? []).filter((a) => !a.endsWith("ewe-safe-ssh.sock"));
    const ok = st.points_here && !others.length;
    return { kind: ok ? "good" : "move", on: ok, hosts: [], ownLines: [], missing: 0, files: [], agent: agentName(others[0]) };
  }
  const yours = new Set(hosts.filter((h) => h.source === "yours").map((h) => h.alias));
  const overridden = g.overridden ?? [];
  const ewe = overridden.filter((o) => !yours.has(o.host));
  const ownLines = overridden.filter((o) => yours.has(o.host));
  const others = g.other_agents ?? [];
  const missing = others.reduce((n, a) => n + Number(a.missing_from_safe ?? 0), 0);
  const files = (g.key_files ?? []).filter((f) => !f.in_safe);
  const agent = others.find((a) => a.missing_from_safe)?.name ?? (ewe[0] ? agentName(ewe[0].agent) : others[0]?.name ?? "another agent");
  const good = !!g.on && !ewe.length && !missing && !files.length;
  return { kind: good ? "good" : "move", on: !!g.on, hosts: ewe.map((o) => o.host), ownLines, missing, files, agent };
}

/** "SHA256:p2QAMXNIC1TJ…" */
export function shortFp(fp) {
  if (!fp) return "";
  const [kind, rest] = fp.includes(":") ? fp.split(/:(.*)/s) : ["", fp];
  return `${kind ? `${kind}:` : ""}${rest.slice(0, 12)}${rest.length > 12 ? "…" : ""}`;
}

/** "Ed25519", "RSA", "ECDSA" */
export function keyTypeName(t) {
  return { ed25519: "Ed25519", rsa: "RSA", ecdsa: "ECDSA" }[t] ?? (t || "");
}

/** "sam@work.example.com:2222" (the port only when it isn't 22). */
export function hostLine(h) {
  const host = h.host_name || h.alias;
  const port = h.port && Number(h.port) !== 22 ? `:${h.port}` : "";
  return `${h.user ? `${h.user}@` : ""}${host}${port}`;
}

/** The hosts whose key is this item. */
export function usedBy(hosts, itemId) {
  return (hosts ?? []).filter((h) => h.key?.item_id === itemId);
}

/** "Last used 2 min ago by ssh (from git)" or "Not used on this computer yet". */
export function lastUsed(lu, now = new Date()) {
  if (!lu?.at) return "Not used on this computer yet";
  return `Last used ${ago(lu.at, now)}${lu.program ? ` by ${lu.program}` : ""}`;
}

/** A name ssh can take as a host (GATE.md S24: no space, `*`, `?`, `!`). */
export const badAlias = (a) => /[\s*?!]/.test(a) || a.startsWith("-");
