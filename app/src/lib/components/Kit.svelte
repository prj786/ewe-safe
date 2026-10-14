<script>
  // The Emergency Kit (the mockup's Kit page): paper in both modes, where the
  // safe lives, a line for the master password, and how to open the file
  // without ewe. Print shows only this page (app.css, @media print).
  import Icon from "./Icon.svelte";
  import { api } from "../api.js";
  import { safe } from "../safe.svelte.js";
  import { longDay, placeLabel } from "../format.js";

  let cloud = $state(null);
  $effect(() => {
    api.cloudStatus().then((c) => (cloud = c?.signed_in ? c : null));
  });

  const place = $derived(safe.status?.place);
  const account = $derived(place?.kind === "nextcloud");
  const who = $derived(cloud?.display_name || cloud?.user || "");
</script>

<article class="safe-paper" aria-label="Emergency Kit">
  <div class="safe-paper__head">
    <span class="ewe-appicon safe-tile"><Icon name="vault" /></span>
    <div class="safe-head">
      <div class="h3">Safe — Emergency Kit</div>
      <div class="caption">Made {longDay()}{who ? ` for ${who}` : ""}</div>
    </div>
  </div>
  <dl class="ewe-kv">
    <dt>Where the safe lives</dt>
    <dd>{placeLabel(place)}{account ? " (Nextcloud)" : ""}</dd>
    {#if account && cloud?.server}
      <dt>Server</dt>
      <dd><span class="ewe-kv__mono">{cloud.server.replace(/^https?:\/\//, "")}</span></dd>
      <dt>Account</dt>
      <dd><span class="ewe-kv__mono">{cloud.user}</span></dd>
    {/if}
    <dt>File</dt>
    <dd><span class="ewe-kv__mono">{place?.location ?? "passwords.kdbx"}</span></dd>
  </dl>
  <div class="safe-stack">
    <div class="label">Master password</div>
    <div class="safe-blank"></div>
  </div>
  <div class="safe-stack">
    <div class="label">If ewe isn't there</div>
    <div class="body">The file is a standard KeePass file (KDBX 4). KeePassXC opens it on any computer. KeePassDX (Android), Strongbox or KeePassium (iPhone) open it on a phone.</div>
  </div>
</article>
