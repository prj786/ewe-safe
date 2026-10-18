<script>
  // The window's states: Safe's service unreachable, no safe on this
  // machine (setup), locked, or open. The `--unlock` process (`mode:
  // "unlock"`) shows only the compact prompt and quits once the safe opens;
  // the `--approve` process (`mode: "approve"`) only asks the SSH agent's
  // question; the `--confirm` process (`mode: "confirm"`) only asks for the
  // password again before a card fill (docs/SYSTEM.md §4).
  import { onMount } from "svelte";
  import Icon from "$lib/components/Icon.svelte";
  import Setup from "$lib/screens/Setup.svelte";
  import Unlock from "$lib/screens/Unlock.svelte";
  import Main from "$lib/screens/Main.svelte";
  import Approve from "$lib/screens/Approve.svelte";
  import Confirm from "$lib/screens/Confirm.svelte";
  import { api, listen } from "$lib/api.js";
  import { safe } from "$lib/safe.svelte.js";
  import { ui } from "$lib/ui.svelte.js";
  import { watchTheme } from "$lib/theme.js";

  let mode = $state("main");
  let approve = $state(null);
  let reason = $state("");

  function follow(a) {
    if (!a) return;
    if (a.show) {
      ui.pick({});
      ui.selected = a.show;
    }
    if (a.new) {
      ui.go("items");
      ui.editing = { mode: "new", kind: "login" };
    }
    if (a.import) ui.go("import");
  }

  onMount(() => {
    const off = [watchTheme()];
    (async () => {
      const a = await api.launchArgs();
      if (a?.mode) mode = a.mode;
      if (a?.approve) approve = a.approve;
      if (a?.reason) reason = a.reason;
      follow(a);
      off.push(await listen("safe-args", follow));
      await safe.start();
    })();
    return () => {
      off.forEach((f) => f?.());
      safe.stop();
    };
  });

  // the unlock-only window is done once the safe is open, however it opened
  $effect(() => {
    if (mode === "unlock" && safe.status && safe.status.set_up && !safe.status.locked) api.quit(0);
  });
</script>

{#if mode === "approve"}
  <Approve app={approve?.app || "An app"} key={approve?.key || "an SSH key"} path={approve?.path ?? ""} system={!!approve?.system} />
{:else if mode === "confirm"}
  <Confirm {reason} />
{:else if mode === "unlock"}
  {#if !safe.daemon.available || (safe.status && !safe.status.set_up)}
    <div class="safe-compact">
      <span class="ewe-appicon safe-tile"><Icon name="lock" /></span>
      <div class="safe-compact__body">
        <div class="safe-head">
          <div class="h3">{safe.daemon.available ? "There's no safe on this computer yet" : "Safe's service isn't running"}</div>
          <div class="caption safe-muted">{safe.daemon.available ? "Open Safe to create one or open one." : (safe.daemon.hint ?? safe.daemon.message ?? "")}</div>
        </div>
        <div class="safe-compact__row"><button class="ewe-btn ewe-btn--secondary" onclick={() => api.quit(1)}>Close</button></div>
      </div>
    </div>
  {:else if safe.status}
    <Unlock compact />
  {/if}
{:else if !safe.daemon.available}
  <div class="safe-win">
    <div class="safe-solo">
      <div class="safe-col safe-col--narrow safe-col--center safe-center">
        <div class="ewe-empty">
          <span class="ewe-empty__icon"><Icon name="cloud-off" /></span>
          <div class="ewe-empty__title">Safe's service isn't running</div>
          <div class="ewe-empty__desc">{safe.daemon.message ?? "The window can't reach it."}</div>
          {#if safe.daemon.hint}<div class="caption safe-muted"><code>{safe.daemon.hint}</code></div>{/if}
          <div class="ewe-empty__actions"><button class="ewe-btn ewe-btn--secondary" onclick={() => safe.refresh()}><Icon name="refresh-cw" />Try again</button></div>
        </div>
      </div>
    </div>
  </div>
{:else if !safe.status}
  <div class="safe-win"></div>
{:else if ui.setup || !safe.setUp}
  <Setup />
{:else if safe.locked}
  <Unlock />
{:else}
  <Main />
{/if}
