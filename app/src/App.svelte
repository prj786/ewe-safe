<script>
  // The window's states: Safe's service unreachable, no safe on this
  // machine (setup), locked, or open. The `--unlock` process (`mode:
  // "unlock"`) shows only the compact prompt and quits once the safe opens;
  // the `--approve` process (`mode: "approve"`) only asks the SSH agent's
  // question; the `--confirm` process (`mode: "confirm"`) only asks for the
  // password again before a card fill (docs/SYSTEM.md §4).
  import { onMount } from "svelte";
  import Icon from "$lib/components/Icon.svelte";
  import Sidenav from "$lib/components/Sidenav.svelte";
  import Toasts from "$lib/components/Toasts.svelte";
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
    // `--ssh`: the SSH page (docs/GATE.md S28)
    if (a.ssh && ui.view !== "ssh") ui.go("ssh");
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

  // the main window's frame (App shell): the rail and the inset pane stay
  // put from the first paint through setup, the lock and the items — only
  // the pane's content changes, so unlocking doesn't move the window
  const rail = $derived(
    !safe.daemon.available || !safe.status || ui.setup || !safe.setUp ? "bare" : safe.locked ? "locked" : "full"
  );

  // the unlock-only window is done once the safe is open, however it opened
  $effect(() => {
    if (mode === "unlock" && safe.status && safe.status.set_up && !safe.status.locked) api.quit(0);
  });
</script>

{#if mode === "approve"}
  <Approve app={approve?.app || "An app"} key={approve?.key || "an SSH key"} path={approve?.path ?? ""} system={!!approve?.system} host={approve?.host ?? ""} forwarded={!!approve?.forwarded} once={!!approve?.once} />
{:else if mode === "confirm"}
  <Confirm {reason} />
{:else if mode === "unlock"}
  <!-- not set up but offered: the account's safe opens with the master password here -->
  {#if !safe.daemon.available || (safe.status && !safe.status.set_up && !safe.status.offer)}
    <div class="safe-compact">
      <span class="ewe-appicon safe-tile"><Icon name={safe.daemon.available ? "vault" : "power"} /></span>
      <div class="safe-compact__body">
        <div class="safe-head">
          <div class="h3">{safe.daemon.available ? "There’s no safe on this computer yet" : "ewe Safe isn’t running"}</div>
          <div class="caption safe-muted">{safe.daemon.available ? "Open ewe Safe to create one or open one." : "Its background service doesn’t answer. Open ewe Safe to try again."}</div>
        </div>
        <div class="safe-compact__row"><button type="button" class="ewe-btn ewe-btn--secondary" onclick={() => api.quit(1)}>Close</button></div>
      </div>
    </div>
  {:else if safe.status}
    <Unlock compact />
  {/if}
{:else}
  <div class="ewe-appwin safe-win">
    <Sidenav mode={rail} />
    <main class="ewe-appwin__pane safe-pane">
      {#if !safe.daemon.available}
        <div class="safe-stage">
          <div class="ewe-empty safe-col safe-col--narrow safe-col--center">
            <span class="ewe-empty__icon"><Icon name="power" /></span>
            <div class="ewe-empty__title">ewe Safe isn’t running</div>
            <div class="ewe-empty__desc">Its background service doesn’t answer, so the window can’t open your safe. Your passwords are not affected.</div>
            <div class="ewe-empty__actions"><button type="button" class="ewe-btn ewe-btn--primary" onclick={() => safe.refresh()}><Icon name="refresh-cw" />Try again</button></div>
            {#if safe.daemon.hint || safe.daemon.message}
              <details class="safe-details">
                <summary class="caption">Details</summary>
                <pre class="safe-detailtext">{[safe.daemon.message, safe.daemon.hint].filter(Boolean).join("\n")}</pre>
              </details>
            {/if}
          </div>
        </div>
      {:else if !safe.status}
        <div class="safe-stage" aria-busy="true">
          <div class="safe-col safe-col--narrow safe-col--center safe-center">
            <span class="ewe-spinner ewe-spinner--lg ewe-spinner--neutral" aria-hidden="true"></span>
            <div class="caption safe-muted" role="status">Opening ewe Safe…</div>
          </div>
        </div>
      {:else if ui.setup || !safe.setUp}
        <Setup />
      {:else if safe.locked}
        <Unlock />
      {:else}
        <Main />
      {/if}
      <Toasts />
    </main>
  </div>
{/if}
