<script>
  // Above the SSH keys: whether the agent serves them (TRIO.md S2). Off, it
  // offers Turn on (`ewe-safe ssh enable`); on but not reached by ssh, it
  // shows the one line for ~/.ssh/config, which Safe never edits itself.
  import Icon from "./Icon.svelte";
  import { safe } from "../safe.svelte.js";
  import { toasts } from "../toast.svelte.js";

  let st = $state(null);

  async function load() {
    const r = await safe.sshStatus();
    st = r?.ok ? r : null;
  }

  $effect(() => {
    void safe.changes;
    load();
  });

  async function turnOn() {
    const r = await safe.sshEnable();
    if (!r?.ok || !r.recorded) {
      toasts.show(r?.hint ?? r?.message ?? "Couldn't turn the agent on.", { icon: "circle-alert" });
    } else {
      toasts.show("The SSH agent is on. New sessions use it.", { icon: "circle-check" });
    }
    load();
  }

  async function copyLine() {
    try {
      await navigator.clipboard.writeText(st.identity_agent);
      toasts.show("Copied the line for ~/.ssh/config.", { icon: "clipboard-copy" });
    } catch {
      toasts.show(st.identity_agent, { icon: "info" });
    }
  }

  // another agent named in ~/.ssh/config wins over SSH_AUTH_SOCK
  const elsewhere = $derived((st?.ssh_config_agents ?? []).filter((a) => !a.endsWith("ewe-safe-ssh.sock")));
</script>

{#if st && !st.enabled}
  <div class="ewe-alert ewe-alert--info" role="status" style="margin:0 calc(var(--space-md) + var(--space-s)) var(--space-s)">
    <Icon name="terminal" />
    <div class="ewe-alert__body">
      <div class="ewe-alert__title">The SSH agent is off</div>
      <div class="ewe-alert__desc">Turn it on and ssh and git use these keys, asking you once per app before a key is used.</div>
    </div>
    <button class="ewe-btn ewe-btn--secondary ewe-btn--sm" disabled={safe.busy === "ssh-enable"} onclick={turnOn}>Turn on</button>
  </div>
{:else if st && (!st.points_here || elsewhere.length)}
  <div class="ewe-alert ewe-alert--warning" role="status" style="margin:0 calc(var(--space-md) + var(--space-s)) var(--space-s)">
    <Icon name="info" />
    <div class="ewe-alert__body">
      <div class="ewe-alert__title">{elsewhere.length ? "~/.ssh/config sends ssh to another agent" : "The agent is on for new sessions"}</div>
      <div class="ewe-alert__desc">
        {elsewhere.length ? `It names ${elsewhere[0]}. Put this line there instead:` : "For ssh now, put this line under Host * in ~/.ssh/config:"}
        <code class="mono">{st.identity_agent}</code>
      </div>
    </div>
    <button class="ewe-btn ewe-btn--secondary ewe-btn--sm" onclick={copyLine}><Icon name="copy" />Copy</button>
  </div>
{/if}
