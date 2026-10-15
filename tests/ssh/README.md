# SSH key fixtures

`KeeAgent.settings` is the XML KeePassXC writes for an SSH key kept in an
entry's attachment `id_ed25519`, with *Add key to agent when database is
opened* and *Remove key from agent when database is closed* checked (the
switches Safe sets). It is written from KeePassXC's own writer,
`KeeAgentSettings::toXml()` in `src/sshagent/KeeAgentSettings.cpp`
(keepassxreboot/keepassxc at `52e2743b3a77`): a `QXmlStreamWriter` with
auto-formatting and an indent of 2, UTF-8, empty elements as `<Name/>`, a
newline at the end. No KeePassXC binary was available to save one, so a file
from a real KeePassXC is still to be added (docs/FORMAT.md, "SSH keys").

No private key is kept here: the tests make their keys when they run.
