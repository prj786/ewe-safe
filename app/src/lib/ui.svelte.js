// What the window shows: the view, the side navigation's filter, the
// selected item, the search text, an open editor. Only the screens change
// it; nothing here is ever a secret.

class Ui {
  // "items" | "settings" | "import"
  view = $state("items");
  // the side navigation: kind "login"/"note"/"ssh-key"/"card"/"address", a
  // tag, a folder, or the trash
  filter = $state({ kind: "", tag: "", folder: "", trash: false });
  selected = $state(null);
  query = $state("");
  // null, or {mode: "new" | "edit", id?, kind}; a new "ssh-key" is
  // SshKeyNew (make one, or add a file)
  editing = $state(null);
  // the Emergency Kit over the window (from Settings)
  kit = $state(false);
  // a safe is being created: stay on the setup screens until the Emergency
  // Kit is done, though the daemon already says set_up
  setup = $state(false);
  // where the setup screens start (the dev mock's ?step=)
  setupStep = null;
  // the generator starts open in the next editor (the dev mock's ?gen=1)
  genOpen = false;

  go(view) {
    this.view = view;
    this.editing = null;
  }

  pick(filter) {
    this.filter = { kind: "", tag: "", folder: "", trash: false, ...filter };
    this.view = "items";
    this.editing = null;
    this.selected = null;
  }

  isFilter(f) {
    const cur = this.filter;
    return (
      this.view === "items" &&
      (f.kind ?? "") === cur.kind &&
      (f.tag ?? "") === cur.tag &&
      (f.folder ?? "") === cur.folder &&
      (f.trash ?? false) === cur.trash
    );
  }
}

export const ui = new Ui();
