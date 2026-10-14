// Toasts (the Toast card): one line, an optional timer bar, gone after
// `ms`. "Copied the password. It clears in 30 s." is the main one.

let next = 1;

class Toasts {
  list = $state([]);

  show(text, { icon = "info", ms = 4000, timer = false } = {}) {
    const id = next++;
    this.list = [...this.list, { id, text, icon, ms, timer }];
    setTimeout(() => this.close(id), ms);
    return id;
  }

  close(id) {
    this.list = this.list.filter((t) => t.id !== id);
  }
}

export const toasts = new Toasts();
