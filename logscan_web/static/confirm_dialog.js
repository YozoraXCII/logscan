window.ConfirmDialog = {
  show({ title = "Confirm action", message, confirmText = "Confirm" }) {
    return new Promise((resolve) => {
      const dialog = document.createElement("dialog");
      dialog.className = "confirm-dialog";
      const content = document.createElement("div");
      content.className = "confirm-dialog-content";
      const heading = document.createElement("h2");
      heading.textContent = title;
      const copy = document.createElement("p");
      copy.textContent = message;
      const actions = document.createElement("div");
      actions.className = "confirm-dialog-actions";
      const cancel = document.createElement("button");
      cancel.className = "secondary-button";
      cancel.type = "button";
      cancel.textContent = "Cancel";
      const confirm = document.createElement("button");
      confirm.className = "danger-button";
      confirm.type = "button";
      confirm.textContent = confirmText;
      cancel.addEventListener("click", () => dialog.close("cancel"));
      confirm.addEventListener("click", () => dialog.close("confirm"));
      dialog.addEventListener("cancel", (event) => { event.preventDefault(); dialog.close("cancel"); });
      dialog.addEventListener("close", () => { const approved = dialog.returnValue === "confirm"; dialog.remove(); resolve(approved); });
      actions.append(cancel, confirm);
      content.append(heading, copy, actions);
      dialog.append(content);
      document.body.append(dialog);
      dialog.showModal();
    });
  },
};
