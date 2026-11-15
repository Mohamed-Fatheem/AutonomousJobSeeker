// Keep drafts within this browser tab and account. Never store passwords or files.
(() => {
  const account = document.body.dataset.account;
  if (!account) return;
  const prefix = `ajs:${account}:`;
  let submitting = false;
  document.addEventListener('submit', () => { submitting = true; });
  window.addEventListener('beforeunload', event => {
    if (!submitting && [...document.querySelectorAll('input[type=password]')].some(el => el.value)) {
      event.preventDefault(); event.returnValue = '';
    }
  });
  const read = key => { try { return JSON.parse(sessionStorage.getItem(key)); } catch { return null; } };
  const write = (key, value) => { try { sessionStorage.setItem(key, JSON.stringify(value)); } catch {} };
  const remove = key => { try { sessionStorage.removeItem(key); } catch {} };
  const pending = read(prefix + 'pending');
  if (pending && document.querySelector('.flash.ok')) remove(pending);
  remove(prefix + 'pending');
  document.querySelectorAll('form[method="post"]').forEach(form => {
    const fields = [...form.elements].filter(el => el.name && el.name !== 'confirm' && !['hidden','password','file','submit'].includes(el.type));
    if (!fields.length) return;
    const key = prefix + new URL(form.action).pathname;
    const snapshot = () => fields.map(el => ({value: el.value, checked: el.checked}));
    const original = JSON.stringify(snapshot());
    const draft = read(key);
    if (Array.isArray(draft) && draft.length === fields.length) fields.forEach((el, i) => {
      el.value = draft[i].value;
      if (['checkbox','radio'].includes(el.type)) el.checked = draft[i].checked;
    });
    const save = [...form.querySelectorAll('button')].find(button => /^save\b/i.test(button.textContent.trim()));
    const status = document.createElement('p');
    status.className = 'draft-status'; status.setAttribute('role','status');
    if (save) save.before(status);
    const dirty = () => JSON.stringify(snapshot()) !== original || [...form.querySelectorAll('input[type=password]')].some(el => el.value);
    const update = () => {
      const changed = dirty();
      if (save) save.disabled = !changed;
      const hasKey = [...form.querySelectorAll('input[type=password]')].some(el => el.value);
      status.textContent = hasKey ? 'Unsaved key · save before leaving; keys are not kept in browser drafts' : changed ? 'Unsaved changes · kept in this browser tab' : 'No unsaved changes';
      if (changed) write(key, snapshot()); else remove(key);
    };
    form.addEventListener('input', update); form.addEventListener('change', update);
    form.addEventListener('submit', () => { write(key, snapshot()); write(prefix + 'pending', key); });
    update();
  });
  document.querySelector('form[action="/logout"]')?.addEventListener('submit', () => {
    Object.keys(sessionStorage).filter(key => key.startsWith(prefix)).forEach(remove);
  });
})();
