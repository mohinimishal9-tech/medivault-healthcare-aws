(() => {
  const input = document.getElementById('plain');
  const ct = document.getElementById('out-ct');
  const edk = document.getElementById('out-edk');
  const kid = document.getElementById('out-kid');
  const note = document.getElementById('out-note');
  const token = document.querySelector('meta[name=csrf]').content;
  const base = note.textContent;
  let timer = null;
  let seq = 0;

  const clip = (s, n) => (s.length > n ? s.slice(0, n) + '…' : s);

  async function encrypt() {
    const mine = ++seq;
    const text = input.value;
    if (!text.trim()) {
      ct.textContent = edk.textContent = kid.textContent = '…';
      return;
    }
    try {
      const r = await fetch('/api/demo/encrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
        body: JSON.stringify({ text }),
      });
      const d = await r.json();
      if (mine !== seq) return;
      if (!r.ok) throw new Error(d.error || 'Could not encrypt.');
      ct.textContent = d.ciphertext;
      edk.textContent = clip(d.encrypted_data_key, 64);
      kid.textContent = d.key_id;
      note.textContent = base;
      note.classList.remove('err');
    } catch (e) {
      note.textContent = e.message;
      note.classList.add('err');
    }
  }

  input.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(encrypt, 250);
  });
  encrypt();
})();
