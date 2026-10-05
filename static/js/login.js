document.querySelectorAll('.accounts button').forEach((b) => {
  b.addEventListener('click', () => {
    document.getElementById('username').value = b.dataset.user;
    document.getElementById('password').value = b.dataset.pass;
    document.querySelector('form button[type=submit]').focus();
  });
});
