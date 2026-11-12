// static/js/main.js

document.addEventListener('DOMContentLoaded', () => {
  // 1) Redirect to /login if hitting a protected page without a token
  const token = localStorage.getItem('token');
  const path  = window.location.pathname;
  const needAuth = ['/dashboard','/encrypt','/decrypt','/share'];
  if (needAuth.includes(path) && !token) {
    window.location.href = '/login';
    return;
  }

  // 2) Logout button
  document.getElementById('logout-btn')?.addEventListener('click', e => {
    e.preventDefault();
    localStorage.removeItem('token');
    window.location.href = '/logout';
  });

  // 3) Drag-and-drop setup for any file-drop-area on the page
  document.querySelectorAll('.file-drop-area').forEach(area => {
    const input       = area.querySelector('input[type="file"]');
    const placeholder = area.querySelector('#file-placeholder');

    area.addEventListener('dragover', e => {
      e.preventDefault();
      area.classList.add('drag-over');
    });
    area.addEventListener('dragleave', () => {
      area.classList.remove('drag-over');
    });
    area.addEventListener('drop', e => {
      e.preventDefault();
      area.classList.remove('drag-over');
      const files = e.dataTransfer.files;
      if (files.length) {
        input.files = files;
        placeholder.innerText = files[0].name;
      }
    });
    area.addEventListener('click', () => input.click());
    input.addEventListener('change', () => {
      if (input.files.length) {
        placeholder.innerText = input.files[0].name;
      }
    });
  });

  // 4) Unified AJAX helper for login, signup, encrypt, decrypt, share
  async function ajaxForm(url, formEl, resultId) {
    const out = document.getElementById(resultId);
    out.innerText = '…working…';

    try {
      let opts;
      if (url === '/login' || url === '/signup') {
        // JSON body for auth
        opts = {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email:    formEl.email.value.trim(),
            password: formEl.password.value
          })
        };
      } else {
        // FormData + JWT header for file operations
        const fd = new FormData(formEl);
        opts = {
          method: 'POST',
          headers: { 'x-access-token': localStorage.getItem('token') },
          body: fd
        };
      }

      const res = await fetch(url, opts);
      if (res.ok && (url === '/encrypt' || url === '/decrypt')) {
        const uploadedName = formEl.querySelector('input[name="file"]').files[0].name;
        const fallback = url === '/encrypt' ? uploadedName + '.enc' : uploadedName.replace(/\.enc$/, '');
        const filename = res.headers.get('Content-Disposition')?.match(/filename="?([^";]+)"?/)?.[1] || fallback;
        const link = document.createElement('a');
        const objectUrl = URL.createObjectURL(await res.blob());
        link.href = objectUrl;
        link.download = filename;
        link.click();
        setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000);
        out.innerText = `Download ready: ${filename}`;
        return;
      }
      const data = await res.json();

      switch (url) {
        case '/login':
          if (data.success && data.token) {
            localStorage.setItem('token', data.token);
            window.location.href = '/dashboard';
          } else {
            out.innerText = data.message || 'Login failed';
          }
          break;

        case '/signup':
          out.innerText = data.success
            ? '✅ Account created! Please log in.'
            : data.message || 'Signup failed';
          break;

        case '/encrypt':
        case '/decrypt':
          out.innerText = data.message || 'File operation failed';
          break;

        case '/share':
          if (data.success) {
            const link = document.createElement('a');
            link.href = data.link;
            link.textContent = data.link;
            link.target = '_blank';
            link.rel = 'noopener noreferrer';
            out.replaceChildren('Share link: ', link);
          } else {
            out.innerText = data.message || 'Link generation failed';
          }
          break;
      }
    } catch (err) {
      console.error('AJAX error on', url, err);
      document.getElementById(resultId).innerText = 'Network error';
    }
  }

  // 5) Bind forms with inline validation
  const forms = [
    { id: 'login-form',   url: '/login',   result: 'login-msg'   },
    { id: 'signup-form',  url: '/signup',  result: 'signup-msg'  },
    { id: 'encrypt-form', url: '/encrypt', result: 'enc-result'  },
    { id: 'decrypt-form', url: '/decrypt', result: 'dec-result'  },
    { id: 'share-form',   url: '/share',   result: 'share-result'}
  ];

  forms.forEach(({ id, url, result }) => {
    const formEl = document.getElementById(id);
    if (!formEl) return;

    formEl.addEventListener('submit', e => {
      e.preventDefault();

      // Inline validation for file+password forms
      if (['encrypt-form','decrypt-form','share-form'].includes(id)) {
        const fileEl = formEl.querySelector('input[name="file"]');
        const pwdEl  = formEl.querySelector('input[name="password"]');
        if (!fileEl.files.length) {
          alert('Please select a file.');
          return;
        }
        if (!pwdEl.value.trim()) {
          alert('Please enter a password.');
          return;
        }
      }

      ajaxForm(url, formEl, result);
    });
  });
});
