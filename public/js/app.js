// Aplikacja Uwierzytelniania i RBAC (Wariant 5)

let currentUser = null;
let currentSessionTimeoutMinutes = 15;
let lastUserActivityTimestamp = Date.now();
let inactivityInterval = null;

// --- Inicjalizacja po załadowaniu DOM ---
document.addEventListener('DOMContentLoaded', () => {
  initEventListeners();
  loadTestAccounts();
  checkExistingSession();
});

// --- Zarządzanie sesją w sessionStorage ---
function getSessionToken() {
  return sessionStorage.getItem('session_token');
}

function setSessionToken(token) {
  if (token) {
    sessionStorage.setItem('session_token', token);
  } else {
    sessionStorage.removeItem('session_token');
  }
}

// --- Wrapper zapytań HTTP do API ---
async function apiFetch(url, options = {}) {
  const token = getSessionToken();
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {})
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  try {
    const response = await fetch(url, { ...options, headers });
    const data = await response.json();

    if (response.status === 401) {
      if (data.error === 'SESSION_EXPIRED') {
        handleSessionExpired('Sesja wygasła z powodu bezczynności.');
        throw new Error('Sesja wygasła z powodu bezczynności.');
      }
    }

    return { ok: response.ok, status: response.status, data };
  } catch (err) {
    throw err;
  }
}

// --- Weryfikacja istniejącej sesji ---
async function checkExistingSession() {
  const token = getSessionToken();
  if (!token) {
    showView('login');
    return;
  }

  try {
    const res = await apiFetch('/api/me');
    if (res.ok && res.data.success) {
      currentUser = res.data.user;
      currentSessionTimeoutMinutes = res.data.sessionTimeoutMinutes || 15;

      if (currentUser.mustChangePassword) {
        showView('firstLogin');
      } else {
        showView('app');
        setupAuthenticatedUI();
      }
    } else {
      setSessionToken(null);
      showView('login');
    }
  } catch (err) {
    setSessionToken(null);
    showView('login');
  }
}

// --- Obsługa widoków ---
function showView(viewName) {
  const loginSection = document.getElementById('loginSection');
  const firstLoginSection = document.getElementById('firstLoginSection');
  const appSection = document.getElementById('appSection');
  const userNav = document.getElementById('userNav');

  loginSection.classList.add('hidden');
  firstLoginSection.classList.add('hidden');
  appSection.classList.add('hidden');
  userNav.classList.add('hidden');

  if (viewName === 'login') {
    loginSection.classList.remove('hidden');
    stopInactivityTracking();
  } else if (viewName === 'firstLogin') {
    firstLoginSection.classList.remove('hidden');
    userNav.classList.remove('hidden');
    updateNavUserInfo();
    startInactivityTracking();
  } else if (viewName === 'app') {
    appSection.classList.remove('hidden');
    userNav.classList.remove('hidden');
    updateNavUserInfo();
    startInactivityTracking();
  }
}

// --- Wyświetlanie powiadomień ---
function showAlert(message, type = 'error', durationMs = 6000) {
  const alertEl = document.getElementById('globalAlert');
  alertEl.className = `alert alert-${type}`;
  alertEl.innerHTML = Array.isArray(message) ? message.join('<br>') : message;
  alertEl.classList.remove('hidden');

  if (durationMs > 0) {
    setTimeout(() => {
      alertEl.classList.add('hidden');
    }, durationMs);
  }
}

function clearAlert() {
  const alertEl = document.getElementById('globalAlert');
  alertEl.classList.add('hidden');
}

// --- Śledzenie bezczynności sesji ---
function resetActivity() {
  lastUserActivityTimestamp = Date.now();
}

function startInactivityTracking() {
  stopInactivityTracking();
  lastUserActivityTimestamp = Date.now();

  // Nasłuchiwanie zdarzeń aktywności użytkownika
  window.addEventListener('mousemove', resetActivity);
  window.addEventListener('keydown', resetActivity);
  window.addEventListener('click', resetActivity);
  window.addEventListener('scroll', resetActivity);

  inactivityInterval = setInterval(updateInactivityTimer, 1000);
  updateInactivityTimer();
}

function stopInactivityTracking() {
  if (inactivityInterval) {
    clearInterval(inactivityInterval);
    inactivityInterval = null;
  }
  window.removeEventListener('mousemove', resetActivity);
  window.removeEventListener('keydown', resetActivity);
  window.removeEventListener('click', resetActivity);
  window.removeEventListener('scroll', resetActivity);
}

function updateInactivityTimer() {
  const timerEl = document.getElementById('sessionTimer');
  if (!timerEl) return;

  const maxMs = currentSessionTimeoutMinutes * 60 * 1000;
  const elapsedMs = Date.now() - lastUserActivityTimestamp;
  const remainingMs = Math.max(0, maxMs - elapsedMs);

  const totalSeconds = Math.floor(remainingMs / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;

  timerEl.textContent = `Sesja: ${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;

  if (remainingMs <= 0) {
    handleSessionExpired('Sesja wygasła z powodu bezczynności.');
  }
}

async function handleSessionExpired(msg) {
  stopInactivityTracking();
  setSessionToken(null);
  currentUser = null;
  showView('login');
  showAlert(msg || 'Sesja wygasła z powodu bezczynności.', 'warning', 8000);
}

// --- Aktualizacja paska użytkownika ---
function updateNavUserInfo() {
  const infoEl = document.getElementById('navUserInfo');
  if (currentUser) {
    infoEl.innerHTML = `Zalogowano: <strong>${currentUser.username}</strong> (<span class="badge">${currentUser.role}</span>)`;
  }
}

// --- Rejestracja zdarzeń formularzy i zakładek ---
function initEventListeners() {
  // Formularz logowania
  document.getElementById('loginForm').addEventListener('submit', handleLogin);

  // Formularz pierwszego logowania
  document.getElementById('firstLoginForm').addEventListener('submit', handleFirstLogin);

  // Formularz zmiany hasła
  document.getElementById('changePasswordForm').addEventListener('submit', handleChangePassword);

  // Przycisk wylogowania
  document.getElementById('logoutBtn').addEventListener('click', handleLogout);

  // Zakładki
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const targetTab = e.target.getAttribute('data-tab');
      switchTab(targetTab);
    });
  });

  // Panel administratora: formularze
  document.getElementById('addUserForm').addEventListener('submit', handleAddUser);
  document.getElementById('policyForm').addEventListener('submit', handleUpdatePolicy);
  document.getElementById('btnResetDb').addEventListener('click', handleResetDatabase);

  // Przełączanie widoczności hasła (pokaż/ukryj)
  document.querySelectorAll('.btn-toggle-password').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-target');
      const input = document.getElementById(targetId);
      if (!input) return;

      if (input.type === 'password') {
        input.type = 'text';
        btn.textContent = 'Ukryj';
        btn.title = 'Ukryj hasło';
        btn.setAttribute('aria-label', 'Ukryj hasło');
      } else {
        input.type = 'password';
        btn.textContent = 'Pokaż';
        btn.title = 'Pokaż hasło';
        btn.setAttribute('aria-label', 'Pokaż hasło');
      }
    });
  });
}

// --- Obsługa logowania ---
async function handleLogin(e) {
  e.preventDefault();
  clearAlert();

  const username = document.getElementById('loginUsername').value.trim();
  const password = document.getElementById('loginPassword').value;

  try {
    const res = await apiFetch('/api/login', {
      method: 'POST',
      body: JSON.stringify({ username, password })
    });

    if (!res.ok) {
      showAlert(res.data.message || 'Login lub hasło niepoprawne', 'error');
      return;
    }

    setSessionToken(res.data.sessionId);
    currentUser = res.data.user;

    // Pobranie pełnych danych profilu i konfiguracji
    const meRes = await apiFetch('/api/me');
    if (meRes.ok) {
      currentUser = meRes.data.user;
      currentSessionTimeoutMinutes = meRes.data.sessionTimeoutMinutes || 15;
    }

    document.getElementById('loginForm').reset();

    if (currentUser.mustChangePassword) {
      showView('firstLogin');
    } else {
      showView('app');
      setupAuthenticatedUI();
    }
  } catch (err) {
    showAlert(err.message || 'Błąd połączenia z serwerem.', 'error');
  }
}

// --- Obsługa wylogowania ---
async function handleLogout() {
  try {
    await apiFetch('/api/logout', { method: 'POST' });
  } catch (err) {
    // Ignoruj błąd przy wylogowaniu
  }

  stopInactivityTracking();
  setSessionToken(null);
  currentUser = null;
  showView('login');
  showAlert('Zostałeś pomyślnie wylogowany.', 'success', 4000);
}

// --- Pierwsze logowanie (wymuszona zmiana hasła) ---
async function handleFirstLogin(e) {
  e.preventDefault();
  clearAlert();

  const newPassword = document.getElementById('firstNewPass').value;
  const confirmPassword = document.getElementById('firstConfirmPass').value;

  if (newPassword !== confirmPassword) {
    showAlert('Wprowadzone hasła nie są identyczne.', 'error');
    return;
  }

  try {
    const res = await apiFetch('/api/change-password', {
      method: 'POST',
      body: JSON.stringify({ newPassword, confirmPassword })
    });

    if (!res.ok) {
      showAlert(res.data.errors || 'Błąd zmiany hasła.', 'error');
      return;
    }

    showAlert('Hasło zostało pomyślnie zmienione! Witamy w systemie.', 'success', 5000);
    currentUser.mustChangePassword = false;
    document.getElementById('firstLoginForm').reset();

    showView('app');
    setupAuthenticatedUI();
  } catch (err) {
    showAlert(err.message || 'Błąd połączenia z serwerem.', 'error');
  }
}

// --- Regularna zmiana hasła ---
async function handleChangePassword(e) {
  e.preventDefault();
  clearAlert();

  const oldPassword = document.getElementById('changeOldPass').value;
  const newPassword = document.getElementById('changeNewPass').value;
  const confirmPassword = document.getElementById('changeConfirmPass').value;

  if (newPassword !== confirmPassword) {
    showAlert('Wprowadzone hasła nie są identyczne.', 'error');
    return;
  }

  try {
    const res = await apiFetch('/api/change-password', {
      method: 'POST',
      body: JSON.stringify({ oldPassword, newPassword, confirmPassword })
    });

    if (!res.ok) {
      showAlert(res.data.errors || 'Błąd zmiany hasła.', 'error');
      return;
    }

    showAlert('Hasło zostało pomyślnie zmienione.', 'success', 5000);
    document.getElementById('changePasswordForm').reset();
    loadProfileData();
  } catch (err) {
    showAlert(err.message || 'Błąd połączenia z serwerem.', 'error');
  }
}

// --- Konfiguracja UI po zalogowaniu na podstawie roli (RBAC) ---
function setupAuthenticatedUI() {
  if (!currentUser) return;

  const tabBtnAdmin = document.getElementById('tabBtnAdmin');
  const tabBtnEmployee = document.getElementById('tabBtnEmployee');
  const tabBtnGuest = document.getElementById('tabBtnGuest');

  // Widoczność zakładek w zależności od ról
  if (currentUser.role === 'Administrator') {
    tabBtnAdmin.classList.remove('hidden');
    tabBtnEmployee.classList.remove('hidden');
    tabBtnGuest.classList.remove('hidden');
  } else if (currentUser.role === 'Pracownik') {
    tabBtnAdmin.classList.add('hidden');
    tabBtnEmployee.classList.remove('hidden');
    tabBtnGuest.classList.remove('hidden');
  } else {
    // Gość
    tabBtnAdmin.classList.add('hidden');
    tabBtnEmployee.classList.add('hidden');
    tabBtnGuest.classList.remove('hidden');
  }

  // Przełączenie na domyślną zakładkę Profil
  switchTab('tabProfile');
  loadProfileData();

  if (currentUser.role === 'Administrator') {
    loadAdminData();
  }
}

// --- Przełączanie zakładek ---
function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-tab') === tabId);
  });

  document.querySelectorAll('.tab-content').forEach(content => {
    content.classList.toggle('hidden', content.id !== tabId);
    content.classList.toggle('active', content.id === tabId);
  });

  if (tabId === 'tabEmployee') {
    loadEmployeeData();
  } else if (tabId === 'tabGuest') {
    loadGuestData();
  } else if (tabId === 'tabAdmin') {
    loadAdminData();
  } else if (tabId === 'tabProfile') {
    loadProfileData();
  }
}

// --- Ładowanie danych profilu ---
async function loadProfileData() {
  try {
    const res = await apiFetch('/api/me');
    if (res.ok && res.data.success) {
      currentUser = res.data.user;
      currentSessionTimeoutMinutes = res.data.sessionTimeoutMinutes || 15;

      document.getElementById('profUsername').textContent = currentUser.username;
      
      const roleBadge = document.getElementById('profRole');
      roleBadge.textContent = currentUser.role;
      roleBadge.className = `badge badge-${currentUser.role.toLowerCase()}`;

      document.getElementById('profPassDate').textContent = currentUser.passwordChangedAt 
        ? new Date(currentUser.passwordChangedAt).toLocaleString() 
        : 'Brak danych';

      const permList = document.getElementById('profPermissionsList');
      permList.innerHTML = '';
      (currentUser.permissions || []).forEach(perm => {
        const li = document.createElement('li');
        li.textContent = perm;
        permList.appendChild(li);
      });
    }
  } catch (err) {
    console.error('Błąd profilu:', err);
  }
}

// --- Ładowanie strefy pracownika ---
async function loadEmployeeData() {
  const container = document.getElementById('employeeContent');
  container.innerHTML = '<p>Pobieranie danych strefy pracownika...</p>';

  try {
    const res = await apiFetch('/api/resources/employee/data');
    if (!res.ok) {
      container.innerHTML = `<div class="alert alert-error">Brak dostępu: ${res.data.message || 'Brak uprawnień'}</div>`;
      return;
    }

    const items = res.data.items || [];
    let html = `
      <div style="margin-top: 12px;">
        <p><strong>Status strefy:</strong> Autoryzacja pomyślna dla roli: <span class="badge badge-pracownik">${res.data.userRole}</span></p>
        <ul style="list-style: disc inside; margin-top: 10px;">
    `;
    items.forEach(it => {
      html += `<li><strong>${it.title}</strong> &mdash; <em>${it.status}</em></li>`;
    });
    html += '</ul></div>';
    container.innerHTML = html;
  } catch (err) {
    container.innerHTML = `<div class="alert alert-error">Błąd: ${err.message}</div>`;
  }
}

// --- Ładowanie strefy gościa ---
async function loadGuestData() {
  const container = document.getElementById('guestContent');
  container.innerHTML = '<p>Pobieranie ogłoszeń strefy gościa...</p>';

  try {
    const res = await apiFetch('/api/resources/guest/data');
    if (!res.ok) {
      container.innerHTML = `<div class="alert alert-error">Błąd: ${res.data.message || 'Brak uprawnień'}</div>`;
      return;
    }

    const announcements = res.data.announcements || [];
    let html = `
      <div style="margin-top: 12px;">
        <p><strong>Status strefy:</strong> Dostęp publiczny dla użytkowników uwierzytelnionych.</p>
        <div style="margin-top: 12px;">
    `;
    announcements.forEach(a => {
      html += `
        <div style="background: #f8fafc; border-left: 3px solid #38bdf8; padding: 8px 12px; margin-bottom: 8px;">
          <small style="color: #64748b;">${a.date}</small>
          <p>${a.text}</p>
        </div>
      `;
    });
    html += '</div></div>';
    container.innerHTML = html;
  } catch (err) {
    container.innerHTML = `<div class="alert alert-error">Błąd: ${err.message}</div>`;
  }
}

// --- Panel Administratora: Ładowanie danych ---
async function loadAdminData() {
  await Promise.all([loadAdminUsers(), loadAdminPolicy()]);
}

async function loadAdminUsers() {
  const tbody = document.getElementById('adminUsersTbody');
  tbody.innerHTML = '<tr><td colspan="6">Pobieranie użytkowników...</td></tr>';

  try {
    const res = await apiFetch('/api/admin/users');
    if (!res.ok) {
      tbody.innerHTML = `<tr><td colspan="6" class="alert alert-error">${res.data.message || 'Błąd'}</td></tr>`;
      return;
    }

    tbody.innerHTML = '';
    const users = res.data.users || [];

    users.forEach(u => {
      const tr = document.createElement('tr');

      const isMe = currentUser && currentUser.id === u.id;
      const isPermanentAdmin = !!u.isPermanentAdmin;

      let tempExpText = '-';
      if (u.mustChangePassword && u.temporaryPasswordExpiresAt) {
        const expDate = new Date(u.temporaryPasswordExpiresAt);
        const isExpired = Date.now() > expDate.getTime();
        tempExpText = isExpired 
          ? `<span style="color: #dc2626; font-weight: bold;">Wygasło (${expDate.toLocaleTimeString()})</span>`
          : expDate.toLocaleString();
      }

      tr.innerHTML = `
        <td><strong>${u.username}</strong> ${isPermanentAdmin ? '<span class="badge" title="Stałe konto">ADMIN</span>' : ''}</td>
        <td>
          <select class="admin-role-select form-group" data-id="${u.id}" ${isPermanentAdmin ? 'disabled' : ''}>
            <option value="Administrator" ${u.role === 'Administrator' ? 'selected' : ''}>Administrator</option>
            <option value="Pracownik" ${u.role === 'Pracownik' ? 'selected' : ''}>Pracownik</option>
            <option value="Gość" ${u.role === 'Gość' ? 'selected' : ''}>Gość</option>
          </select>
        </td>
        <td>
          <span class="badge ${u.isBlocked ? 'badge-blocked' : 'badge-active'}">
            ${u.isBlocked ? 'Zablokowany' : 'Aktywny'}
          </span>
        </td>
        <td>${u.mustChangePassword ? '<span style="color:#d97706; font-weight:600;">Tak</span>' : 'Nie'}</td>
        <td><small>${tempExpText}</small></td>
        <td>
          <div class="table-actions">
            ${!isPermanentAdmin ? `
              <button class="btn btn-sm ${u.isBlocked ? 'btn-secondary' : 'btn-danger'} btn-block-user" data-id="${u.id}">
                ${u.isBlocked ? 'Odblokuj' : 'Blokuj'}
              </button>
              <button class="btn btn-sm btn-secondary btn-reset-user" data-id="${u.id}" title="Nadaj nowe hasło jednorazowe 14-znakowe">
                Reset hasła
              </button>
              <button class="btn btn-sm btn-danger btn-delete-user" data-id="${u.id}">
                Usuń
              </button>
            ` : '<em>Stały administrator</em>'}
          </div>
        </td>
      `;

      tbody.appendChild(tr);
    });

    // Podpięcie zdarzeń przycisków w tabeli
    tbody.querySelectorAll('.admin-role-select').forEach(sel => {
      sel.addEventListener('change', handleRoleChange);
    });
    tbody.querySelectorAll('.btn-block-user').forEach(btn => {
      btn.addEventListener('click', handleBlockToggle);
    });
    tbody.querySelectorAll('.btn-reset-user').forEach(btn => {
      btn.addEventListener('click', handleResetPasswordModal);
    });
    tbody.querySelectorAll('.btn-delete-user').forEach(btn => {
      btn.addEventListener('click', handleDeleteUser);
    });

  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" class="alert alert-error">${err.message}</td></tr>`;
  }
}

async function handleRoleChange(e) {
  const userId = e.target.getAttribute('data-id');
  const newRole = e.target.value;

  try {
    const res = await apiFetch(`/api/admin/users/${userId}/role`, {
      method: 'PUT',
      body: JSON.stringify({ role: newRole })
    });

    if (!res.ok) {
      showAlert(res.data.message || 'Błąd zmiany roli', 'error');
      loadAdminUsers();
      return;
    }

    showAlert(`Zaktualizowano rolę użytkownika na: ${newRole}`, 'success', 3000);
  } catch (err) {
    showAlert(err.message, 'error');
  }
}

async function handleBlockToggle(e) {
  const userId = e.target.getAttribute('data-id');

  try {
    const res = await apiFetch(`/api/admin/users/${userId}/block`, {
      method: 'PUT'
    });

    if (!res.ok) {
      showAlert(res.data.message || 'Błąd zmiany blokady', 'error');
      return;
    }

    showAlert(res.data.message, 'success', 3000);
    loadAdminUsers();
  } catch (err) {
    showAlert(err.message, 'error');
  }
}

async function handleResetPasswordModal(e) {
  const userId = e.target.getAttribute('data-id');
  if (!confirm('Czy na pewno chcesz wygenerować nowe hasło jednorazowe dla tego użytkownika? Dotychczasowe hasło i sesje zostaną unieważnione.')) {
    return;
  }

  try {
    const res = await apiFetch(`/api/admin/users/${userId}/reset-password`, {
      method: 'POST'
    });

    if (!res.ok) {
      showAlert(res.data.message || 'Błąd generowania hasła', 'error');
      return;
    }

    const alertBox = document.getElementById('newPasswordAlert');
    alertBox.innerHTML = `
      <strong>Wygenerowano hasło jednorazowe (Wariant 5):</strong><br>
      Kod: <code style="font-size: 1.1rem; background: #fff; padding: 2px 6px; border: 1px solid #cbd5e1; border-radius: 4px;">${res.data.temporaryPassword}</code> (14 znaków)<br>
      Ważne przez: 24 godziny (do ${new Date(res.data.expiresAt).toLocaleString()})<br>
      <small>Przekaż to hasło użytkownikowi. Przy logowaniu zostanie wymuszona zmiana hasła.</small>
    `;
    alertBox.classList.remove('hidden');

    loadAdminUsers();
  } catch (err) {
    showAlert(err.message, 'error');
  }
}

async function handleDeleteUser(e) {
  const userId = e.target.getAttribute('data-id');
  if (!confirm('Czy na pewno chcesz usunąć tego użytkownika?')) {
    return;
  }

  try {
    const res = await apiFetch(`/api/admin/users/${userId}`, {
      method: 'DELETE'
    });

    if (!res.ok) {
      showAlert(res.data.message || 'Błąd usuwania użytkownika', 'error');
      return;
    }

    showAlert('Użytkownik został usunięty.', 'success', 3000);
    loadAdminUsers();
  } catch (err) {
    showAlert(err.message, 'error');
  }
}

async function handleAddUser(e) {
  e.preventDefault();
  const username = document.getElementById('newUsername').value.trim();
  const role = document.getElementById('newUserRole').value;

  try {
    const res = await apiFetch('/api/admin/users', {
      method: 'POST',
      body: JSON.stringify({ username, role })
    });

    if (!res.ok) {
      showAlert(res.data.message || 'Błąd dodawania użytkownika', 'error');
      return;
    }

    document.getElementById('addUserForm').reset();

    const alertBox = document.getElementById('newPasswordAlert');
    alertBox.innerHTML = `
      <strong>Utworzono użytkownika ${res.data.user.username}!</strong><br>
      Hasło jednorazowe (14 znaków alfanumerycznych): <code style="font-size: 1.1rem; background: #fff; padding: 2px 6px; border: 1px solid #cbd5e1; border-radius: 4px;">${res.data.temporaryPassword}</code><br>
      Ważność: 24 godziny (do ${new Date(res.data.user.temporaryPasswordExpiresAt).toLocaleString()})<br>
      <small>Użytkownik przy pierwszym logowaniu będzie musiał ustanowić własne nowe hasło.</small>
    `;
    alertBox.classList.remove('hidden');

    loadAdminUsers();
  } catch (err) {
    showAlert(err.message, 'error');
  }
}

// --- Ładowanie i zapis konfiguracji polityki ---
async function loadAdminPolicy() {
  try {
    const res = await apiFetch('/api/admin/policy');
    if (res.ok && res.data.config) {
      const cfg = res.data.config;
      document.getElementById('cfgMinLength').value = cfg.minPasswordLength || 12;
      document.getElementById('cfgTimeout').value = cfg.sessionInactivityTimeoutMinutes || 15;
      document.getElementById('cfgValidity').value = cfg.passwordValidityDays || 90;
      document.getElementById('cfgHibp').checked = !!cfg.checkHaveIBeenPwned;
    }
  } catch (err) {
    console.error('Błąd pobierania polityki:', err);
  }
}

async function handleUpdatePolicy(e) {
  e.preventDefault();

  const minPasswordLength = parseInt(document.getElementById('cfgMinLength').value, 10);
  const sessionInactivityTimeoutMinutes = parseInt(document.getElementById('cfgTimeout').value, 10);
  const passwordValidityDays = parseInt(document.getElementById('cfgValidity').value, 10);
  const checkHaveIBeenPwned = document.getElementById('cfgHibp').checked;

  try {
    const res = await apiFetch('/api/admin/policy', {
      method: 'PUT',
      body: JSON.stringify({
        minPasswordLength,
        sessionInactivityTimeoutMinutes,
        passwordValidityDays,
        checkHaveIBeenPwned
      })
    });

    if (!res.ok) {
      showAlert(res.data.message || 'Błąd zapisu polityki', 'error');
      return;
    }

    currentSessionTimeoutMinutes = sessionInactivityTimeoutMinutes;
    showAlert('Ustawienia polityki bezpieczeństwa zostały pomyślnie zaktualizowane.', 'success', 4000);
  } catch (err) {
    showAlert(err.message, 'error');
  }
}

async function handleResetDatabase() {
  if (!confirm('Czy na pewno chcesz zresetować bazę danych do 6 kont testowych?')) {
    return;
  }

  try {
    const res = await apiFetch('/api/admin/reset-database', { method: 'POST' });
    if (res.ok) {
      showAlert('Baza została zresetowana do 6 kont testowych.', 'success', 3000);
      loadAdminUsers();
      loadTestAccounts();
    }
  } catch (err) {
    showAlert(err.message, 'error');
  }
}

// --- Ładowanie ściągawki z 6 kontami testowymi na ekranie logowania ---
async function loadTestAccounts() {
  const tbody = document.getElementById('testAccountsTbody');
  if (!tbody) return;

  try {
    const res = await fetch('/api/test-accounts');
    const data = await res.json();

    tbody.innerHTML = '';
    (data.accounts || []).forEach(acc => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>${acc.username}</strong></td>
        <td><code>${acc.password}</code></td>
        <td><span class="badge badge-${acc.role.toLowerCase()}">${acc.role}</span></td>
        <td>
          <button class="btn btn-secondary btn-sm btn-fill-login" data-user="${acc.username}" data-pass="${acc.password}">
            Użyj
          </button>
        </td>
      `;
      tbody.appendChild(tr);
    });

    tbody.querySelectorAll('.btn-fill-login').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const u = e.currentTarget.getAttribute('data-user');
        const p = e.currentTarget.getAttribute('data-pass');
        document.getElementById('loginUsername').value = u;
        document.getElementById('loginPassword').value = p;
      });
    });
  } catch (err) {
    console.error('Błąd ładowania kont testowych:', err);
  }
}
