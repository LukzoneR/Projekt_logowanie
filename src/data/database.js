const fs = require('fs');
const path = require('path');
const { DEFAULT_CONFIG } = require('../config/config');
const { getInitialSeedData } = require('./seedData');

const DB_PATH = path.join(__dirname, 'db.json');

class Database {
  constructor() {
    this.init();
  }

  init() {
    if (!fs.existsSync(DB_PATH)) {
      const initial = getInitialSeedData();
      const initialData = {
        config: { ...DEFAULT_CONFIG },
        users: initial.users
      };
      this._save(initialData);
    }
  }

  _read() {
    try {
      const data = fs.readFileSync(DB_PATH, 'utf-8');
      return JSON.parse(data);
    } catch (err) {
      console.error('Błąd odczytu bazy danych, reinicjalizacja:', err);
      const initial = getInitialSeedData();
      const initialData = {
        config: { ...DEFAULT_CONFIG },
        users: initial.users
      };
      this._save(initialData);
      return initialData;
    }
  }

  _save(data) {
    fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf-8');
  }

  // --- Konfiguracja / Polityka ---
  getConfig() {
    const data = this._read();
    return data.config || { ...DEFAULT_CONFIG };
  }

  updateConfig(updates) {
    const data = this._read();
    data.config = {
      ...data.config,
      ...updates
    };
    this._save(data);
    return data.config;
  }

  // --- Użytkownicy ---
  getUsers() {
    const data = this._read();
    return data.users || [];
  }

  getUserById(id) {
    const users = this.getUsers();
    return users.find(u => u.id === id) || null;
  }

  getUserByUsername(username) {
    const users = this.getUsers();
    if (!username) return null;
    return users.find(u => u.username.toLowerCase() === username.toLowerCase()) || null;
  }

  createUser(userData) {
    const data = this._read();
    const newUser = {
      id: 'usr_' + Date.now() + '_' + Math.random().toString(36).substr(2, 5),
      createdAt: new Date().toISOString(),
      passwordChangedAt: new Date().toISOString(),
      isPermanentAdmin: false,
      isBlocked: false,
      ...userData
    };
    data.users.push(newUser);
    this._save(data);
    return newUser;
  }

  updateUser(id, updates) {
    const data = this._read();
    const index = data.users.findIndex(u => u.id === id);
    if (index === -1) return null;

    data.users[index] = {
      ...data.users[index],
      ...updates
    };
    this._save(data);
    return data.users[index];
  }

  deleteUser(id) {
    const data = this._read();
    const user = data.users.find(u => u.id === id);
    if (!user) return false;
    if (user.isPermanentAdmin) {
      throw new Error('Nie można usunąć stałego konta administratora.');
    }
    data.users = data.users.filter(u => u.id !== id);
    this._save(data);
    return true;
  }

  /**
   * Resetuje bazę do stanu początkowego (przydatne do testów)
   */
  resetToInitial() {
    const initial = getInitialSeedData();
    const initialData = {
      config: { ...DEFAULT_CONFIG },
      users: initial.users
    };
    this._save(initialData);
    return initialData;
  }
}

const db = new Database();
module.exports = db;
