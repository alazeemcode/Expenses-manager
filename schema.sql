-- Users table
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User profiles
CREATE TABLE IF NOT EXISTS user_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL UNIQUE,
  salary REAL NOT NULL DEFAULT 0,
  savings_target REAL NOT NULL DEFAULT 0,
  currency TEXT NOT NULL DEFAULT '₹',
  FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Categories table
CREATE TABLE IF NOT EXISTS categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  user_id INTEGER, -- NULL for default categories
  UNIQUE(name, user_id),
  FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Expenses table
CREATE TABLE IF NOT EXISTS expenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  amount REAL NOT NULL,
  category_id INTEGER NOT NULL,
  date TEXT NOT NULL,
  note TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users (id),
  FOREIGN KEY (category_id) REFERENCES categories (id)
);

-- Incomes table
CREATE TABLE IF NOT EXISTS incomes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  amount REAL NOT NULL,
  date TEXT NOT NULL,
  source TEXT,
  note TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Insert default categories
INSERT OR IGNORE INTO categories (name) VALUES ('Food');
INSERT OR IGNORE INTO categories (name) VALUES ('Transportation');
INSERT OR IGNORE INTO categories (name) VALUES ('Housing');
INSERT OR IGNORE INTO categories (name) VALUES ('Utilities');
INSERT OR IGNORE INTO categories (name) VALUES ('Entertainment');
INSERT OR IGNORE INTO categories (name) VALUES ('Shopping');
INSERT OR IGNORE INTO categories (name) VALUES ('Health');
INSERT OR IGNORE INTO categories (name) VALUES ('Education');
INSERT OR IGNORE INTO categories (name) VALUES ('Travel');
INSERT OR IGNORE INTO categories (name) VALUES ('Other');
