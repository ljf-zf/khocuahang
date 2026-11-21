CREATE TABLE IF NOT EXISTS sapo_connection (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  alias TEXT NOT NULL,
  access_token_encrypted TEXT NOT NULL,
  connected_at TEXT NOT NULL,
  last_test_at TEXT,
  last_test_status TEXT,
  last_test_error TEXT
);
