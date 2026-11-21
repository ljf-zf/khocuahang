CREATE TABLE IF NOT EXISTS sapo_extension_orders (
  order_key TEXT PRIMARY KEY,
  order_id TEXT NOT NULL,
  order_number TEXT NOT NULL,
  connection_id TEXT,
  channel TEXT,
  channel_order_status TEXT,
  sapo_order_status TEXT,
  status TEXT,
  classification TEXT NOT NULL,
  cancellation_explicit INTEGER NOT NULL DEFAULT 0,
  created_at TEXT,
  source_updated_at TEXT,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  last_changed_at TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  phase TEXT NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sapo_extension_orders_last_seen ON sapo_extension_orders(last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_sapo_extension_orders_classification ON sapo_extension_orders(classification, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS sapo_extension_events (
  event_id TEXT PRIMARY KEY,
  order_key TEXT NOT NULL,
  event_type TEXT NOT NULL,
  classification TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sapo_extension_events_order ON sapo_extension_events(order_key, observed_at DESC);

CREATE TABLE IF NOT EXISTS sapo_extension_agents (
  agent_id TEXT PRIMARY KEY,
  device_label TEXT,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  last_poll_at TEXT NOT NULL,
  last_error TEXT,
  last_received_count INTEGER NOT NULL DEFAULT 0,
  last_changed_count INTEGER NOT NULL DEFAULT 0,
  baseline_complete INTEGER NOT NULL DEFAULT 0
);
