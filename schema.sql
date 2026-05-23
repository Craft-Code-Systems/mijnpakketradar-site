-- schema.sql — PakketRadar waitlist D1 database
--
-- Run this once against your D1 database:
--   wrangler d1 execute pakketradar-waitlist --file=./schema.sql --remote
--
-- Or via the Cloudflare dashboard:
--   D1 > pakketradar-waitlist > Console > paste and execute

CREATE TABLE IF NOT EXISTS waitlist (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  email       TEXT NOT NULL UNIQUE,           -- lowercased, one entry per address
  ip_hash     TEXT NOT NULL,                  -- SHA-256 of (salt + IP), not raw IP
  user_agent  TEXT,                           -- for spam-pattern analysis only
  country     TEXT DEFAULT 'XX',              -- ISO country code from CF-IPCountry
  referer     TEXT,                           -- where the signup came from
  created_at  INTEGER NOT NULL,               -- unix timestamp (seconds)
  invited_at  INTEGER,                        -- set when we email the invite
  unsubscribed_at INTEGER                     -- set if user unsubscribes
);

-- Fast lookup for rate-limiting by IP hash
CREATE INDEX IF NOT EXISTS idx_waitlist_ip_time
  ON waitlist (ip_hash, created_at);

-- Fast lookup for "who hasn't been invited yet"
CREATE INDEX IF NOT EXISTS idx_waitlist_invited
  ON waitlist (invited_at)
  WHERE invited_at IS NULL;
