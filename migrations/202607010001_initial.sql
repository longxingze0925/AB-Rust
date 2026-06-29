CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  user_agent TEXT NOT NULL DEFAULT '',
  ip INET,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE routes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL DEFAULT '',
  entry_domain TEXT NOT NULL UNIQUE,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE route_targets (
  route_id UUID PRIMARY KEY REFERENCES routes(id) ON DELETE CASCADE,
  target_type TEXT NOT NULL DEFAULT 'internal' CHECK (target_type IN ('internal', 'external')),
  exit_domain TEXT UNIQUE,
  external_url TEXT NOT NULL DEFAULT '',
  transfer_token_ttl_seconds INTEGER NOT NULL DEFAULT 120,
  CHECK (
    (target_type = 'internal' AND exit_domain IS NOT NULL AND external_url = '')
    OR
    (target_type = 'external' AND exit_domain IS NULL AND external_url <> '')
  )
);

CREATE TABLE landing_templates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  storage_key TEXT NOT NULL UNIQUE,
  entry_file TEXT NOT NULL DEFAULT 'index.html',
  file_count INTEGER NOT NULL DEFAULT 0,
  size_bytes BIGINT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE assets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  original_name TEXT NOT NULL,
  storage_path TEXT NOT NULL UNIQUE,
  mime_type TEXT NOT NULL DEFAULT '',
  size_bytes BIGINT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE route_landing_configs (
  route_id UUID PRIMARY KEY REFERENCES routes(id) ON DELETE CASCADE,
  landing_mode TEXT NOT NULL DEFAULT 'default' CHECK (landing_mode IN ('default', 'template')),
  template_id UUID REFERENCES landing_templates(id) ON DELETE SET NULL,
  title TEXT NOT NULL DEFAULT '下载',
  image_asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
  apk_url TEXT NOT NULL DEFAULT '',
  auto_download BOOLEAN NOT NULL DEFAULT TRUE,
  CHECK (
    (landing_mode = 'default' AND template_id IS NULL)
    OR
    (landing_mode = 'template' AND template_id IS NOT NULL)
  )
);

CREATE TABLE route_cloak_configs (
  route_id UUID PRIMARY KEY REFERENCES routes(id) ON DELETE CASCADE,
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  threshold INTEGER NOT NULL DEFAULT 8,
  token_hours INTEGER NOT NULL DEFAULT 6,
  decoy_title TEXT NOT NULL DEFAULT '下载',
  decoy_image_asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
  decoy_apk_url TEXT NOT NULL DEFAULT ''
);

CREATE TABLE route_meta_configs (
  route_id UUID PRIMARY KEY REFERENCES routes(id) ON DELETE CASCADE,
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  pixel_id TEXT NOT NULL DEFAULT '',
  capi_token TEXT NOT NULL DEFAULT '',
  test_event_code TEXT NOT NULL DEFAULT '',
  currency TEXT NOT NULL DEFAULT 'USD',
  value NUMERIC(12, 2) NOT NULL DEFAULT 0,
  page_view_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  view_content_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  lead_enabled BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE promo_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  route_id UUID NOT NULL REFERENCES routes(id) ON DELETE CASCADE,
  code TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  apk_url TEXT,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (route_id, code)
);

CREATE TABLE visits (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  route_id UUID REFERENCES routes(id) ON DELETE SET NULL,
  promo_id UUID REFERENCES promo_codes(id) ON DELETE SET NULL,
  promo_code TEXT NOT NULL DEFAULT '',
  page_variant TEXT NOT NULL DEFAULT 'unknown' CHECK (page_variant IN ('real', 'fake', 'probe', 'unknown')),
  cloak_reason TEXT NOT NULL DEFAULT '',
  entry_domain TEXT NOT NULL DEFAULT '',
  exit_domain TEXT NOT NULL DEFAULT '',
  ip INET,
  ip_source TEXT NOT NULL DEFAULT '',
  cf_ray TEXT NOT NULL DEFAULT '',
  country TEXT NOT NULL DEFAULT '',
  province TEXT NOT NULL DEFAULT '',
  city TEXT NOT NULL DEFAULT '',
  isp TEXT NOT NULL DEFAULT '',
  os TEXT NOT NULL DEFAULT '',
  os_version TEXT NOT NULL DEFAULT '',
  device TEXT NOT NULL DEFAULT '',
  browser TEXT NOT NULL DEFAULT '',
  language TEXT NOT NULL DEFAULT '',
  referer TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE visit_client_updates (
  visit_id UUID PRIMARY KEY REFERENCES visits(id) ON DELETE CASCADE,
  screen TEXT NOT NULL DEFAULT '',
  timezone TEXT NOT NULL DEFAULT '',
  network TEXT NOT NULL DEFAULT '',
  fingerprint TEXT NOT NULL DEFAULT '',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE download_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  route_id UUID REFERENCES routes(id) ON DELETE SET NULL,
  visit_id UUID REFERENCES visits(id) ON DELETE SET NULL,
  promo_id UUID REFERENCES promo_codes(id) ON DELETE SET NULL,
  event_id TEXT NOT NULL DEFAULT '',
  apk_url TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ip_blacklist (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cidr CIDR NOT NULL UNIQUE,
  note TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE domain_allowlist (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain TEXT NOT NULL UNIQUE,
  source TEXT NOT NULL DEFAULT 'manual',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE settings (
  key TEXT PRIMARY KEY,
  value JSONB NOT NULL DEFAULT 'null'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL DEFAULT '',
  entity_id UUID,
  detail JSONB NOT NULL DEFAULT '{}'::jsonb,
  ip INET,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_routes_enabled ON routes(enabled);
CREATE INDEX idx_route_targets_exit_domain ON route_targets(exit_domain);
CREATE INDEX idx_promo_codes_route ON promo_codes(route_id);
CREATE INDEX idx_visits_route_created ON visits(route_id, created_at DESC);
CREATE INDEX idx_visits_promo_code ON visits(promo_code);
CREATE INDEX idx_visits_created ON visits(created_at DESC);
CREATE INDEX idx_visit_client_fingerprint ON visit_client_updates(fingerprint);
CREATE INDEX idx_download_events_route_created ON download_events(route_id, created_at DESC);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at DESC);
