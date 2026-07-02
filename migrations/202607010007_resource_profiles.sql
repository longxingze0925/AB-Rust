CREATE TABLE domains (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL DEFAULT 'entry' CHECK (role IN ('entry', 'exit')),
  note TEXT NOT NULL DEFAULT '',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE landing_profiles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  landing_mode TEXT NOT NULL DEFAULT 'default' CHECK (landing_mode IN ('default', 'template')),
  template_id UUID REFERENCES landing_templates(id) ON DELETE SET NULL,
  image_asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
  title TEXT NOT NULL DEFAULT '下载',
  apk_url TEXT NOT NULL DEFAULT '',
  auto_download BOOLEAN NOT NULL DEFAULT TRUE,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (
    (landing_mode = 'default' AND template_id IS NULL)
    OR
    (landing_mode = 'template' AND template_id IS NOT NULL)
  )
);

CREATE TABLE cloak_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL UNIQUE,
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  threshold INTEGER NOT NULL DEFAULT 8,
  token_hours INTEGER NOT NULL DEFAULT 6,
  decoy_title TEXT NOT NULL DEFAULT '下载',
  decoy_image_asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
  decoy_apk_url TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE meta_profiles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL UNIQUE,
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  pixel_id TEXT NOT NULL DEFAULT '',
  capi_token TEXT NOT NULL DEFAULT '',
  test_event_code TEXT NOT NULL DEFAULT '',
  currency TEXT NOT NULL DEFAULT 'USD',
  value NUMERIC(12, 2) NOT NULL DEFAULT 0,
  page_view_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  view_content_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  lead_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE route_targets
  ADD COLUMN exit_domain_id UUID REFERENCES domains(id) ON DELETE SET NULL;

ALTER TABLE route_landing_configs
  ADD COLUMN landing_profile_id UUID REFERENCES landing_profiles(id) ON DELETE SET NULL;

ALTER TABLE route_cloak_configs
  ADD COLUMN cloak_policy_id UUID REFERENCES cloak_policies(id) ON DELETE SET NULL;

ALTER TABLE route_meta_configs
  ADD COLUMN meta_profile_id UUID REFERENCES meta_profiles(id) ON DELETE SET NULL;

INSERT INTO domains (domain, role, note, enabled)
SELECT entry_domain, 'entry', '由现有线路迁移', enabled
FROM routes
ON CONFLICT (domain) DO UPDATE
SET role = 'entry',
    enabled = domains.enabled OR EXCLUDED.enabled,
    updated_at = now();

INSERT INTO domains (domain, role, note, enabled)
SELECT exit_domain, 'exit', '由现有出口域名迁移', TRUE
FROM route_targets
WHERE exit_domain IS NOT NULL AND exit_domain <> ''
ON CONFLICT (domain) DO UPDATE
SET role = 'exit',
    enabled = TRUE,
    updated_at = now();

UPDATE route_targets t
SET exit_domain_id = d.id
FROM domains d
WHERE t.exit_domain IS NOT NULL
  AND t.exit_domain = d.domain;

INSERT INTO landing_profiles (
  name, landing_mode, template_id, image_asset_id, title, apk_url, auto_download, enabled
)
SELECT
  '默认落地页',
  'default',
  NULL,
  NULL,
  '下载',
  '',
  TRUE,
  TRUE
WHERE NOT EXISTS (SELECT 1 FROM landing_profiles);

INSERT INTO landing_profiles (
  name, landing_mode, template_id, image_asset_id, title, apk_url, auto_download, enabled
)
SELECT
  COALESCE(NULLIF(r.name, ''), r.entry_domain) || ' 落地页',
  l.landing_mode,
  l.template_id,
  l.image_asset_id,
  l.title,
  l.apk_url,
  l.auto_download,
  r.enabled
FROM route_landing_configs l
JOIN routes r ON r.id = l.route_id
WHERE l.template_id IS NOT NULL
   OR l.image_asset_id IS NOT NULL
   OR l.title <> '下载'
   OR l.apk_url <> ''
   OR l.auto_download IS DISTINCT FROM TRUE;

WITH preferred AS (
  SELECT DISTINCT ON (l.route_id)
    l.route_id,
    p.id AS profile_id
  FROM route_landing_configs l
  LEFT JOIN routes r ON r.id = l.route_id
  JOIN landing_profiles p ON
    p.landing_mode = l.landing_mode
    AND p.template_id IS NOT DISTINCT FROM l.template_id
    AND p.image_asset_id IS NOT DISTINCT FROM l.image_asset_id
    AND p.title = l.title
    AND p.apk_url = l.apk_url
    AND p.auto_download = l.auto_download
  ORDER BY l.route_id, p.created_at DESC
)
UPDATE route_landing_configs l
SET landing_profile_id = preferred.profile_id
FROM preferred
WHERE l.route_id = preferred.route_id;

UPDATE route_landing_configs
SET landing_profile_id = (SELECT id FROM landing_profiles ORDER BY created_at ASC LIMIT 1)
WHERE landing_profile_id IS NULL;

INSERT INTO cloak_policies (name, enabled, threshold, token_hours, decoy_title, decoy_apk_url)
VALUES ('默认分流策略', FALSE, 8, 6, '下载', '')
ON CONFLICT (name) DO NOTHING;

INSERT INTO cloak_policies (name, enabled, threshold, token_hours, decoy_title, decoy_apk_url)
SELECT
  COALESCE(NULLIF(r.name, ''), r.entry_domain) || ' 分流策略',
  c.enabled,
  c.threshold,
  c.token_hours,
  c.decoy_title,
  c.decoy_apk_url
FROM route_cloak_configs c
JOIN routes r ON r.id = c.route_id
WHERE c.enabled = TRUE
   OR c.threshold <> 8
   OR c.token_hours <> 6
   OR c.decoy_title <> '下载'
   OR c.decoy_apk_url <> '';

WITH preferred AS (
  SELECT DISTINCT ON (c.route_id)
    c.route_id,
    p.id AS policy_id
  FROM route_cloak_configs c
  JOIN cloak_policies p ON
    p.enabled = c.enabled
    AND p.threshold = c.threshold
    AND p.token_hours = c.token_hours
    AND p.decoy_title = c.decoy_title
    AND p.decoy_apk_url = c.decoy_apk_url
  ORDER BY c.route_id, p.created_at DESC
)
UPDATE route_cloak_configs c
SET cloak_policy_id = preferred.policy_id
FROM preferred
WHERE c.route_id = preferred.route_id;

UPDATE route_cloak_configs
SET cloak_policy_id = (SELECT id FROM cloak_policies WHERE name = '默认分流策略')
WHERE cloak_policy_id IS NULL;

INSERT INTO meta_profiles (
  name, enabled, pixel_id, capi_token, test_event_code, currency, value,
  page_view_enabled, view_content_enabled, lead_enabled
)
VALUES ('默认 Meta 配置', FALSE, '', '', '', 'USD', 0, TRUE, TRUE, TRUE)
ON CONFLICT (name) DO NOTHING;

INSERT INTO meta_profiles (
  name, enabled, pixel_id, capi_token, test_event_code, currency, value,
  page_view_enabled, view_content_enabled, lead_enabled
)
SELECT
  COALESCE(NULLIF(r.name, ''), r.entry_domain) || ' Meta 配置',
  m.enabled,
  m.pixel_id,
  m.capi_token,
  m.test_event_code,
  m.currency,
  m.value,
  m.page_view_enabled,
  m.view_content_enabled,
  m.lead_enabled
FROM route_meta_configs m
JOIN routes r ON r.id = m.route_id
WHERE m.enabled = TRUE
   OR m.pixel_id <> ''
   OR m.capi_token <> ''
   OR m.test_event_code <> ''
   OR m.currency <> 'USD'
   OR m.value <> 0
   OR m.page_view_enabled IS DISTINCT FROM TRUE
   OR m.view_content_enabled IS DISTINCT FROM TRUE
   OR m.lead_enabled IS DISTINCT FROM TRUE;

WITH preferred AS (
  SELECT DISTINCT ON (m.route_id)
    m.route_id,
    p.id AS profile_id
  FROM route_meta_configs m
  JOIN meta_profiles p ON
    p.enabled = m.enabled
    AND p.pixel_id = m.pixel_id
    AND p.capi_token = m.capi_token
    AND p.test_event_code = m.test_event_code
    AND p.currency = m.currency
    AND p.value = m.value
    AND p.page_view_enabled = m.page_view_enabled
    AND p.view_content_enabled = m.view_content_enabled
    AND p.lead_enabled = m.lead_enabled
  ORDER BY m.route_id, p.created_at DESC
)
UPDATE route_meta_configs m
SET meta_profile_id = preferred.profile_id
FROM preferred
WHERE m.route_id = preferred.route_id;

UPDATE route_meta_configs
SET meta_profile_id = (SELECT id FROM meta_profiles WHERE name = '默认 Meta 配置')
WHERE meta_profile_id IS NULL;

CREATE INDEX idx_domains_role_enabled ON domains(role, enabled);
CREATE INDEX idx_landing_profiles_enabled ON landing_profiles(enabled);
CREATE INDEX idx_cloak_policies_enabled ON cloak_policies(enabled);
CREATE INDEX idx_meta_profiles_enabled ON meta_profiles(enabled);
CREATE INDEX idx_route_targets_exit_domain_id ON route_targets(exit_domain_id);
CREATE INDEX idx_route_landing_profile ON route_landing_configs(landing_profile_id);
CREATE INDEX idx_route_cloak_policy ON route_cloak_configs(cloak_policy_id);
CREATE INDEX idx_route_meta_profile ON route_meta_configs(meta_profile_id);
