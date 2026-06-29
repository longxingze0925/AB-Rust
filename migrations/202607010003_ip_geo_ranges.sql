CREATE TABLE ip_geo_ranges (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cidr CIDR NOT NULL UNIQUE,
  country TEXT NOT NULL DEFAULT '',
  province TEXT NOT NULL DEFAULT '',
  city TEXT NOT NULL DEFAULT '',
  isp TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT 'manual',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_ip_geo_ranges_cidr ON ip_geo_ranges USING gist (cidr inet_ops);
CREATE INDEX idx_ip_geo_ranges_updated ON ip_geo_ranges(updated_at DESC);
