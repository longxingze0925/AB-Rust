INSERT INTO domains (domain, role, note, enabled)
SELECT r.entry_domain, 'entry', '由现有线路补齐', r.enabled
FROM routes r
WHERE r.entry_domain <> ''
ON CONFLICT (domain) DO UPDATE
SET role = 'entry',
    enabled = domains.enabled OR EXCLUDED.enabled,
    updated_at = now();

INSERT INTO domains (domain, role, note, enabled)
SELECT COALESCE(t.exit_domain, d.domain), 'exit', '由现有线路补齐', r.enabled
FROM route_targets t
JOIN routes r ON r.id = t.route_id
LEFT JOIN domains d ON d.id = t.exit_domain_id
WHERE t.target_type = 'internal'
  AND COALESCE(t.exit_domain, d.domain, '') <> ''
ON CONFLICT (domain) DO UPDATE
SET role = 'exit',
    enabled = domains.enabled OR EXCLUDED.enabled,
    updated_at = now();

UPDATE route_targets t
SET exit_domain_id = d.id
FROM domains d
WHERE t.target_type = 'internal'
  AND t.exit_domain_id IS NULL
  AND t.exit_domain = d.domain
  AND d.role = 'exit';
