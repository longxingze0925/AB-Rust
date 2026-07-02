UPDATE cloak_policies
SET use_asn = TRUE,
    block_datacenter_asn = TRUE
WHERE name = '默认分流策略';

UPDATE route_cloak_configs
SET use_asn = TRUE,
    block_datacenter_asn = TRUE
WHERE cloak_policy_id IN (
    SELECT id FROM cloak_policies WHERE name = '默认分流策略'
  )
  OR cloak_policy_id IS NULL;
