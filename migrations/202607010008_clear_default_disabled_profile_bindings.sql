UPDATE route_cloak_configs
SET cloak_policy_id = NULL
WHERE cloak_policy_id IS NOT NULL
  AND enabled = FALSE
  AND threshold = 8
  AND token_hours = 6
  AND decoy_title = '下载'
  AND decoy_apk_url = '';

UPDATE route_meta_configs
SET meta_profile_id = NULL
WHERE meta_profile_id IS NOT NULL
  AND enabled = FALSE
  AND pixel_id = ''
  AND capi_token = ''
  AND test_event_code = ''
  AND currency = 'USD'
  AND value = 0
  AND page_view_enabled = TRUE
  AND view_content_enabled = TRUE
  AND lead_enabled = TRUE;
