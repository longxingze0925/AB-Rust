DELETE FROM download_events d
USING download_events keep
WHERE d.route_id IS NOT NULL
  AND d.visit_id IS NOT NULL
  AND d.event_id <> ''
  AND keep.route_id = d.route_id
  AND keep.visit_id = d.visit_id
  AND keep.event_id = d.event_id
  AND (
    keep.created_at < d.created_at
    OR (keep.created_at = d.created_at AND keep.id < d.id)
  );

CREATE UNIQUE INDEX IF NOT EXISTS idx_download_events_route_visit_event_unique
  ON download_events(route_id, visit_id, event_id)
  WHERE route_id IS NOT NULL AND visit_id IS NOT NULL AND event_id <> '';
