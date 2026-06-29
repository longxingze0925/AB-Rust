ALTER TABLE meta_event_queue
  ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_meta_event_queue_archived
  ON meta_event_queue(archived_at, created_at DESC);
