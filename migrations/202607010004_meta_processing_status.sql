ALTER TABLE meta_event_queue
  DROP CONSTRAINT IF EXISTS meta_event_queue_status_check;

ALTER TABLE meta_event_queue
  ADD CONSTRAINT meta_event_queue_status_check
  CHECK (status IN ('pending', 'processing', 'sent', 'failed', 'skipped'));

UPDATE meta_event_queue
SET status = 'failed',
    next_attempt_at = now(),
    last_response = 'Recovered stale processing event during migration',
    updated_at = now()
WHERE status = 'processing';
