-- 004: 'conflict' error category
--
-- `sentio_core::SentioError::Conflict` (introduced with the globally-unique
-- SMTP username constraint, migration 003) maps to the `error_events.error_type`
-- column, whose CHECK must admit the new value.

ALTER TABLE error_events DROP CONSTRAINT error_events_error_type_check;
ALTER TABLE error_events ADD CONSTRAINT error_events_error_type_check
    CHECK (error_type = ANY (ARRAY[
        'database'::text, 'redis'::text, 'queue'::text, 'storage'::text,
        'smtp'::text, 'auth'::text, 'rate_limit'::text, 'not_found'::text,
        'validation'::text, 'internal'::text, 'config'::text,
        'conflict'::text
    ]));
