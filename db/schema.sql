-- Charon data model.
-- tool_calls is a separate table rather than part of the report text, so
-- every tool call can be inspected after the fact.

CREATE TABLE IF NOT EXISTS investigations (
    id SERIAL PRIMARY KEY,
    submitted_input TEXT NOT NULL,      -- file reference or URL
    input_type TEXT NOT NULL,           -- 'file' | 'url'
    status TEXT NOT NULL DEFAULT 'running',  -- 'running' | 'complete' | 'incomplete' | 'failed'
    report TEXT,                        -- final report (JSON)
    error TEXT,                         -- failure reason (failed) or limitation reason (incomplete)
    model TEXT,                         -- model id the run was submitted with; NULL means unknown
    created_at TIMESTAMP DEFAULT now()
);
-- upgrades databases created without the error column
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS error TEXT;
-- upgrades databases created without the model column; existing rows stay NULL (unknown)
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS model TEXT;

CREATE TABLE IF NOT EXISTS tool_calls (
    id SERIAL PRIMARY KEY,
    investigation_id INTEGER REFERENCES investigations(id),
    -- server name of the requested tool: 'sandbox' | 'ocr' | 'traffic_summary' | 'threat_intel'
    -- are the expected values; a tool name the model invents is logged exactly as given
    tool_name TEXT NOT NULL,
    input_payload TEXT,
    output_payload TEXT,
    called_at TIMESTAMP DEFAULT now()
);
