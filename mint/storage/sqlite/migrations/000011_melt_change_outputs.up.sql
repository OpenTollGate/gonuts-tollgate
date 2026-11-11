CREATE TABLE IF NOT EXISTS melt_change_outputs (
	quote_id TEXT NOT NULL,
	output_index INTEGER NOT NULL,
	b_ TEXT NOT NULL UNIQUE,
	keyset_id TEXT NOT NULL,
	PRIMARY KEY (quote_id, output_index)
);

CREATE INDEX IF NOT EXISTS idx_melt_change_outputs_quote ON melt_change_outputs(quote_id);
