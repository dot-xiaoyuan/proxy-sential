-- Keep the independently verified L2 identity on the terminal projection so
-- mirror statistics can require a matching scoped MAC without re-reading
-- discovery history during list and comparison requests.
ALTER TABLE passive_census_terminal_current
 ADD COLUMN IF NOT EXISTS mac text NOT NULL DEFAULT '';
