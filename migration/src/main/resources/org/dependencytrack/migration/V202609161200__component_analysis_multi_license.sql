-- A component whose license was set by a durable component analysis (manual
-- or component-policy license curation) carries this flag, so a policy
-- condition can tell a human-decided license from a BOM-declared one
-- (component.license_curated). Every BOM import resets it while synchronizing
-- the component's fields; the analysis applier sets it again where an analysis
-- applies. Nullable like "INTERNAL": NULL reads as false.
ALTER TABLE "COMPONENT"
  ADD COLUMN IF NOT EXISTS "LICENSE_CURATED" BOOLEAN;
