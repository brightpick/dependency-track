-- A component whose license was set by a durable component analysis (manual
-- or component-policy license curation) carries this flag, so a policy
-- condition can tell a human-decided license from a BOM-declared one
-- (component.license_curated). Every BOM import resets it while synchronizing
-- the component's fields; the analysis applier sets it again where an analysis
-- applies. Nullable like "INTERNAL": NULL reads as false.
ALTER TABLE "COMPONENT"
  ADD COLUMN IF NOT EXISTS "LICENSE_CURATED" BOOLEAN;

-- A license override targets exactly one of the component's three license
-- slots, mirroring the DECLARED_* snapshot: a resolved license (LICENSE_ID),
-- an SPDX expression whose every operand is a known license
-- (LICENSE_EXPRESSION), or a free-text name (LICENSE_NAME). A multi-license
-- is thereby curated as a whole instead of being collapsed to one member.
ALTER TABLE "COMPONENT_ANALYSIS"
  ADD COLUMN IF NOT EXISTS "LICENSE_EXPRESSION" TEXT,
  ADD COLUMN IF NOT EXISTS "LICENSE_NAME"       TEXT;

ALTER TABLE "COMPONENT_ANALYSIS"
  DROP CONSTRAINT IF EXISTS "COMPONENT_ANALYSIS_ONE_LICENSE_SLOT",
  ADD CONSTRAINT "COMPONENT_ANALYSIS_ONE_LICENSE_SLOT"
    CHECK (num_nonnulls("LICENSE_ID", "LICENSE_EXPRESSION", "LICENSE_NAME") <= 1) NOT VALID;

ALTER TABLE "COMPONENT_ANALYSIS"
  VALIDATE CONSTRAINT "COMPONENT_ANALYSIS_ONE_LICENSE_SLOT";

-- The same three slots on component policies; a matching policy copies its
-- override into the analysis it maintains.
ALTER TABLE "COMPONENT_POLICY"
  ADD COLUMN IF NOT EXISTS "LICENSE_EXPRESSION" TEXT,
  ADD COLUMN IF NOT EXISTS "LICENSE_NAME"       TEXT;

ALTER TABLE "COMPONENT_POLICY"
  DROP CONSTRAINT IF EXISTS "COMPONENT_POLICY_ONE_LICENSE_SLOT",
  ADD CONSTRAINT "COMPONENT_POLICY_ONE_LICENSE_SLOT"
    CHECK (num_nonnulls("LICENSE_ID", "LICENSE_EXPRESSION", "LICENSE_NAME") <= 1) NOT VALID;

ALTER TABLE "COMPONENT_POLICY"
  VALIDATE CONSTRAINT "COMPONENT_POLICY_ONE_LICENSE_SLOT";
