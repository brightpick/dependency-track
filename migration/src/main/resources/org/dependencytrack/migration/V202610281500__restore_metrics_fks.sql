-- Restore the 5.0.3 metrics FKs (V202605022031__init.sql) that V202606101343 dropped.
-- Same lock mode as ADD FOREIGN KEY: no new orphan row can appear between the DELETEs and the validation.
LOCK TABLE "COMPONENT", "PROJECT", "DEPENDENCYMETRICS", "PROJECTMETRICS" IN SHARE ROW EXCLUSIVE MODE;

-- Rows without a parent would fail the ADD CONSTRAINT below.
DELETE FROM "DEPENDENCYMETRICS" AS dm
 WHERE NOT EXISTS (SELECT 1 FROM "COMPONENT" AS c WHERE c."ID" = dm."COMPONENT_ID")
    OR NOT EXISTS (SELECT 1 FROM "PROJECT" AS p WHERE p."ID" = dm."PROJECT_ID");

DELETE FROM "PROJECTMETRICS" AS pm
 WHERE NOT EXISTS (SELECT 1 FROM "PROJECT" AS p WHERE p."ID" = pm."PROJECT_ID");

ALTER TABLE "DEPENDENCYMETRICS"
  DROP CONSTRAINT IF EXISTS "DEPENDENCYMETRICS_COMPONENT_FK",
  -- PostgreSQL 14 rejects NOT VALID FKs on partitioned tables, so the FK is added and validated in one step.
  -- squawk-ignore adding-foreign-key-constraint, constraint-missing-not-valid
  ADD CONSTRAINT "DEPENDENCYMETRICS_COMPONENT_FK" FOREIGN KEY ("COMPONENT_ID") REFERENCES "COMPONENT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE "DEPENDENCYMETRICS"
  DROP CONSTRAINT IF EXISTS "DEPENDENCYMETRICS_PROJECT_FK",
  -- PostgreSQL 14 rejects NOT VALID FKs on partitioned tables, so the FK is added and validated in one step.
  -- squawk-ignore adding-foreign-key-constraint, constraint-missing-not-valid
  ADD CONSTRAINT "DEPENDENCYMETRICS_PROJECT_FK" FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE "PROJECTMETRICS"
  DROP CONSTRAINT IF EXISTS "PROJECTMETRICS_PROJECT_FK",
  -- PostgreSQL 14 rejects NOT VALID FKs on partitioned tables, so the FK is added and validated in one step.
  -- squawk-ignore adding-foreign-key-constraint, constraint-missing-not-valid
  ADD CONSTRAINT "PROJECTMETRICS_PROJECT_FK" FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;
