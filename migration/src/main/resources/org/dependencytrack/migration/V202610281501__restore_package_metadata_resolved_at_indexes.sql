-- Restore the 5.0.3 RESOLVED_AT indexes (V202605022031__init.sql) that V202608041243 dropped.
DROP INDEX CONCURRENTLY IF EXISTS "PACKAGE_METADATA_RESOLVED_AT_IDX";
-- The DROP above also removes an invalid index left by an interrupted run.
-- squawk-ignore prefer-robust-stmts
CREATE INDEX CONCURRENTLY "PACKAGE_METADATA_RESOLVED_AT_IDX" ON "PACKAGE_METADATA" USING btree ("RESOLVED_AT");

DROP INDEX CONCURRENTLY IF EXISTS "PACKAGE_ARTIFACT_METADATA_RESOLVED_AT_IDX";
-- The DROP above also removes an invalid index left by an interrupted run.
-- squawk-ignore prefer-robust-stmts
CREATE INDEX CONCURRENTLY "PACKAGE_ARTIFACT_METADATA_RESOLVED_AT_IDX" ON "PACKAGE_ARTIFACT_METADATA" USING btree ("RESOLVED_AT");
