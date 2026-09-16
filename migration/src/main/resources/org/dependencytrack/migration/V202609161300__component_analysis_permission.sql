-- License curation on components is its own authority: the COMPONENT_ANALYSIS
-- permission, granted to teams like any other, distinct from managing
-- policies. The permission row is normally seeded from the Permissions enum
-- at start-up; it is created here as well because the seeder grants a team
-- its permissions only when it creates the team — an Administrators team that
-- already exists would otherwise never receive the new permission.
INSERT INTO "PERMISSION" ("NAME", "DESCRIPTION")
VALUES ('COMPONENT_ANALYSIS',
        'Provides the ability to make license curation decisions on components: override the declared license and comment on the decision')
ON CONFLICT ("NAME") DO NOTHING;

-- Administrators hold every permission; other teams are granted this one
-- deliberately, by hand.
INSERT INTO "TEAMS_PERMISSIONS" ("TEAM_ID", "PERMISSION_ID")
SELECT t."ID", p."ID"
  FROM "TEAM" t
     , "PERMISSION" p
 WHERE t."NAME" = 'Administrators'
   AND p."NAME" = 'COMPONENT_ANALYSIS'
   AND NOT EXISTS (SELECT 1
                     FROM "TEAMS_PERMISSIONS" tp
                    WHERE tp."TEAM_ID" = t."ID"
                      AND tp."PERMISSION_ID" = p."ID");
