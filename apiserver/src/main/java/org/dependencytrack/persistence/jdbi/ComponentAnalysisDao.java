/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.persistence.jdbi;

import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.PreparedBatch;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Access to durable, identity-keyed component analyses (license curation).
 * <p>
 * Component records are deleted and recreated across BOM uploads; a component
 * analysis is therefore keyed by the component's identity (purl, or
 * group/name/version) within a project, and re-applied on every ingest by
 * {@code ImportBomActivity}.
 */
public final class ComponentAnalysisDao {

    private final Handle handle;

    public ComponentAnalysisDao(final Handle handle) {
        this.handle = handle;
    }

    /**
     * The license an analysis applies — at most one of a resolved license
     * (incl. custom licenses), an SPDX expression, or a free-text name,
     * mirroring the component's three license slots. {@link #NONE} carries
     * no license override (details only).
     */
    public record LicenseOverride(
            @Nullable Long licenseId,
            @Nullable String licenseExpression,
            @Nullable String licenseName) {

        public static final LicenseOverride NONE = new LicenseOverride(null, null, null);

        public LicenseOverride {
            if ((licenseId != null ? 1 : 0) + (licenseExpression != null ? 1 : 0)
                    + (licenseName != null ? 1 : 0) > 1) {
                throw new IllegalArgumentException("A license override fills at most one license slot");
            }
        }

        public boolean isEmpty() {
            return licenseId == null && licenseExpression == null && licenseName == null;
        }
    }

    public record ComponentAnalysis(
            long id,
            long projectId,
            @Nullable String purl,
            @Nullable String group,
            String name,
            @Nullable String version,
            @Nullable Long licenseId,
            @Nullable String licenseExpression,
            @Nullable String licenseName,
            @Nullable Long declaredLicenseId,
            @Nullable String declaredLicenseName,
            @Nullable String declaredLicenseExpression,
            @Nullable String details,
            @Nullable Long policyId) {

        public LicenseOverride override() {
            return new LicenseOverride(licenseId, licenseExpression, licenseName);
        }
    }

    public record ComponentAnalysisComment(
            long id,
            Instant timestamp,
            @Nullable String commenter,
            String comment) {
    }

    private static final String ANALYSIS_COLUMNS = """
            "ID", "PROJECT_ID", "PURL", "GROUP", "NAME", "VERSION",
            "LICENSE_ID", "LICENSE_EXPRESSION", "LICENSE_NAME",
            "DECLARED_LICENSE_ID", "DECLARED_LICENSE_NAME",
            "DECLARED_LICENSE_EXPRESSION", "DETAILS", "POLICY_ID"
            """;

    private static final RowMapper<ComponentAnalysis> ANALYSIS_ROW_MAPPER = (rs, ctx) -> new ComponentAnalysis(
            rs.getLong("ID"),
            rs.getLong("PROJECT_ID"),
            rs.getString("PURL"),
            rs.getString("GROUP"),
            rs.getString("NAME"),
            rs.getString("VERSION"),
            rs.getObject("LICENSE_ID", Long.class),
            rs.getString("LICENSE_EXPRESSION"),
            rs.getString("LICENSE_NAME"),
            rs.getObject("DECLARED_LICENSE_ID", Long.class),
            rs.getString("DECLARED_LICENSE_NAME"),
            rs.getString("DECLARED_LICENSE_EXPRESSION"),
            rs.getString("DETAILS"),
            rs.getObject("POLICY_ID", Long.class));

    private static final RowMapper<ComponentAnalysisComment> COMMENT_ROW_MAPPER = (rs, ctx) -> new ComponentAnalysisComment(
            rs.getLong("ID"),
            rs.getTimestamp("TIMESTAMP").toInstant(),
            rs.getString("COMMENTER"),
            rs.getString("COMMENT"));

    /**
     * All analyses of one project, for bulk matching during BOM ingest.
     */
    public List<ComponentAnalysis> getAllByProject(final long projectId) {
        return handle.createQuery("""
                        SELECT %s
                          FROM "COMPONENT_ANALYSIS"
                         WHERE "PROJECT_ID" = :projectId
                        """.formatted(ANALYSIS_COLUMNS))
                .bind("projectId", projectId)
                .map(ANALYSIS_ROW_MAPPER)
                .list();
    }

    public Optional<ComponentAnalysis> getById(final long analysisId) {
        return handle.createQuery("""
                        SELECT %s
                          FROM "COMPONENT_ANALYSIS"
                         WHERE "ID" = :id
                        """.formatted(ANALYSIS_COLUMNS))
                .bind("id", analysisId)
                .map(ANALYSIS_ROW_MAPPER)
                .findOne();
    }

    public Optional<ComponentAnalysis> getByIdentity(
            final long projectId,
            @Nullable final String purl,
            @Nullable final String group,
            final String name,
            @Nullable final String version) {
        return handle.createQuery("""
                        SELECT %s
                          FROM "COMPONENT_ANALYSIS"
                         WHERE "PROJECT_ID" = :projectId
                           AND COALESCE("PURL", '') = COALESCE(:purl, '')
                           AND COALESCE("GROUP", '') = COALESCE(:group, '')
                           AND "NAME" = :name
                           AND COALESCE("VERSION", '') = COALESCE(:version, '')
                        """.formatted(ANALYSIS_COLUMNS))
                .bind("projectId", projectId)
                .bind("purl", purl)
                .bind("group", group)
                .bind("name", name)
                .bind("version", version)
                .map(ANALYSIS_ROW_MAPPER)
                .findOne();
    }

    /**
     * Create-or-update keyed by the identity unique index; returns the row id.
     */
    public long upsert(
            final long projectId,
            @Nullable final String purl,
            @Nullable final String group,
            final String name,
            @Nullable final String version,
            final LicenseOverride override,
            @Nullable final String details) {
        return handle.createQuery("""
                        INSERT INTO "COMPONENT_ANALYSIS"
                          ("PROJECT_ID", "PURL", "GROUP", "NAME", "VERSION",
                           "LICENSE_ID", "LICENSE_EXPRESSION", "LICENSE_NAME", "DETAILS")
                        VALUES
                          (:projectId, :purl, :group, :name, :version,
                           :licenseId, :licenseExpression, :licenseName, :details)
                        ON CONFLICT ("PROJECT_ID", COALESCE("PURL", ''), COALESCE("GROUP", ''),
                                     "NAME", COALESCE("VERSION", ''))
                        DO UPDATE
                           SET "LICENSE_ID" = EXCLUDED."LICENSE_ID"
                             , "LICENSE_EXPRESSION" = EXCLUDED."LICENSE_EXPRESSION"
                             , "LICENSE_NAME" = EXCLUDED."LICENSE_NAME"
                             , "DETAILS" = EXCLUDED."DETAILS"
                             , "POLICY_ID" = NULL
                             , "UPDATED_AT" = NOW()
                        RETURNING "ID"
                        """)
                .bind("projectId", projectId)
                .bind("purl", purl)
                .bind("group", group)
                .bind("name", name)
                .bind("version", version)
                .bind("licenseId", override.licenseId())
                .bind("licenseExpression", override.licenseExpression())
                .bind("licenseName", override.licenseName())
                .bind("details", details)
                .mapTo(Long.class)
                .one();
    }

    /**
     * Applies an analysis to the project's currently matching component rows
     * (the ingest hook does the same on every later BOM upload). Details are
     * written to the component notes; a license override fills its slot,
     * clears the other two, and marks the component's license as curated.
     */
    public int applyToComponents(
            final long projectId,
            @Nullable final String purl,
            @Nullable final String group,
            final String name,
            @Nullable final String version,
            final LicenseOverride override,
            @Nullable final String details) {
        return handle.createUpdate("""
                        UPDATE "COMPONENT"
                           SET "LICENSE_ID" = CASE WHEN :apply THEN :licenseId ELSE "LICENSE_ID" END
                             , "LICENSE_EXPRESSION" = CASE WHEN :apply THEN :licenseExpression
                                                           ELSE "LICENSE_EXPRESSION" END
                             , "LICENSE" = CASE WHEN :apply THEN :licenseName ELSE "LICENSE" END
                             , "LICENSE_CURATED" = CASE WHEN :apply THEN TRUE ELSE "LICENSE_CURATED" END
                             , "TEXT" = COALESCE(:details, "TEXT")
                         WHERE "PROJECT_ID" = :projectId
                           AND COALESCE("PURL", '') = COALESCE(:purl, '')
                           AND COALESCE("GROUP", '') = COALESCE(:group, '')
                           AND "NAME" = :name
                           AND COALESCE("VERSION", '') = COALESCE(:version, '')
                        """)
                .bind("projectId", projectId)
                .bind("purl", purl)
                .bind("group", group)
                .bind("name", name)
                .bind("version", version)
                .bind("apply", !override.isEmpty())
                .bind("licenseId", override.licenseId())
                .bind("licenseExpression", override.licenseExpression())
                .bind("licenseName", override.licenseName())
                .bind("details", details)
                .execute();
    }

    /**
     * Stores the BOM-declared license snapshot on an analysis; used to
     * restore the uploaded value when the override is cleared.
     */
    public void updateDeclaredSnapshot(
            final long analysisId,
            @Nullable final Long declaredLicenseId,
            @Nullable final String declaredLicenseName,
            @Nullable final String declaredLicenseExpression) {
        handle.createUpdate("""
                        UPDATE "COMPONENT_ANALYSIS"
                           SET "DECLARED_LICENSE_ID" = :declaredLicenseId
                             , "DECLARED_LICENSE_NAME" = :declaredLicenseName
                             , "DECLARED_LICENSE_EXPRESSION" = :declaredLicenseExpression
                         WHERE "ID" = :analysisId
                        """)
                .bind("analysisId", analysisId)
                .bind("declaredLicenseId", declaredLicenseId)
                .bind("declaredLicenseName", declaredLicenseName)
                .bind("declaredLicenseExpression", declaredLicenseExpression)
                .execute();
    }

    /**
     * Restores the declared-license snapshot onto the project's matching
     * component rows that carry the override ({@code LICENSE_CURATED}) — the
     * instant part of clearing or deleting an analysis. A row the override no
     * longer covers keeps its license: the snapshot describes the upload the
     * override was applied to, not a later one.
     */
    public int restoreDeclaredLicense(
            final long projectId,
            @Nullable final String purl,
            @Nullable final String group,
            final String name,
            @Nullable final String version,
            @Nullable final Long declaredLicenseId,
            @Nullable final String declaredLicenseName,
            @Nullable final String declaredLicenseExpression) {
        return handle.createUpdate("""
                        UPDATE "COMPONENT"
                           SET "LICENSE_ID" = :declaredLicenseId
                             , "LICENSE" = :declaredLicenseName
                             , "LICENSE_EXPRESSION" = :declaredLicenseExpression
                             , "LICENSE_CURATED" = FALSE
                         WHERE "LICENSE_CURATED" IS TRUE
                           AND "PROJECT_ID" = :projectId
                           AND COALESCE("PURL", '') = COALESCE(:purl, '')
                           AND COALESCE("GROUP", '') = COALESCE(:group, '')
                           AND "NAME" = :name
                           AND COALESCE("VERSION", '') = COALESCE(:version, '')
                        """)
                .bind("projectId", projectId)
                .bind("purl", purl)
                .bind("group", group)
                .bind("name", name)
                .bind("version", version)
                .bind("declaredLicenseId", declaredLicenseId)
                .bind("declaredLicenseName", declaredLicenseName)
                .bind("declaredLicenseExpression", declaredLicenseExpression)
                .execute();
    }

    /**
     * Stores the declared-license snapshots of many analyses in one batch,
     * keyed by analysis id; the ingest hook writes those of one upload.
     */
    public void updateDeclaredSnapshots(final Map<Long, ComponentLicenseRow> snapshotsByAnalysisId) {
        if (snapshotsByAnalysisId.isEmpty()) {
            return;
        }
        final PreparedBatch batch = handle.prepareBatch("""
                UPDATE "COMPONENT_ANALYSIS"
                   SET "DECLARED_LICENSE_ID" = :declaredLicenseId
                     , "DECLARED_LICENSE_NAME" = :declaredLicenseName
                     , "DECLARED_LICENSE_EXPRESSION" = :declaredLicenseExpression
                 WHERE "ID" = :analysisId
                """);
        snapshotsByAnalysisId.forEach((analysisId, row) -> batch
                .bind("analysisId", analysisId)
                .bind("declaredLicenseId", row.licenseId())
                .bind("declaredLicenseName", row.licenseName())
                .bind("declaredLicenseExpression", row.licenseExpression())
                .add());
        batch.execute();
    }

    public record ComponentLicenseRow(
            @Nullable Long licenseId,
            @Nullable String licenseName,
            @Nullable String licenseExpression) {
    }

    /**
     * Current license fields of the first component matching the identity —
     * the values captured as the declared snapshot when an override is set.
     */
    public Optional<ComponentLicenseRow> getComponentLicense(
            final long projectId,
            @Nullable final String purl,
            @Nullable final String group,
            final String name,
            @Nullable final String version) {
        return handle.createQuery("""
                        SELECT "LICENSE_ID", "LICENSE", "LICENSE_EXPRESSION"
                          FROM "COMPONENT"
                         WHERE "PROJECT_ID" = :projectId
                           AND COALESCE("PURL", '') = COALESCE(:purl, '')
                           AND COALESCE("GROUP", '') = COALESCE(:group, '')
                           AND "NAME" = :name
                           AND COALESCE("VERSION", '') = COALESCE(:version, '')
                         LIMIT 1
                        """)
                .bind("projectId", projectId)
                .bind("purl", purl)
                .bind("group", group)
                .bind("name", name)
                .bind("version", version)
                .map((rs, ctx) -> new ComponentLicenseRow(
                        rs.getObject("LICENSE_ID", Long.class),
                        rs.getString("LICENSE"),
                        rs.getString("LICENSE_EXPRESSION")))
                .findOne();
    }

    /**
     * Create-or-update by a component policy. Manual analyses
     * (POLICY_ID IS NULL) are never modified — the empty Optional says the
     * policy lost to a manual decision.
     */
    public Optional<Long> upsertPolicyAnalysis(
            final long projectId,
            @Nullable final String purl,
            @Nullable final String group,
            final String name,
            @Nullable final String version,
            final LicenseOverride override,
            @Nullable final String details,
            final long policyId) {
        return handle.createQuery("""
                        INSERT INTO "COMPONENT_ANALYSIS"
                          ("PROJECT_ID", "PURL", "GROUP", "NAME", "VERSION",
                           "LICENSE_ID", "LICENSE_EXPRESSION", "LICENSE_NAME", "DETAILS", "POLICY_ID")
                        VALUES
                          (:projectId, :purl, :group, :name, :version,
                           :licenseId, :licenseExpression, :licenseName, :details, :policyId)
                        ON CONFLICT ("PROJECT_ID", COALESCE("PURL", ''), COALESCE("GROUP", ''),
                                     "NAME", COALESCE("VERSION", ''))
                        DO UPDATE
                           SET "LICENSE_ID" = EXCLUDED."LICENSE_ID"
                             , "LICENSE_EXPRESSION" = EXCLUDED."LICENSE_EXPRESSION"
                             , "LICENSE_NAME" = EXCLUDED."LICENSE_NAME"
                             , "DETAILS" = EXCLUDED."DETAILS"
                             , "POLICY_ID" = EXCLUDED."POLICY_ID"
                             , "UPDATED_AT" = NOW()
                         WHERE "COMPONENT_ANALYSIS"."POLICY_ID" IS NOT NULL
                        RETURNING "ID"
                        """)
                .bind("projectId", projectId)
                .bind("purl", purl)
                .bind("group", group)
                .bind("name", name)
                .bind("version", version)
                .bind("licenseId", override.licenseId())
                .bind("licenseExpression", override.licenseExpression())
                .bind("licenseName", override.licenseName())
                .bind("details", details)
                .bind("policyId", policyId)
                .mapTo(Long.class)
                .findOne();
    }

    public boolean delete(final long analysisId) {
        return handle.createUpdate("""
                        DELETE FROM "COMPONENT_ANALYSIS" WHERE "ID" = :id
                        """)
                .bind("id", analysisId)
                .execute() > 0;
    }

    public record CreateCommentCommand(long componentAnalysisId, @Nullable String commenter, String comment) {
    }

    public int createComments(final Collection<CreateCommentCommand> commands) {
        final var batch = handle.prepareBatch("""
                INSERT INTO "COMPONENT_ANALYSIS_COMMENT"
                  ("COMPONENT_ANALYSIS_ID", "COMMENTER", "COMMENT")
                VALUES
                  (:componentAnalysisId, :commenter, :comment)
                """);
        for (final CreateCommentCommand command : commands) {
            batch.bind("componentAnalysisId", command.componentAnalysisId())
                    .bind("commenter", command.commenter())
                    .bind("comment", command.comment())
                    .add();
        }
        return batch.execute().length;
    }

    public List<ComponentAnalysisComment> getComments(final long componentAnalysisId) {
        return handle.createQuery("""
                        SELECT "ID", "TIMESTAMP", "COMMENTER", "COMMENT"
                          FROM "COMPONENT_ANALYSIS_COMMENT"
                         WHERE "COMPONENT_ANALYSIS_ID" = :componentAnalysisId
                         ORDER BY "TIMESTAMP", "ID"
                        """)
                .bind("componentAnalysisId", componentAnalysisId)
                .map(COMMENT_ROW_MAPPER)
                .list();
    }
}
