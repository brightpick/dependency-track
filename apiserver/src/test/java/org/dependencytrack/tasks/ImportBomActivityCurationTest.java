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
package org.dependencytrack.tasks;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.memory.MemoryFileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.persistence.jdbi.ComponentAnalysisDao;
import org.dependencytrack.componentanalysis.LicenseOverride;
import org.dependencytrack.persistence.jdbi.ComponentPolicyDao;
import org.dependencytrack.proto.internal.workflow.v1.ImportBomArg;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX;
import static org.dependencytrack.notification.NotificationTestUtil.createCatchAllNotificationRule;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.mockito.Mockito.mock;

/**
 * License curation across BOM imports: an analysis is re-applied on every
 * ingest, and a component whose analysis is gone carries the uploaded license
 * again — with {@code license_curated} false.
 */
class ImportBomActivityCurationTest extends PersistenceCapableTest {

    private static final String PURL = "pkg:maven/org.acme/acme-lib@1.0.0";
    private static final byte[] BOM = /* language=JSON */ """
            {
              "bomFormat": "CycloneDX",
              "specVersion": "1.5",
              "version": 1,
              "components": [
                {
                  "type": "library",
                  "group": "org.acme",
                  "name": "acme-lib",
                  "version": "1.0.0",
                  "purl": "pkg:maven/org.acme/acme-lib@1.0.0",
                  "licenses": [ { "license": { "id": "MIT" } } ]
                }
              ]
            }
            """.getBytes(StandardCharsets.UTF_8);

    private FileStorage fileStorage;
    private ImportBomActivity activity;
    private Project project;
    private License mit;
    private License apache;

    @BeforeEach
    void beforeEach() {
        fileStorage = new MemoryFileStorage();
        activity = new ImportBomActivity(fileStorage, mock(DexEngine.class), false);
        qm.createConfigProperty(
                ACCEPT_ARTIFACT_CYCLONEDX.getGroupName(),
                ACCEPT_ARTIFACT_CYCLONEDX.getPropertyName(),
                "true",
                ACCEPT_ARTIFACT_CYCLONEDX.getPropertyType(),
                ACCEPT_ARTIFACT_CYCLONEDX.getDescription());
        createCatchAllNotificationRule(qm, NotificationScope.PORTFOLIO);
        mit = createLicense("MIT", "MIT License");
        apache = createLicense("Apache-2.0", "Apache License 2.0");
        project = qm.createProject("acme-app", null, "1.0", null, null, null, null, false);
    }

    @Test
    void overrideIsReappliedOnEveryImportAndFlagsTheComponent() throws Exception {
        upload();
        Component component = theComponent();
        assertThat(component.getResolvedLicense().getId()).isEqualTo(mit.getId());
        assertThat(component.isLicenseCurated()).isFalse();

        curate(new LicenseOverride(apache.getId(), null, null));

        upload();
        component = theComponent();
        assertThat(component.getResolvedLicense().getId()).isEqualTo(apache.getId());
        assertThat(component.isLicenseCurated()).isTrue();
        // the snapshot holds what the upload declared, not the decision
        final ComponentAnalysisDao.ComponentAnalysis analysis = withJdbiHandle(handle ->
                new ComponentAnalysisDao(handle).getByIdentity(project.getId(), PURL, "org.acme", "acme-lib", "1.0.0")).orElseThrow();
        assertThat(analysis.declaredLicenseId()).isEqualTo(mit.getId());
    }

    @Test
    void deletedAnalysisLeavesNoFlagBehindOnTheNextImport() throws Exception {
        upload();
        final long analysisId = curate(new LicenseOverride(apache.getId(), null, null));
        upload();
        assertThat(theComponent().isLicenseCurated()).isTrue();

        // the analysis row alone disappears; the next import must undo everything it set
        inJdbiTransaction(handle -> new ComponentAnalysisDao(handle).delete(analysisId));

        upload();
        final Component component = theComponent();
        assertThat(component.getResolvedLicense().getId()).isEqualTo(mit.getId());
        assertThat(component.isLicenseCurated()).isFalse();
    }

    @Test
    void retractedPolicyAnalysisClearsTheFlagOnTheNextImport() throws Exception {
        final long policyId = inJdbiTransaction(handle -> new ComponentPolicyDao(handle).create(
                "acme curation", null, "tester", true, 0,
                "component.name == \"acme-lib\"",
                new LicenseOverride(apache.getId(), null, null), null, null, null));

        upload();
        Component component = theComponent();
        assertThat(component.getResolvedLicense().getId()).isEqualTo(apache.getId());
        assertThat(component.isLicenseCurated()).isTrue();

        // the rule no longer matches: its analysis is retracted, the upload applies again
        inJdbiTransaction(handle -> new ComponentPolicyDao(handle).update(
                policyId, "acme curation", null, true, 0,
                "component.name == \"something-else\"",
                new LicenseOverride(apache.getId(), null, null), null, null, null));

        upload();
        component = theComponent();
        assertThat(component.getResolvedLicense().getId()).isEqualTo(mit.getId());
        assertThat(component.isLicenseCurated()).isFalse();
    }

    private void upload() throws Exception {
        final FileMetadata bomFile = fileStorage.store(
                "test/%s-%s".formatted(getClass().getSimpleName(), UUID.randomUUID()),
                new ByteArrayInputStream(BOM));
        activity.execute(null, ImportBomArg.newBuilder()
                .setProjectUuid(project.getUuid().toString())
                .setProjectName(project.getName())
                .setProjectVersion(project.getVersion())
                .setBomUploadToken(UUID.randomUUID().toString())
                .setBomFileMetadata(bomFile)
                .build());
    }

    private long curate(final LicenseOverride override) {
        return inJdbiTransaction(handle -> {
            final var dao = new ComponentAnalysisDao(handle);
            final long id = dao.upsert(project.getId(), PURL, "org.acme", "acme-lib", "1.0.0", override, null);
            dao.applyToComponents(project.getId(), PURL, "org.acme", "acme-lib", "1.0.0", override, null);
            return id;
        });
    }

    private Component theComponent() {
        // the activity works in its own persistence context: read fresh
        qm.getPersistenceManager().evictAll();
        return qm.getAllComponents(project).stream()
                .filter(c -> "acme-lib".equals(c.getName()))
                .findFirst().orElseThrow();
    }

    private License createLicense(final String licenseId, final String name) {
        final var license = new License();
        license.setLicenseId(licenseId);
        license.setName(name);
        return qm.persist(license);
    }
}
