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
package org.dependencytrack.resources.v2;

import alpine.server.auth.PermissionRequired;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.Provider;
import org.dependencytrack.api.v2.ComponentAnalysesApi;
import org.dependencytrack.api.v2.model.ComponentAnalysisComment;
import org.dependencytrack.api.v2.model.CreateComponentAnalysisCommentRequest;
import org.dependencytrack.api.v2.model.ListComponentAnalysesResponse;
import org.dependencytrack.api.v2.model.ListComponentAnalysisCommentsResponse;
import org.dependencytrack.api.v2.model.UpsertComponentAnalysisRequest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.persistence.jdbi.ComponentAnalysisDao;
import org.dependencytrack.persistence.jdbi.ComponentAnalysisDao.ComponentAnalysis;
import org.dependencytrack.persistence.jdbi.ComponentAnalysisDao.CreateCommentCommand;
import org.dependencytrack.persistence.jdbi.ComponentAnalysisDao.LicenseOverride;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * REST resource for component analyses (durable license curation).
 */
@Provider
public final class ComponentAnalysesResource extends AbstractApiResource implements ComponentAnalysesApi {

    @Context
    private UriInfo uriInfo;

    @Override
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response listComponentAnalyses(final UUID project) {
        try (final var qm = new QueryManager()) {
            final long projectId = requireProject(qm, project).getId();
            final List<ComponentAnalysis> analyses = withJdbiHandle(
                    handle -> new ComponentAnalysisDao(handle).getAllByProject(projectId));
            final var items = new ArrayList<org.dependencytrack.api.v2.model.ComponentAnalysis>(analyses.size());
            for (final ComponentAnalysis analysis : analyses) {
                items.add(mapAnalysis(qm, analysis));
            }
            return Response.ok(ListComponentAnalysesResponse.builder().analyses(items).build()).build();
        }
    }

    @Override
    @PermissionRequired(Permissions.Constants.COMPONENT_ANALYSIS)
    public Response updateComponentAnalysis(final UpsertComponentAnalysisRequest request) {
        try (final var qm = new QueryManager()) {
            final long projectId = requireProject(qm, request.getProjectUuid()).getId();
            final LicenseOverride override = LicenseOverrideResolver.resolve(
                    qm, request.getLicense(), request.getLicenseExpression(), request.getLicenseName());

            final String commenter = getPrincipal().getName();
            inJdbiTransaction(handle -> {
                final var dao = new ComponentAnalysisDao(handle);
                final ComponentAnalysis existing = dao.getByIdentity(
                        projectId, request.getPurl(), request.getGroup(),
                        request.getName(), request.getVersion()).orElse(null);
                final long id = dao.upsert(
                        projectId, request.getPurl(), request.getGroup(),
                        request.getName(), request.getVersion(),
                        override, request.getDetails());
                final var comments = new ArrayList<CreateCommentCommand>();
                final LicenseOverride oldOverride = existing != null ? existing.override() : LicenseOverride.NONE;
                if (!Objects.equals(oldOverride, override)) {
                    comments.add(new CreateCommentCommand(id, commenter,
                            "License override: %s → %s".formatted(
                                    LicenseOverrideResolver.label(qm, oldOverride),
                                    LicenseOverrideResolver.label(qm, override))));
                }
                final String oldDetails = existing != null ? existing.details() : null;
                if (!Objects.equals(oldDetails, request.getDetails())) {
                    comments.add(new CreateCommentCommand(id, commenter,
                            "Details: %s → %s".formatted(
                                    Objects.requireNonNullElse(oldDetails, "not set"),
                                    Objects.requireNonNullElse(request.getDetails(), "not set"))));
                }
                if (!comments.isEmpty()) {
                    dao.createComments(comments);
                }
                if (!override.isEmpty()) {
                    // first override on this component: snapshot the uploaded
                    // license so clearing can restore it instantly
                    if (oldOverride.isEmpty()) {
                        dao.getComponentLicense(
                                projectId, request.getPurl(), request.getGroup(),
                                request.getName(), request.getVersion())
                            .ifPresent(row -> dao.updateDeclaredSnapshot(
                                    id, row.licenseId(), row.licenseName(),
                                    row.licenseExpression()));
                    }
                    dao.applyToComponents(
                            projectId, request.getPurl(), request.getGroup(),
                            request.getName(), request.getVersion(),
                            override, request.getDetails());
                } else {
                    if (!oldOverride.isEmpty()) {
                        dao.restoreDeclaredLicense(
                                projectId, request.getPurl(), request.getGroup(),
                                request.getName(), request.getVersion(),
                                existing.declaredLicenseId(),
                                existing.declaredLicenseName(),
                                existing.declaredLicenseExpression());
                    }
                    dao.applyToComponents(
                            projectId, request.getPurl(), request.getGroup(),
                            request.getName(), request.getVersion(),
                            LicenseOverride.NONE, request.getDetails());
                }
                return null;
            });
            return Response.noContent().build();
        }
    }

    @Override
    @PermissionRequired(Permissions.Constants.COMPONENT_ANALYSIS)
    public Response deleteComponentAnalysis(final Long id) {
        final ComponentAnalysis analysis;
        try (final var qm = new QueryManager()) {
            analysis = requireAnalysis(qm, id);
        }
        inJdbiTransaction(handle -> {
            final var dao = new ComponentAnalysisDao(handle);
            // a component that carries the decision gets its uploaded license
            // back, also an empty one, and also when the decision's license has
            // since left the catalogue
            dao.restoreDeclaredLicense(
                    analysis.projectId(), analysis.purl(), analysis.group(),
                    analysis.name(), analysis.version(),
                    analysis.declaredLicenseId(),
                    analysis.declaredLicenseName(),
                    analysis.declaredLicenseExpression());
            dao.delete(analysis.id());
            return null;
        });
        return Response.noContent().build();
    }

    @Override
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response listComponentAnalysisComments(final Long id) {
        try (final var qm = new QueryManager()) {
            requireAnalysis(qm, id);
        }
        final List<ComponentAnalysisDao.ComponentAnalysisComment> comments = withJdbiHandle(
                handle -> new ComponentAnalysisDao(handle).getComments(id));
        return Response.ok(ListComponentAnalysisCommentsResponse.builder()
                .comments(comments.stream()
                        .<ComponentAnalysisComment>map(comment -> ComponentAnalysisComment.builder()
                                .timestamp(comment.timestamp().toEpochMilli())
                                .commenter(comment.commenter())
                                .comment(comment.comment())
                                .build())
                        .toList())
                .build()).build();
    }

    @Override
    @PermissionRequired(Permissions.Constants.COMPONENT_ANALYSIS)
    public Response createComponentAnalysisComment(final Long id, final CreateComponentAnalysisCommentRequest request) {
        try (final var qm = new QueryManager()) {
            requireAnalysis(qm, id);
        }
        final String commenter = getPrincipal().getName();
        inJdbiTransaction(handle -> new ComponentAnalysisDao(handle)
                .createComments(List.of(new CreateCommentCommand(id, commenter, request.getComment()))));
        return Response.created(uriInfo.getBaseUriBuilder()
                        .path("/component-analyses")
                        .path(String.valueOf(id))
                        .path("/comments")
                        .build())
                .build();
    }

    /**
     * Curation is scoped like everything else in the portfolio: the project
     * must exist (404) and the principal must have access to it (403).
     */
    private Project requireProject(final QueryManager qm, final UUID uuid) {
        final Project project = qm.getObjectByUuid(Project.class, uuid);
        if (project == null) {
            throw new NotFoundException();
        }
        requireAccess(qm, project);
        return project;
    }

    /**
     * An analysis addressed by id carries its project; access is checked on
     * that project.
     */
    private ComponentAnalysis requireAnalysis(final QueryManager qm, final long id) {
        final ComponentAnalysis analysis = withJdbiHandle(handle -> new ComponentAnalysisDao(handle).getById(id))
                .orElseThrow(NotFoundException::new);
        requireAccess(qm, qm.getObjectById(Project.class, analysis.projectId()));
        return analysis;
    }

    private static org.dependencytrack.api.v2.model.ComponentAnalysis mapAnalysis(
            final QueryManager qm, final ComponentAnalysis analysis) {
        final String licenseIdOrName = analysis.licenseId() != null
                ? LicenseOverrideResolver.licenseLabel(qm, analysis.licenseId())
                : null;
        // the snapshot keeps the three slots apart; the response carries the
        // value plus which slot it came from, since the policies judge an id,
        // a name and an expression differently
        String declaredLicense = analysis.declaredLicenseExpression();
        String declaredLicenseKind = declaredLicense != null ? "expression" : null;
        if (declaredLicense == null && analysis.declaredLicenseId() != null) {
            declaredLicense = LicenseOverrideResolver.licenseLabel(qm, analysis.declaredLicenseId());
            declaredLicenseKind = "id";
        }
        if (declaredLicense == null && analysis.declaredLicenseName() != null) {
            declaredLicense = analysis.declaredLicenseName();
            declaredLicenseKind = "name";
        }
        return org.dependencytrack.api.v2.model.ComponentAnalysis.builder()
                .id(analysis.id())
                .purl(analysis.purl())
                .group(analysis.group())
                .name(analysis.name())
                .version(analysis.version())
                .license(licenseIdOrName)
                .licenseExpression(analysis.licenseExpression())
                .licenseName(analysis.licenseName())
                .declaredLicense(declaredLicense)
                .declaredLicenseKind(declaredLicenseKind)
                .details(analysis.details())
                .build();
    }
}
