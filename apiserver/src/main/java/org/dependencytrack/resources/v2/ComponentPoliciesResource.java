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
import dev.cel.common.CelValidationException;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.Provider;
import org.dependencytrack.api.v2.ComponentPoliciesApi;
import org.dependencytrack.api.v2.model.ComponentPolicy;
import org.dependencytrack.api.v2.model.ListComponentPoliciesResponse;
import org.dependencytrack.api.v2.model.UpsertComponentPolicyRequest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.exception.AlreadyExistsException;
import org.dependencytrack.componentanalysis.LicenseOverride;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.ComponentPolicyDao;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.policy.cel.CelPolicyCompiler;
import org.dependencytrack.policy.cel.CelPolicyType;

import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.util.PersistenceUtil.isUniqueConstraintViolation;

/**
 * REST resource for component policies (automated license curation rules).
 * <p>
 * A component policy is curation at scale — it writes the same component
 * analyses a manual override does — so the curation permission grants it,
 * next to policy management. The portfolio gate policies stay with policy
 * management alone.
 */
@Provider
public final class ComponentPoliciesResource extends AbstractApiResource implements ComponentPoliciesApi {

    @Context
    private UriInfo uriInfo;

    @Override
    @PermissionRequired({Permissions.Constants.POLICY_MANAGEMENT, Permissions.Constants.COMPONENT_ANALYSIS})
    public Response listComponentPolicies() {
        final List<ComponentPolicyDao.ComponentPolicy> policies = withJdbiHandle(
                handle -> new ComponentPolicyDao(handle).getAll());
        try (final var qm = new QueryManager()) {
            return Response.ok(ListComponentPoliciesResponse.builder()
                    .policies(policies.stream()
                            .<ComponentPolicy>map(policy -> mapPolicy(qm, policy))
                            .toList())
                    .build()).build();
        }
    }

    @Override
    @PermissionRequired({Permissions.Constants.POLICY_MANAGEMENT, Permissions.Constants.COMPONENT_ANALYSIS})
    public Response createComponentPolicy(final UpsertComponentPolicyRequest request) {
        validateCondition(request.getCondition());
        try (final var qm = new QueryManager()) {
            final LicenseOverride override = LicenseOverrideResolver.resolve(
                    qm, request.getLicense(), request.getLicenseExpression(), request.getLicenseName());
            final long id = orNameConflict(request.getName(), () -> inJdbiTransaction(handle -> {
                final var dao = new ComponentPolicyDao(handle);
                return dao.create(
                    request.getName(), request.getDescription(), getPrincipal().getName(),
                    Objects.requireNonNullElse(request.getEnabled(), true),
                    Objects.requireNonNullElse(request.getPriority(), 0),
                    request.getCondition(), override, request.getDetails(),
                    request.getValidFrom() != null ? request.getValidFrom().toInstant() : null,
                    request.getValidUntil() != null ? request.getValidUntil().toInstant() : null);
            }));
            return Response.created(uriInfo.getBaseUriBuilder()
                            .path("/component-policies")
                            .path(String.valueOf(id))
                            .build())
                    .build();
        }
    }

    @Override
    @PermissionRequired({Permissions.Constants.POLICY_MANAGEMENT, Permissions.Constants.COMPONENT_ANALYSIS})
    public Response updateComponentPolicy(final Long id, final UpsertComponentPolicyRequest request) {
        validateCondition(request.getCondition());
        try (final var qm = new QueryManager()) {
            final LicenseOverride override = LicenseOverrideResolver.resolve(
                    qm, request.getLicense(), request.getLicenseExpression(), request.getLicenseName());
            final boolean updated = orNameConflict(request.getName(), () -> inJdbiTransaction(handle -> {
                final var dao = new ComponentPolicyDao(handle);
                return dao.update(
                    id, request.getName(), request.getDescription(),
                    Objects.requireNonNullElse(request.getEnabled(), true),
                    Objects.requireNonNullElse(request.getPriority(), 0),
                    request.getCondition(), override, request.getDetails(),
                    request.getValidFrom() != null ? request.getValidFrom().toInstant() : null,
                    request.getValidUntil() != null ? request.getValidUntil().toInstant() : null);
            }));
            if (!updated) {
                throw new NotFoundException();
            }
            return Response.noContent().build();
        }
    }

    @Override
    @PermissionRequired({Permissions.Constants.POLICY_MANAGEMENT, Permissions.Constants.COMPONENT_ANALYSIS})
    public Response deleteComponentPolicy(final Long id) {
        final boolean deleted = inJdbiTransaction(
                handle -> new ComponentPolicyDao(handle).delete(id));
        if (!deleted) {
            throw new NotFoundException();
        }
        return Response.noContent().build();
    }

    /**
     * Policy names are unique: the unique index rejects a taken name, and
     * that is a 409 naming the name, not a database error. An update of an
     * unknown id changes no row, so it stays a 404 whatever its name.
     */
    private static <T> T orNameConflict(final String name, final Supplier<T> action) {
        try {
            return action.get();
        } catch (RuntimeException e) {
            if (isUniqueConstraintViolation(e)) {
                throw new AlreadyExistsException(
                        "A component policy named \"%s\" already exists".formatted(name), e);
            }
            throw e;
        }
    }

    /**
     * The condition must compile as a component policy condition.
     */
    private static void validateCondition(final String condition) {
        try {
            CelPolicyCompiler.getInstance(CelPolicyType.COMPONENT)
                    .compile(condition, CelPolicyCompiler.CacheMode.NO_CACHE);
        } catch (CelValidationException e) {
            throw new BadRequestException("Invalid CEL condition: " + e.getMessage());
        }
    }

    private static ComponentPolicy mapPolicy(final QueryManager qm, final ComponentPolicyDao.ComponentPolicy policy) {
        final String license = policy.licenseId() != null
                ? LicenseOverrideResolver.licenseLabel(qm, policy.licenseId())
                : null;
        return ComponentPolicy.builder()
                .id(policy.id())
                .name(policy.name())
                .description(policy.description())
                .author(policy.author())
                .enabled(policy.enabled())
                .priority(policy.priority())
                .condition(policy.condition())
                .license(license)
                .licenseExpression(policy.licenseExpression())
                .licenseName(policy.licenseName())
                .details(policy.details())
                .validFrom(policy.validFrom() != null
                        ? policy.validFrom().atOffset(java.time.ZoneOffset.UTC) : null)
                .validUntil(policy.validUntil() != null
                        ? policy.validUntil().atOffset(java.time.ZoneOffset.UTC) : null)
                .build();
    }
}
