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

import jakarta.ws.rs.BadRequestException;
import org.dependencytrack.model.License;
import org.dependencytrack.parser.spdx.expression.SpdxExpression;
import org.dependencytrack.parser.spdx.expression.SpdxExpressionParseException;
import org.dependencytrack.parser.spdx.expression.SpdxExpressionParser;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.ComponentAnalysisDao.LicenseOverride;
import org.jspecify.annotations.Nullable;

/**
 * Turns the three license fields of an analysis or component-policy request
 * into a {@link LicenseOverride}: exactly one of a license (SPDX ID or custom
 * license name), a well-formed SPDX expression whose every license is one DT
 * can attach, or a free-text name. Anything else is a 400.
 */
final class LicenseOverrideResolver {

    private LicenseOverrideResolver() {
    }

    static LicenseOverride resolve(
            final QueryManager qm,
            @Nullable final String license,
            @Nullable final String licenseExpression,
            @Nullable final String licenseName) {
        final String id = blankToNull(license);
        final String expression = blankToNull(licenseExpression);
        final String name = blankToNull(licenseName);
        final int slots = (id != null ? 1 : 0) + (expression != null ? 1 : 0) + (name != null ? 1 : 0);
        if (slots > 1) {
            throw new BadRequestException("Exactly one of license, license_expression and license_name may be set");
        }
        if (id != null) {
            return new LicenseOverride(resolveLicense(qm, id).getId(), null, null);
        }
        if (expression != null) {
            validateExpression(qm, expression);
            return new LicenseOverride(null, expression, null);
        }
        if (name != null) {
            return new LicenseOverride(null, null, name);
        }
        return LicenseOverride.NONE;
    }

    /**
     * Resolves an SPDX license ID or (custom) license name; 400 when unknown —
     * overrides must reference licenses DT can attach to components.
     */
    static License resolveLicense(final QueryManager qm, final String licenseIdOrName) {
        final License license = qm.getLicenseByIdOrName(licenseIdOrName);
        if (license != null && license != License.UNRESOLVED) {
            return license;
        }
        final License customLicense = qm.getCustomLicenseByName(licenseIdOrName);
        if (customLicense != null && customLicense != License.UNRESOLVED) {
            return customLicense;
        }
        throw new BadRequestException("License %s is not known; create it as a custom license first".formatted(licenseIdOrName));
    }

    /**
     * The expression must parse — the policy engine evaluates the stored
     * value with the same parser, and a value it cannot parse would make the
     * license conditions silently false — and every license in it must be one
     * DT can attach.
     */
    private static void validateExpression(final QueryManager qm, final String expression) {
        final SpdxExpression parsed;
        try {
            parsed = SpdxExpressionParser.getInstance().parse(expression);
        } catch (SpdxExpressionParseException e) {
            throw new BadRequestException(
                    "Invalid SPDX expression %s: %s — a single license, including a custom one, goes into `license`"
                            .formatted(expression, e.getMessage()));
        }
        requireKnownLicenses(qm, parsed);
    }

    /**
     * Walks the expression: license identifiers, also under a trailing "+"
     * and on the left of WITH, must resolve. The right-hand side of WITH is an
     * exception, not a license: the catalogue holds no SPDX exceptions, so it
     * is accepted as written.
     */
    private static void requireKnownLicenses(final QueryManager qm, final SpdxExpression node) {
        switch (node) {
            case SpdxExpression.Identifier identifier -> resolveLicense(qm, identifier.id());
            case SpdxExpression.OrLater orLater -> resolveLicense(qm, orLater.license().id());
            case SpdxExpression.With with -> requireKnownLicenses(qm, with.license());
            case SpdxExpression.And and -> and.operands().forEach(operand -> requireKnownLicenses(qm, operand));
            case SpdxExpression.Or or -> or.operands().forEach(operand -> requireKnownLicenses(qm, operand));
        }
    }

    /**
     * Display label of an override: the license's SPDX ID or custom name, the
     * expression, the free-text name, or "not set".
     */
    static String label(final QueryManager qm, final LicenseOverride override) {
        if (override.licenseId() != null) {
            final License license = qm.getObjectById(License.class, override.licenseId());
            if (license == null) {
                return "unknown";
            }
            return license.getLicenseId() != null ? license.getLicenseId() : license.getName();
        }
        if (override.licenseExpression() != null) {
            return override.licenseExpression();
        }
        if (override.licenseName() != null) {
            return override.licenseName();
        }
        return "not set";
    }

    private static @Nullable String blankToNull(@Nullable final String value) {
        if (value == null) {
            return null;
        }
        final String stripped = value.strip();
        return stripped.isEmpty() ? null : stripped;
    }
}
