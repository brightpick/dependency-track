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
package org.dependencytrack.vulnanalysis.trivy;

import com.github.packageurl.PackageURL;
import org.cyclonedx.proto.v1_7.Component;
import org.cyclonedx.proto.v1_7.Property;
import org.jspecify.annotations.Nullable;

import java.util.HashMap;
import java.util.Map;

/**
 * Source package of an OS package, as recorded by SBOM generators other than Trivy.
 * <p>
 * Sources, in order of precedence:
 * <ul>
 *   <li>syft properties: {@code syft:metadata:originPackage} (apk),
 *       {@code syft:metadata:source} and {@code syft:metadata:sourceVersion} (deb),
 *       {@code syft:metadata:sourceRpm} (rpm)</li>
 *   <li>the {@code upstream} PURL qualifier, as written by syft: {@code openssl} (apk),
 *       {@code gcc-defaults@1.203} (deb), {@code openssl-3.5.5-6.el9_8.src.rpm} (rpm)</li>
 * </ul>
 * A {@code null} version means the source version equals the binary version.
 *
 * @param name    Source package name
 * @param version Source package version, without release for RPM
 * @param release Source package release, RPM only
 */
record SourcePackage(String name, @Nullable String version, @Nullable String release) {

    private static final String SYFT_ORIGIN_PACKAGE = "syft:metadata:originPackage";
    private static final String SYFT_SOURCE = "syft:metadata:source";
    private static final String SYFT_SOURCE_VERSION = "syft:metadata:sourceVersion";
    private static final String SYFT_SOURCE_RPM = "syft:metadata:sourceRpm";

    static @Nullable SourcePackage of(Component component, PackageURL purl) {
        final Map<String, String> properties = new HashMap<>();
        for (final Property property : component.getPropertiesList()) {
            properties.putIfAbsent(property.getName(), property.getValue());
        }

        // Qualifier values are already percent-decoded by PackageURL.
        final String upstream = purl.getQualifiers() != null
                ? purl.getQualifiers().get("upstream")
                : null;

        return switch (purl.getType()) {
            case "apk" -> ofName(firstNonBlank(properties.get(SYFT_ORIGIN_PACKAGE), upstream));
            case "deb" -> {
                final String source = properties.get(SYFT_SOURCE);
                yield isBlank(source)
                        ? ofDebianUpstream(upstream)
                        : new SourcePackage(source, blankToNull(properties.get(SYFT_SOURCE_VERSION)), null);
            }
            case "rpm" -> ofSourceRpm(firstNonBlank(properties.get(SYFT_SOURCE_RPM), upstream));
            default -> null;
        };
    }

    private static @Nullable SourcePackage ofName(@Nullable String name) {
        return isBlank(name) ? null : new SourcePackage(name, null, null);
    }

    /**
     * Parses {@code <name>[@<version>]}.
     */
    private static @Nullable SourcePackage ofDebianUpstream(@Nullable String upstream) {
        if (isBlank(upstream)) {
            return null;
        }

        final int atIndex = upstream.indexOf('@');
        if (atIndex < 0) {
            return new SourcePackage(upstream, null, null);
        }
        if (atIndex == 0) {
            return null;
        }

        return new SourcePackage(
                upstream.substring(0, atIndex),
                blankToNull(upstream.substring(atIndex + 1)),
                null);
    }

    /**
     * Parses an SRPM file name ({@code <name>-<version>-<release>.<arch>.rpm}),
     * the same way Trivy's own RPM analyzer does.
     */
    private static @Nullable SourcePackage ofSourceRpm(@Nullable String sourceRpm) {
        if (isBlank(sourceRpm) || !sourceRpm.endsWith(".rpm")) {
            return null;
        }

        String remainder = sourceRpm.substring(0, sourceRpm.length() - ".rpm".length());

        final int archIndex = remainder.lastIndexOf('.');
        if (archIndex < 0) {
            return null;
        }
        remainder = remainder.substring(0, archIndex);

        final int releaseIndex = remainder.lastIndexOf('-');
        if (releaseIndex <= 0) {
            return null;
        }
        final String release = remainder.substring(releaseIndex + 1);
        remainder = remainder.substring(0, releaseIndex);

        final int versionIndex = remainder.lastIndexOf('-');
        if (versionIndex <= 0) {
            return null;
        }
        final String version = remainder.substring(versionIndex + 1);
        final String name = remainder.substring(0, versionIndex);

        if (version.isEmpty() || release.isEmpty()) {
            return null;
        }

        return new SourcePackage(name, version, release);
    }

    private static @Nullable String firstNonBlank(@Nullable String first, @Nullable String second) {
        return !isBlank(first) ? first : second;
    }

    private static @Nullable String blankToNull(@Nullable String value) {
        return isBlank(value) ? null : value;
    }

    private static boolean isBlank(@Nullable String value) {
        return value == null || value.isBlank();
    }

}
