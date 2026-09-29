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
package org.dependencytrack.support.distrometadata;

import com.github.packageurl.PackageURL;
import org.jspecify.annotations.Nullable;

/**
 * Source package an OS package was built from.
 * <p>
 * Distro advisories (Alpine secdb, Debian and Ubuntu trackers) are keyed by source package,
 * which often differs from the binary package, e.g. {@code libssl3} is built from {@code openssl}.
 * A {@code null} version means the source version equals the binary version.
 *
 * @param name    Source package name
 * @param version Source package version, without release for RPM
 * @param release Source package release, RPM only
 */
public record SourcePackage(String name, @Nullable String version, @Nullable String release) {

    /**
     * Derives the source package from the {@code upstream} PURL qualifier, as written by syft:
     * {@code openssl} (apk), {@code gcc-defaults@1.203} (deb), {@code openssl-3.5.5-6.el9_8.src.rpm} (rpm).
     *
     * @return The source package, or {@code null} if the PURL has none or it could not be parsed
     */
    public static @Nullable SourcePackage ofUpstreamQualifier(PackageURL purl) {
        // Qualifier values are already percent-decoded by PackageURL.
        final String upstream = purl.getQualifiers() != null
                ? purl.getQualifiers().get("upstream")
                : null;
        if (isBlank(upstream)) {
            return null;
        }

        return switch (purl.getType()) {
            case "apk" -> ofName(upstream);
            case "deb" -> ofNameAndVersion(upstream);
            case "rpm" -> ofSourceRpm(upstream);
            default -> null;
        };
    }

    public static @Nullable SourcePackage ofName(@Nullable String name) {
        return isBlank(name) ? null : new SourcePackage(name, null, null);
    }

    /**
     * Parses {@code <name>[@<version>]}.
     */
    public static @Nullable SourcePackage ofNameAndVersion(@Nullable String nameAndVersion) {
        if (isBlank(nameAndVersion)) {
            return null;
        }

        final int atIndex = nameAndVersion.indexOf('@');
        if (atIndex < 0) {
            return new SourcePackage(nameAndVersion, null, null);
        }
        if (atIndex == 0) {
            return null;
        }

        return new SourcePackage(
                nameAndVersion.substring(0, atIndex),
                blankToNull(nameAndVersion.substring(atIndex + 1)),
                null);
    }

    /**
     * Parses an SRPM file name ({@code <name>-<version>-<release>.<arch>.rpm}),
     * the same way Trivy's own RPM analyzer does.
     */
    public static @Nullable SourcePackage ofSourceRpm(@Nullable String sourceRpm) {
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

    private static @Nullable String blankToNull(@Nullable String value) {
        return isBlank(value) ? null : value;
    }

    private static boolean isBlank(@Nullable String value) {
        return value == null || value.isBlank();
    }

}
