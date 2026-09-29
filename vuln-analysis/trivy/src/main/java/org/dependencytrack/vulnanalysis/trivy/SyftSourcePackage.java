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
import org.dependencytrack.support.distrometadata.SourcePackage;
import org.jspecify.annotations.Nullable;

import java.util.HashMap;
import java.util.Map;

/**
 * Resolves the source package of an OS package from an SBOM not produced by Trivy.
 * <p>
 * Sources, in order of precedence:
 * <ul>
 *   <li>syft properties: {@code syft:metadata:originPackage} (apk),
 *       {@code syft:metadata:source} and {@code syft:metadata:sourceVersion} (deb),
 *       {@code syft:metadata:sourceRpm} (rpm)</li>
 *   <li>the {@code upstream} PURL qualifier, see {@link SourcePackage#ofUpstreamQualifier(PackageURL)}</li>
 * </ul>
 */
final class SyftSourcePackage {

    private static final String SYFT_ORIGIN_PACKAGE = "syft:metadata:originPackage";
    private static final String SYFT_SOURCE = "syft:metadata:source";
    private static final String SYFT_SOURCE_VERSION = "syft:metadata:sourceVersion";
    private static final String SYFT_SOURCE_RPM = "syft:metadata:sourceRpm";

    private SyftSourcePackage() {
    }

    static @Nullable SourcePackage of(Component component, PackageURL purl) {
        final Map<String, String> properties = new HashMap<>();
        for (final Property property : component.getPropertiesList()) {
            properties.putIfAbsent(property.getName(), property.getValue());
        }

        final SourcePackage fromProperties = switch (purl.getType()) {
            case "apk" -> SourcePackage.ofName(properties.get(SYFT_ORIGIN_PACKAGE));
            case "deb" -> {
                final SourcePackage source = SourcePackage.ofName(properties.get(SYFT_SOURCE));
                final String sourceVersion = properties.get(SYFT_SOURCE_VERSION);
                yield source != null && sourceVersion != null && !sourceVersion.isBlank()
                        ? new SourcePackage(source.name(), sourceVersion, null)
                        : source;
            }
            case "rpm" -> SourcePackage.ofSourceRpm(properties.get(SYFT_SOURCE_RPM));
            default -> null;
        };

        return fromProperties != null
                ? fromProperties
                : SourcePackage.ofUpstreamQualifier(purl);
    }

}
