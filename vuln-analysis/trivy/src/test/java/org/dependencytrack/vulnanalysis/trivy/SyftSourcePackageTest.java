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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class SyftSourcePackageTest {

    static Stream<Arguments> testOf() {
        return Stream.of(
                // apk
                Arguments.of(
                        "pkg:apk/alpine/libssl3@3.5.7-r0?distro=alpine-3.24.1",
                        Map.of("syft:metadata:originPackage", "openssl"),
                        new SourcePackage("openssl", null, null)),

                // deb
                Arguments.of(
                        "pkg:deb/debian/cpp@4%3A12.2.0-3?distro=debian-12.15",
                        Map.of("syft:metadata:source", "gcc-defaults", "syft:metadata:sourceVersion", "1.203"),
                        new SourcePackage("gcc-defaults", "1.203", null)),
                Arguments.of(
                        "pkg:deb/debian/libssl3@3.0.17-1~deb12u2?distro=debian-12.15",
                        Map.of("syft:metadata:source", "openssl"),
                        new SourcePackage("openssl", null, null)),

                // rpm
                Arguments.of(
                        "pkg:rpm/almalinux/openssl-libs@3.5.5-6.el9_8?epoch=1&distro=almalinux-9.8",
                        Map.of("syft:metadata:sourceRpm", "openssl-3.5.5-6.el9_8.src.rpm"),
                        new SourcePackage("openssl", "3.5.5", "6.el9_8")),

                // properties take precedence over the upstream qualifier
                Arguments.of(
                        "pkg:apk/alpine/libssl3@3.5.7-r0?upstream=from-qualifier",
                        Map.of("syft:metadata:originPackage", "from-property"),
                        new SourcePackage("from-property", null, null)),
                // falls back to the upstream qualifier without (usable) properties
                Arguments.of(
                        "pkg:apk/alpine/libssl3@3.5.7-r0?upstream=openssl",
                        Map.of(),
                        new SourcePackage("openssl", null, null)),
                Arguments.of(
                        "pkg:rpm/almalinux/openssl-libs@3.5.5-6.el9_8?upstream=openssl-3.5.5-6.el9_8.src.rpm",
                        Map.of("syft:metadata:sourceRpm", "garbage"),
                        new SourcePackage("openssl", "3.5.5", "6.el9_8")),

                // neither
                Arguments.of("pkg:apk/alpine/libssl3@3.5.7-r0", Map.of(), null),
                Arguments.of("pkg:pypi/requests@2.32.3", Map.of("syft:metadata:source", "foo"), null));
    }

    @ParameterizedTest
    @MethodSource
    void testOf(String purl, Map<String, String> properties, SourcePackage expected) throws Exception {
        final var component = Component.newBuilder().setPurl(purl);
        properties.forEach((name, value) -> component.addProperties(
                Property.newBuilder().setName(name).setValue(value)));

        assertThat(SyftSourcePackage.of(component.build(), new PackageURL(purl))).isEqualTo(expected);
    }

}
