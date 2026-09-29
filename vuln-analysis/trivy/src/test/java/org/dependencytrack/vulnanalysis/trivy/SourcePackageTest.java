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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class SourcePackageTest {

    static Stream<Arguments> testOf() {
        return Stream.of(
                // apk: syft property and upstream qualifier
                Arguments.of(
                        "pkg:apk/alpine/libssl3@3.5.7-r0?arch=x86_64&distro=alpine-3.24.1&upstream=openssl",
                        Map.of("syft:metadata:originPackage", "openssl"),
                        new SourcePackage("openssl", null, null)),
                Arguments.of(
                        "pkg:apk/alpine/libssl3@3.5.7-r0?arch=x86_64&distro=alpine-3.24.1&upstream=openssl",
                        Map.of(),
                        new SourcePackage("openssl", null, null)),
                Arguments.of(
                        "pkg:apk/alpine/libssl3@3.5.7-r0?arch=x86_64&distro=alpine-3.24.1",
                        Map.of(),
                        null),

                // deb: source version differs from binary version
                Arguments.of(
                        "pkg:deb/debian/cpp@4%3A12.2.0-3?arch=amd64&distro=debian-12.15&upstream=gcc-defaults%401.203",
                        Map.of("syft:metadata:source", "gcc-defaults", "syft:metadata:sourceVersion", "1.203"),
                        new SourcePackage("gcc-defaults", "1.203", null)),
                Arguments.of(
                        "pkg:deb/debian/cpp@4%3A12.2.0-3?arch=amd64&distro=debian-12.15&upstream=gcc-defaults%401.203",
                        Map.of(),
                        new SourcePackage("gcc-defaults", "1.203", null)),
                // deb: "+" in a version must survive (no form-decoding)
                Arguments.of(
                        "pkg:deb/debian/bash@5.2.15-2%2Bb13?arch=amd64&distro=debian-12.15&upstream=bash%405.2.15-2",
                        Map.of(),
                        new SourcePackage("bash", "5.2.15-2", null)),
                Arguments.of(
                        "pkg:deb/debian/bsdutils@1%3A2.38.1-5%2Bdeb12u3?arch=amd64&distro=debian-12.15&upstream=util-linux%402.38.1-5%2Bdeb12u3",
                        Map.of(),
                        new SourcePackage("util-linux", "2.38.1-5+deb12u3", null)),
                // deb: source name only, version equals binary version
                Arguments.of(
                        "pkg:deb/debian/libssl3@3.0.17-1~deb12u2?arch=amd64&distro=debian-12.15&upstream=openssl",
                        Map.of("syft:metadata:source", "openssl"),
                        new SourcePackage("openssl", null, null)),
                Arguments.of(
                        "pkg:deb/debian/libssl3@3.0.17-1~deb12u2?arch=amd64&distro=debian-12.15&upstream=openssl",
                        Map.of(),
                        new SourcePackage("openssl", null, null)),
                Arguments.of(
                        "pkg:deb/debian/foo@1.0?upstream=%401.0",
                        Map.of(),
                        null),

                // rpm: SRPM file name
                Arguments.of(
                        "pkg:rpm/almalinux/openssl-libs@3.5.5-6.el9_8?arch=x86_64&epoch=1&distro=almalinux-9.8&upstream=openssl-3.5.5-6.el9_8.src.rpm",
                        Map.of("syft:metadata:sourceRpm", "openssl-3.5.5-6.el9_8.src.rpm"),
                        new SourcePackage("openssl", "3.5.5", "6.el9_8")),
                Arguments.of(
                        "pkg:rpm/almalinux/almalinux-gpg-keys@9.8-1.el9?arch=x86_64&distro=almalinux-9.8&upstream=almalinux-release-9.8-1.el9.src.rpm",
                        Map.of(),
                        new SourcePackage("almalinux-release", "9.8", "1.el9")),
                Arguments.of(
                        "pkg:rpm/almalinux/foo@1.0-1?upstream=foo.src.rpm",
                        Map.of(),
                        null),

                // not an OS package type
                Arguments.of(
                        "pkg:pypi/requests@2.32.3?upstream=foo",
                        Map.of(),
                        null));
    }

    @ParameterizedTest
    @MethodSource
    void testOf(String purl, Map<String, String> properties, SourcePackage expected) throws Exception {
        final var component = Component.newBuilder().setPurl(purl);
        properties.forEach((name, value) -> component.addProperties(
                Property.newBuilder().setName(name).setValue(value)));

        assertThat(SourcePackage.of(component.build(), new PackageURL(purl))).isEqualTo(expected);
    }

    @Test
    void testPropertyTakesPrecedenceOverQualifier() throws Exception {
        final String purl = "pkg:apk/alpine/libssl3@3.5.7-r0?upstream=from-qualifier";
        final Component component = Component.newBuilder()
                .setPurl(purl)
                .addProperties(Property.newBuilder()
                        .setName("syft:metadata:originPackage")
                        .setValue("from-property"))
                .build();

        assertThat(SourcePackage.of(component, new PackageURL(purl)))
                .isEqualTo(new SourcePackage("from-property", null, null));
    }

}
