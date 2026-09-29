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
package org.dependencytrack.vulnanalysis.internal;

import com.github.packageurl.PackageURL;
import org.dependencytrack.support.distrometadata.SourcePackage;
import org.jspecify.annotations.Nullable;
import us.springett.parsers.cpe.Cpe;

/**
 * @param sourcePackage Source package of an OS package, if it is known and
 *                      distro advisories are keyed by it (apk, deb)
 * @since 5.0.0
 */
record CandidateComponent(
        long id,
        @Nullable Cpe parsedCpe,
        @Nullable PackageURL parsedPurl,
        @Nullable SourcePackage sourcePackage) {
}
