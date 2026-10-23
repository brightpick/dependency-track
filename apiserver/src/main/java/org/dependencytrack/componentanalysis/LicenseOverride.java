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
package org.dependencytrack.componentanalysis;

import org.jspecify.annotations.Nullable;

/**
 * The license an analysis applies — at most one of a resolved license
 * (incl. custom licenses), an SPDX expression, or a free-text name,
 * mirroring the component's three license slots. {@link #NONE} carries
 * no license override (details only).
 */
public record LicenseOverride(
        @Nullable Long licenseId,
        @Nullable String licenseExpression,
        @Nullable String licenseName) {

    public static final LicenseOverride NONE = new LicenseOverride(null, null, null);

    public LicenseOverride {
        if ((licenseId != null ? 1 : 0) + (licenseExpression != null ? 1 : 0)
                + (licenseName != null ? 1 : 0) > 1) {
            throw new IllegalArgumentException("A license override fills at most one license slot");
        }
    }

    public boolean isEmpty() {
        return licenseId == null && licenseExpression == null && licenseName == null;
    }
}
