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
package org.dependencytrack.policy.cel.persistence;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.protobuf.util.JsonFormat;
import org.dependencytrack.common.Mappers;
import org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil;
import org.dependencytrack.proto.policy.v1.Component;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.result.UnableToProduceResultException;
import org.jdbi.v3.core.statement.StatementContext;

import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;

public final class CelPolicyComponentRowMapper implements RowMapper<Component> {

    @Override
    public Component map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        final Component.Builder builder = Component.newBuilder();
        maybeSet(rs, "uuid", ResultSet::getString, builder::setUuid);
        maybeSet(rs, "group", ResultSet::getString, builder::setGroup);
        maybeSet(rs, "name", ResultSet::getString, builder::setName);
        maybeSet(rs, "version", ResultSet::getString, builder::setVersion);
        maybeSet(rs, "classifier", ResultSet::getString, builder::setClassifier);
        maybeSet(rs, "cpe", ResultSet::getString, builder::setCpe);
        maybeSet(rs, "purl", ResultSet::getString, builder::setPurl);
        maybeSet(rs, "swid_tag_id", ResultSet::getString, builder::setSwidTagId);
        maybeSet(rs, "is_internal", ResultSet::getBoolean, builder::setIsInternal);
        maybeSet(rs, "md5", ResultSet::getString, builder::setMd5);
        maybeSet(rs, "sha1", ResultSet::getString, builder::setSha1);
        maybeSet(rs, "sha256", ResultSet::getString, builder::setSha256);
        maybeSet(rs, "sha384", ResultSet::getString, builder::setSha384);
        maybeSet(rs, "sha512", ResultSet::getString, builder::setSha512);
        maybeSet(rs, "sha3_256", ResultSet::getString, builder::setSha3256);
        maybeSet(rs, "sha3_384", ResultSet::getString, builder::setSha3384);
        maybeSet(rs, "sha3_512", ResultSet::getString, builder::setSha3512);
        maybeSet(rs, "blake2b_256", ResultSet::getString, builder::setBlake2B256);
        maybeSet(rs, "blake2b_384", ResultSet::getString, builder::setBlake2B384);
        maybeSet(rs, "blake2b_512", ResultSet::getString, builder::setBlake2B512);
        maybeSet(rs, "blake3", ResultSet::getString, builder::setBlake3);
        maybeSet(rs, "license_name", ResultSet::getString, builder::setLicenseName);
        maybeSet(rs, "license_expression", ResultSet::getString, builder::setLicenseExpression);
        maybeSet(rs, "license_curated", ResultSet::getBoolean, builder::setLicenseCurated);
        maybeSet(rs, "published_at", RowMapperUtil::nullableTimestamp, builder::setPublishedAt);
        maybeSet(rs, "latest_version", ResultSet::getString, builder::setLatestVersion);
        maybeSet(rs, "latest_version_published_at", RowMapperUtil::nullableTimestamp, builder::setLatestVersionPublishedAt);
        maybeSet(rs, "package_artifact_md5", ResultSet::getString, builder::setPackageArtifactMd5);
        maybeSet(rs, "package_artifact_sha1", ResultSet::getString, builder::setPackageArtifactSha1);
        maybeSet(rs, "package_artifact_sha256", ResultSet::getString, builder::setPackageArtifactSha256);
        maybeSet(rs, "package_artifact_sha512", ResultSet::getString, builder::setPackageArtifactSha512);
        maybeSet(rs, "properties", CelPolicyComponentRowMapper::maybeConvertProperties, builder::addAllProperties);
        return builder.build();
    }

    private static final JsonFormat.Parser PROPERTY_JSON_PARSER =
            JsonFormat.parser().ignoringUnknownFields();

    private static List<Component.Property> maybeConvertProperties(
            final ResultSet rs, final String columnName) throws SQLException {
        final String jsonString = rs.getString(columnName);
        if (isBlank(jsonString)) {
            return Collections.emptyList();
        }

        // Protobuf's JsonFormat.Parser can't deserialize JSON arrays, so the
        // aggregated array is walked with Jackson and each object parsed alone.
        final var properties = new ArrayList<Component.Property>();
        try (final JsonParser jsonParser = Mappers.jsonMapper().createParser(jsonString)) {
            if (jsonParser.nextToken() != JsonToken.START_ARRAY) {
                return Collections.emptyList();
            }

            while (jsonParser.nextToken() != JsonToken.END_ARRAY) {
                if (jsonParser.currentToken() == JsonToken.START_OBJECT) {
                    final JsonNode objectNode = jsonParser.readValueAsTree();
                    final var propertyBuilder = Component.Property.newBuilder();
                    PROPERTY_JSON_PARSER.merge(objectNode.toString(), propertyBuilder);
                    properties.add(propertyBuilder.build());
                } else {
                    jsonParser.skipChildren();
                }
            }
        } catch (IOException e) {
            throw new UnableToProduceResultException(e);
        }
        return properties;
    }
}
