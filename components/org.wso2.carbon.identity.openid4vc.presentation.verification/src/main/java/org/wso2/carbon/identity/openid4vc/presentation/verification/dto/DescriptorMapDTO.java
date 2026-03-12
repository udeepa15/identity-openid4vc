/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openid4vc.presentation.verification.dto;

import com.google.gson.annotations.SerializedName;

/**
 * Data Transfer Object for Descriptor Map entries in Presentation Submission.
 * Maps input descriptors from the presentation definition to submitted
 * credentials.
 */
public class DescriptorMapDTO {

    /**
     * The ID of the input descriptor from the presentation definition.
     */
    @SerializedName("id")
    private String id;

    /**
     * The format of the submitted credential (e.g., jwt_vp, ldp_vp, vc+sd-jwt).
     */
    @SerializedName("format")
    private String format;

    /**
     * JSONPath expression pointing to the credential in the VP token.
     */
    @SerializedName("path")
    private String path;

    /**
     * Optional nested path for credentials within a VP.
     */
    @SerializedName("path_nested")
    private PathNestedDTO pathNested;

    /**
     * Get the input descriptor ID.
     *
     * @return Input descriptor ID
     */
    public String getId() {

        return id;
    }

    /**
     * Set the input descriptor ID.
     *
     * @param descId Input descriptor ID
     */
    public void setId(final String descId) {

        this.id = descId;
    }

    /**
     * Get the credential format.
     *
     * @return Credential format
     */
    public String getFormat() {

        return format;
    }

    /**
     * Set the credential format.
     *
     * @param credFormat Credential format
     */
    public void setFormat(final String credFormat) {

        this.format = credFormat;
    }

    /**
     * Get the path to the credential.
     *
     * @return JSONPath expression
     */
    public String getPath() {

        return path;
    }

    /**
     * Set the path to the credential.
     *
     * @param jsonPath JSONPath expression
     */
    public void setPath(final String jsonPath) {

        this.path = jsonPath;
    }

    /**
     * Validate that required fields are present.
     *
     * @return true if valid, false otherwise
     */
    public boolean isValid() {

        if (id == null || id.trim().isEmpty()) {
            return false;
        }
        if (format == null || format.trim().isEmpty()) {
            return false;
        }
        if (path == null || path.trim().isEmpty()) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {

        return "DescriptorMapDTO{"
                + "id='" + id + '\''
                + ", format='" + format + '\''
                + ", path='" + path + '\''
                + ", pathNested=" + pathNested
                + '}';
    }
}
