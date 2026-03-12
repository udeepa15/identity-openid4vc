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
 * Data Transfer Object for nested path in Descriptor Map.
 * Used when a credential is nested within a Verifiable Presentation.
 */
public class PathNestedDTO {

    /**
     * The format of the nested credential.
     */
    @SerializedName("format")
    private String format;

    /**
     * JSONPath expression pointing to the nested credential.
     */
    @SerializedName("path")
    private String path;

    /**
     * Get the format.
     *
     * @return Credential format
     */
    public String getFormat() {

        return format;
    }

    /**
     * Set the format.
     *
     * @param credFormat Credential format
     */
    public void setFormat(final String credFormat) {

        this.format = credFormat;
    }

    /**
     * Get the path.
     *
     * @return JSONPath expression
     */
    public String getPath() {

        return path;
    }

    /**
     * Set the path.
     *
     * @param jsonPath JSONPath expression
     */
    public void setPath(final String jsonPath) {

        this.path = jsonPath;
    }

    @Override
    public String toString() {

        return "PathNestedDTO{"
                + "format='" + format + '\''
                + ", path='" + path + '\''
                + '}';
    }
}
