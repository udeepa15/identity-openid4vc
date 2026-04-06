/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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


import java.util.List;

/**
 * DTO representing the presentation_submission object in a Verifiable Presentation.
 */
public class PresentationSubmission {

    private String id;

    private String definitionId;

    private List<DescriptorMap> descriptorMap;

    /**
     * Returns the presentation submission identifier.
     *
     * @return The presentation submission {@code id}
     */
    public String getId() {

        return id;
    }

    /**
     * Sets the presentation submission identifier.
     *
     * @param id The presentation submission {@code id}
     */
    public void setId(String id) {

        this.id = id;
    }

    /**
     * Returns the Presentation Definition identifier associated with this submission.
     *
     * @return The {@code definition_id} value
     */
    public String getDefinitionId() {

        return definitionId;
    }

    /**
     * Sets the Presentation Definition identifier associated with this submission.
     *
     * @param definitionId The {@code definition_id} value
     */
    public void setDefinitionId(String definitionId) {

        this.definitionId = definitionId;
    }

    /**
     * Returns the descriptor map entries that describe how submitted credentials
     * satisfy the Presentation Definition inputs.
     *
     * @return The list of {@link DescriptorMap} entries
     */
    public List<DescriptorMap> getDescriptorMap() {

        return descriptorMap;
    }

    /**
     * Sets the descriptor map entries that describe how submitted credentials
     * satisfy the Presentation Definition inputs.
     *
     * @param descriptorMap The list of {@link DescriptorMap} entries
     */
    public void setDescriptorMap(List<DescriptorMap> descriptorMap) {

        this.descriptorMap = descriptorMap;
    }

    /**
     * DTO for descriptor map.
     */
    public static class DescriptorMap {

        private String id;

        private String format;

        private String path;

        /**
         * Returns the descriptor identifier.
         *
         * @return The descriptor {@code id}
         */
        public String getId() {

            return id;
        }

        /**
         * Sets the descriptor identifier.
         *
         * @param id The descriptor {@code id}
         */
        public void setId(String id) {

            this.id = id;
        }

        /**
         * Returns the VC format represented by this descriptor mapping.
         *
         * @return The descriptor {@code format}
         */
        public String getFormat() {

            return format;
        }

        /**
         * Sets the VC format represented by this descriptor mapping.
         *
         * @param format The descriptor {@code format}
         */
        public void setFormat(String format) {

            this.format = format;
        }

        /**
         * Returns the JSONPath expression that points to the submitted credential.
         *
         * @return The descriptor {@code path}
         */
        public String getPath() {

            return path;
        }

        /**
         * Sets the JSONPath expression that points to the submitted credential.
         *
         * @param path The descriptor {@code path}
         */
        public void setPath(String path) {

            this.path = path;
        }
    }
}
