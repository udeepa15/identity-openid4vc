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

import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.List;

/**
 * DTO representing the presentation_submission object in a Verifiable Presentation.
 */
public class PresentationSubmission implements Serializable {

    private static final long serialVersionUID = 753159842601L;

    @JsonProperty("id")
    private String id;

    @JsonProperty("definition_id")
    private String definitionId;

    @JsonProperty("descriptor_map")
    private List<DescriptorMap> descriptorMap;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getDefinitionId() {
        return definitionId;
    }

    public void setDefinitionId(String definitionId) {
        this.definitionId = definitionId;
    }

    public List<DescriptorMap> getDescriptorMap() {
        return descriptorMap;
    }

    public void setDescriptorMap(List<DescriptorMap> descriptorMap) {
        this.descriptorMap = descriptorMap;
    }

    /**
     * DTO for descriptor map.
     */
    public static class DescriptorMap implements Serializable {

        private static final long serialVersionUID = 951357846201L;

        @JsonProperty("id")
        private String id;

        @JsonProperty("format")
        private String format;

        @JsonProperty("path")
        private String path;

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getFormat() {
            return format;
        }

        public void setFormat(String format) {
            this.format = format;
        }

        public String getPath() {
            return path;
        }

        public void setPath(String path) {
            this.path = path;
        }
    }
}
