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

import java.util.ArrayList;
import java.util.List;

/**
 * Data Transfer Object for Presentation Submission.
 * Per OpenID4VP and Presentation Exchange specifications, this describes
 * how the submitted credentials map to the presentation definition.
 */
public class PresentationSubmissionDTO {

    /**
     * Unique identifier for this presentation submission.
     */
    @SerializedName("id")
    private String id;

    /**
     * The ID of the presentation definition this submission fulfills.
     */
    @SerializedName("definition_id")
    private String definitionId;

    /**
     * List of descriptor maps indicating which credentials fulfill
     * which input descriptors.
     */
    @SerializedName("descriptor_map")
    private List<DescriptorMapDTO> descriptorMap;

    /**
     * Default constructor.
     */
    public PresentationSubmissionDTO() {
    }

    /**
     * Get the submission ID.
     *
     * @return Submission ID
     */
    public String getId() {

        return id;
    }

    /**
     * Set the submission ID.
     *
     * @param submissionId Submission ID
     */
    public void setId(final String submissionId) {

        this.id = submissionId;
    }

    /**
     * Get the definition ID.
     *
     * @return Definition ID
     */
    public String getDefinitionId() {

        return definitionId;
    }

    /**
     * Set the definition ID.
     *
     * @param defId Definition ID
     */
    public void setDefinitionId(final String defId) {

        this.definitionId = defId;
    }

    /**
     * Get the descriptor map.
     *
     * @return Descriptor map list
     */
    public List<DescriptorMapDTO> getDescriptorMap() {

        return descriptorMap != null ? new ArrayList<>(descriptorMap) : null;
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
        if (definitionId == null || definitionId.trim().isEmpty()) {
            return false;
        }
        if (descriptorMap == null || descriptorMap.isEmpty()) {
            return false;
        }
        // Validate each descriptor map entry
        for (DescriptorMapDTO desc : descriptorMap) {
            if (desc == null || !desc.isValid()) {
                return false;
            }
        }
        return true;
    }

    @Override
    public String toString() {

        return "PresentationSubmissionDTO{"
                + "id='" + id + '\''
                + ", definitionId='" + definitionId + '\''
                + ", descriptorMapSize="
                + (descriptorMap != null ? descriptorMap.size() : 0)
                + '}';
    }
}
