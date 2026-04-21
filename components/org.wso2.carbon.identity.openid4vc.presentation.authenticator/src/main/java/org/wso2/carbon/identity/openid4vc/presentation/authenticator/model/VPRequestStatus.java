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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.model;

/**
 * Enum representing the status of a Verifiable Presentation Request.
 */
public enum VPRequestStatus {

    /**
     * Authorization request created, waiting for VP submission from the wallet.
     */
    ACTIVE("ACTIVE"),

    /**
     * Verifiable Presentation has been submitted by the wallet.
     */
    VP_SUBMITTED("VP_SUBMITTED"),

    /**
     * Verification process has been completed successfully.
     */
    VERIFIED("VERIFIED"),

    /**
     * Request was invalidated.
     */
    FAILED("FAILED");

    /**
     * String value of the status.
     */
    private final String value;

    /**
     * Constructor for VPRequestStatus enum.
     *
     * @param value String value of the status.
     */
    VPRequestStatus(String value) {

        this.value = value;
    }

    /**
     * Get the string value of the status.
     *
     * @return The status string.
     */
    public String getValue() {

        return value;
    }

    /**
     * Returns the string representation of the status.
     *
     * @return The status string value.
     */
    @Override
    public String toString() {

        return value;
    }
}
