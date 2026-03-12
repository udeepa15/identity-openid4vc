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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.model;

/**
 * Enum representing the status of a Verifiable Presentation Request.
 */
public enum VPRequestStatus {

    /**
     * Authorization request created, waiting for VP submission from wallet.
     */
    ACTIVE("ACTIVE"),

    /**
     * Verifiable Presentation has been submitted by the wallet.
     */
    VP_SUBMITTED("VP_SUBMITTED"),

    /**
     * Request has expired before any submission was received.
     */
    EXPIRED("EXPIRED"),

    /**
     * Verification process has been completed.
     */
    COMPLETED("COMPLETED"),

    /**
     * Request was cancelled or invalidated.
     */
    CANCELLED("CANCELLED");

    private final String value;

    VPRequestStatus(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    /**
     * Get VPRequestStatus from string value.
     *
     * @param value String value of the status
     * @return VPRequestStatus enum or null if not found
     */
    public static VPRequestStatus fromValue(String value) {
        if (value == null) {
            return null;
        }
        for (VPRequestStatus status : VPRequestStatus.values()) {
            if (status.value.equalsIgnoreCase(value)) {
                return status;
            }
        }
        return null;
    }

    @Override
    public String toString() {
        return value;
    }
}
