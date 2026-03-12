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

package org.wso2.carbon.identity.openid4vc.presentation.verification.exception;

import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;

/**
 * Exception thrown when a revocation status check fails.
 */
public class RevocationCheckException extends VPException {

    /**
     * URL of the status list.
     */
    private String statusListUrl;

    /**
     * Index in the status list.
     */
    private Integer statusIndex;

    /**
     * Type of status check.
     */
    private String statusType;

    /**
     * Constructor with message.
     *
     * @param message Error message
     */
    public RevocationCheckException(final String message) {
        super(message);
    }

    /**
     * Constructor with message and cause.
     *
     * @param message Error message
     * @param cause   Original exception
     */
    public RevocationCheckException(final String message,
            final Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructor with all details and cause.
     *
     * @param message Error message
     * @param listUrl The status list URL being checked
     * @param index   The index being checked
     * @param cause   Original exception
     */
    public RevocationCheckException(final String message, final String listUrl,
            final Integer index, final Throwable cause) {
        super(message, cause);
        this.statusListUrl = listUrl;
        this.statusIndex = index;
    }

    // Static factory methods

    /**
     * Create exception for network errors.
     *
     * @param url   The URL that failed
     * @param cause The network error
     * @return RevocationCheckException
     */
    public static RevocationCheckException networkError(final String url,
            final Throwable cause) {
        RevocationCheckException ex = new RevocationCheckException(
                "Failed to fetch status list from: " + url, cause);
        ex.setStatusListUrl(url);
        return ex;
    }

    /**
     * Create exception for invalid status list credential.
     *
     * @param url    The URL of the invalid credential
     * @param reason The reason it's invalid
     * @return RevocationCheckException
     */
    public static RevocationCheckException invalidStatusList(final String url,
            final String reason) {
        RevocationCheckException ex = new RevocationCheckException(
                "Invalid status list credential at " + url + ": " + reason);
        ex.setStatusListUrl(url);
        return ex;
    }

    /**
     * Create exception for decoding errors.
     *
     * @param cause The decoding error
     * @return RevocationCheckException
     */
    public static RevocationCheckException decodingError(
            final Throwable cause) {
        return new RevocationCheckException(
                "Failed to decode status list: " + cause.getMessage(), cause);
    }

    // Getters and Setters

    /**
     * Set the status list URL.
     *
     * @param listUrl Status list URL
     */
    public void setStatusListUrl(final String listUrl) {
        this.statusListUrl = listUrl;
    }

}
