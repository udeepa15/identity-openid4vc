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

package org.wso2.carbon.identity.openid4vc.presentation.verification.service;

import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.RevocationCheckException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.model.RevocationCheckResult;
import org.wso2.carbon.identity.openid4vc.presentation.verification.model.VerifiableCredential;

/**
 * Service interface for checking credential revocation status using various status list mechanisms.
 * Supports StatusList2021 (W3C CCG) and BitstringStatusList (W3C VC Bitstring Status List).
 */
public interface StatusListService {

    /**
     * Check if a credential is revoked using its credentialStatus field.
     *
     * @param credentialStatus The credential status from the VC
     * @return RevocationCheckResult containing the revocation status
     * @throws RevocationCheckException If an error occurs during the check
     */
    RevocationCheckResult checkRevocationStatus(VerifiableCredential.CredentialStatus credentialStatus)
            throws RevocationCheckException;

    /**
     * Check if a credential is revoked using StatusList2021.
     * Fetches the status list credential from the statusListCredential URL,
     * decodes the encodedList, and checks the bit at statusListIndex.
     *
     * @param statusListCredentialUrl URL to the status list credential
     * @param statusListIndex         Index in the status list
     * @param statusPurpose           Purpose of the status (e.g., "revocation", "suspension")
     * @return RevocationCheckResult containing the revocation status
     * @throws RevocationCheckException If an error occurs during the check
     */
    RevocationCheckResult checkStatusList2021(String statusListCredentialUrl,
            int statusListIndex,
            String statusPurpose) throws RevocationCheckException;

    /**
     * Check if a credential is revoked using BitstringStatusList.
     *
     * @param statusCredentialUrl URL to the status credential
     * @param statusIndex         Index in the bitstring
     * @param statusPurpose       Purpose of the status
     * @return RevocationCheckResult containing the revocation status
     * @throws RevocationCheckException If an error occurs during the check
     */
    RevocationCheckResult checkBitstringStatusList(String statusCredentialUrl,
            int statusIndex,
            String statusPurpose) throws RevocationCheckException;

    /**
     * Fetch and decode the status list from a status list credential URL.
     *
     * @param statusListCredentialUrl URL to fetch the status list 
     *                                credential from
     * @return Decoded bitstring as a byte array
     * @throws RevocationCheckException If fetching or decoding fails
     */
    byte[] fetchAndDecodeStatusList(String statusListCredentialUrl)
            throws RevocationCheckException;

    /**
     * Check if a specific bit is set in a bitstring.
     *
     * @param bitstring The decoded bitstring
     * @param index     The index to check
     * @return true if the bit is set (revoked/suspended), false otherwise
     */
    boolean isBitSet(byte[] bitstring, int index);

    /**
     * Clear the status list cache.
     */
    void clearCache();

    /**
     * Check if revocation checking is enabled.
     *
     * @return true if revocation checking is enabled
     */
    boolean isRevocationCheckEnabled();
}
