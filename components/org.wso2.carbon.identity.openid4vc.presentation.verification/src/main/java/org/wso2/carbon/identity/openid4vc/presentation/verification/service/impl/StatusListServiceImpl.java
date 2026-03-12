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

package org.wso2.carbon.identity.openid4vc.presentation.verification.service.impl;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.RevocationCheckException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.model.RevocationCheckResult;
import org.wso2.carbon.identity.openid4vc.presentation.verification.model.VerifiableCredential;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.StatusListService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.HttpClientUtil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.GZIPInputStream;

/**
 * Implementation of StatusListService for checking credential revocation
 * status.
 * Supports StatusList2021 and BitstringStatusList.
 */
public class StatusListServiceImpl implements StatusListService {

    private static final Gson GSON = new Gson();

    // Cache for decoded status lists
    private final Map<String, CachedStatusList> statusListCache = new ConcurrentHashMap<>();

    // Cache TTL in milliseconds (default: 5 minutes)
    private static final long CACHE_TTL_MS = 5 * 60 * 1000;


    private boolean revocationCheckEnabled = true;

    @Override
    public RevocationCheckResult checkRevocationStatus(VerifiableCredential.CredentialStatus credentialStatus)
            throws RevocationCheckException {

        if (!revocationCheckEnabled) {
            return RevocationCheckResult.skipped("Revocation checking is disabled");
        }

        if (credentialStatus == null) {
            return RevocationCheckResult.skipped("No credential status field");
        }

        String statusType = credentialStatus.getType();
        if (StringUtils.isBlank(statusType)) {
            return RevocationCheckResult.skipped("No status type specified");
        }

        // Determine which status list mechanism to use
        if (isStatusList2021(statusType)) {
            return checkStatusList2021FromCredentialStatus(credentialStatus);
        } else if (isBitstringStatusList(statusType)) {
            return checkBitstringStatusListFromCredentialStatus(credentialStatus);
        } else {
            return RevocationCheckResult.unknown("Unsupported status type: " + statusType);
        }
    }

    @Override
    public RevocationCheckResult checkStatusList2021(String statusListCredentialUrl, int statusListIndex,
            String statusPurpose) throws RevocationCheckException {

        try {
            // Fetch and decode the status list
            byte[] bitstring = fetchAndDecodeStatusList(statusListCredentialUrl);

            // Check the bit at the specified index
            boolean isSet = isBitSet(bitstring, statusListIndex);

            // Build result
            RevocationCheckResult.Builder builder = new RevocationCheckResult.Builder()
                    .statusListCredentialUrl(statusListCredentialUrl)
                    .statusIndex(statusListIndex)
                    .statusPurpose(statusPurpose);

            if (isSet) {
                // Bit is set - credential is revoked or suspended based on purpose
                if ("suspension".equalsIgnoreCase(statusPurpose)) {
                    builder.status(RevocationCheckResult.Status.SUSPENDED)
                            .message("Credential is suspended");
                } else {
                    builder.status(RevocationCheckResult.Status.REVOKED)
                            .message("Credential is revoked");
                }
            } else {
                builder.status(RevocationCheckResult.Status.VALID)
                        .message("Credential is not revoked");
            }

            return builder.build();

        } catch (RevocationCheckException e) {
            throw e;
        } catch (Exception e) {
            throw new RevocationCheckException("Failed to check status list: " + e.getMessage(),
                    statusListCredentialUrl, statusListIndex, e);
        }
    }

    @Override
    public RevocationCheckResult checkBitstringStatusList(String statusCredentialUrl, int statusIndex,
            String statusPurpose) throws RevocationCheckException {
        // BitstringStatusList uses the same mechanism as StatusList2021 but with
        // different encoding
        return checkStatusList2021(statusCredentialUrl, statusIndex, statusPurpose);
    }

    @Override
    public byte[] fetchAndDecodeStatusList(String statusListCredentialUrl) throws RevocationCheckException {

        // Check cache first
        CachedStatusList cached = statusListCache.get(statusListCredentialUrl);
        if (cached != null && !cached.isExpired()) {

            return cached.getBitstring();
        }

        try {
            // Fetch the status list credential
            String credentialJson = fetchStatusListCredential(statusListCredentialUrl);

            // Parse and extract the encoded list
            String encodedList = extractEncodedList(credentialJson);

            // Decode the list (Base64 + GZIP)
            byte[] bitstring = decodeStatusList(encodedList);

            // Cache the result
            statusListCache.put(statusListCredentialUrl, new CachedStatusList(bitstring));

            return bitstring;

        } catch (RevocationCheckException e) {
            throw e;
        } catch (Exception e) {
            throw RevocationCheckException.networkError(statusListCredentialUrl, e);
        }
    }

    @Override
    public boolean isBitSet(byte[] bitstring, int index) {
        if (bitstring == null || bitstring.length == 0) {
            return false;
        }

        // Calculate which byte and which bit within that byte
        int byteIndex = index / 8;
        int bitIndex = index % 8;

        if (byteIndex >= bitstring.length) {
            return false;
        }

        // Check if the bit is set (MSB first within each byte)
        int mask = 1 << (7 - bitIndex);
        return (bitstring[byteIndex] & mask) != 0;
    }

    @Override
    public void clearCache() {
        statusListCache.clear();
    }

    @Override
    public boolean isRevocationCheckEnabled() {
        return revocationCheckEnabled;
    }

    /**
     * Set whether revocation checking is enabled.
     *
     * @param enabled true to enable revocation checking
     */
    public void setRevocationCheckEnabled(boolean enabled) {
        this.revocationCheckEnabled = enabled;
    }

    // Private helper methods

    /**
     * Check if the status type is StatusList2021.
     */
    private boolean isStatusList2021(String statusType) {
        return "StatusList2021Entry".equals(statusType) ||
                "StatusList2021".equals(statusType);
    }

    /**
     * Check if the status type is BitstringStatusList.
     */
    private boolean isBitstringStatusList(String statusType) {
        return "BitstringStatusListEntry".equals(statusType) ||
                "BitstringStatusList".equals(statusType);
    }

    /**
     * Check StatusList2021 from credential status object.
     */
    private RevocationCheckResult checkStatusList2021FromCredentialStatus(
            VerifiableCredential.CredentialStatus credentialStatus) throws RevocationCheckException {

        String statusListCredential = credentialStatus.getStatusListCredential();
        if (StringUtils.isBlank(statusListCredential)) {
            return RevocationCheckResult.unknown("No statusListCredential URL");
        }

        String statusListIndexStr = credentialStatus.getStatusListIndex();
        if (StringUtils.isBlank(statusListIndexStr)) {
            return RevocationCheckResult.unknown("No statusListIndex");
        }

        int statusListIndex;
        try {
            statusListIndex = Integer.parseInt(statusListIndexStr);
        } catch (NumberFormatException e) {
            return RevocationCheckResult.unknown("Invalid statusListIndex: " + statusListIndexStr);
        }

        String statusPurpose = credentialStatus.getStatusPurpose();
        if (StringUtils.isBlank(statusPurpose)) {
            statusPurpose = "revocation"; // Default to revocation
        }

        return checkStatusList2021(statusListCredential, statusListIndex, statusPurpose);
    }

    /**
     * Check BitstringStatusList from credential status object.
     */
    private RevocationCheckResult checkBitstringStatusListFromCredentialStatus(
            VerifiableCredential.CredentialStatus credentialStatus) throws RevocationCheckException {

        // BitstringStatusList uses statusListCredential and statusListIndex same as
        // StatusList2021
        String statusCredential = credentialStatus.getStatusListCredential();
        if (StringUtils.isBlank(statusCredential)) {
            return RevocationCheckResult.unknown("No statusListCredential URL");
        }

        String statusIndexStr = credentialStatus.getStatusListIndex();
        if (StringUtils.isBlank(statusIndexStr)) {
            return RevocationCheckResult.unknown("No statusListIndex");
        }

        int statusIndex;
        try {
            statusIndex = Integer.parseInt(statusIndexStr);
        } catch (NumberFormatException e) {
            return RevocationCheckResult.unknown("Invalid statusListIndex: " + statusIndexStr);
        }

        String statusPurpose = credentialStatus.getStatusPurpose();
        if (StringUtils.isBlank(statusPurpose)) {
            statusPurpose = "revocation";
        }

        return checkBitstringStatusList(statusCredential, statusIndex, statusPurpose);
    }

    /**
     * Fetch the status list credential from a URL.
     */
    @SuppressFBWarnings("URLCONNECTION_SSRF_FD")
    private String fetchStatusListCredential(String url) throws RevocationCheckException {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/vc+ld+json, application/json");
            String response = HttpClientUtil.fetchContent(url, headers);
            if (response == null) {
                 throw RevocationCheckException.networkError(url,
                         new IOException("HTTP response not OK"));
            }
            return response;
        } catch (RevocationCheckException e) {
            throw e;
        } catch (Exception e) {
            throw RevocationCheckException.networkError(url, e);
        }
    }

    /**
     * Extract the encoded list from a status list credential JSON.
     */
    private String extractEncodedList(String credentialJson) throws RevocationCheckException {
        try {
            JsonObject credential = GSON.fromJson(credentialJson, JsonObject.class);

            // Handle JWT wrapped credential
            if (credential.has("vc")) {
                credential = credential.getAsJsonObject("vc");
            }

            // Get credentialSubject
            JsonElement subjectElement = credential.get("credentialSubject");
            JsonObject credentialSubject;

            if (subjectElement.isJsonArray()) {
                JsonArray subjectArray = subjectElement.getAsJsonArray();
                if (subjectArray.size() == 0) {
                    throw RevocationCheckException.invalidStatusList(null, "Empty credentialSubject array");
                }
                credentialSubject = subjectArray.get(0).getAsJsonObject();
            } else {
                credentialSubject = subjectElement.getAsJsonObject();
            }

            // Extract encodedList
            String encodedList = null;

            // Try StatusList2021 format
            if (credentialSubject.has("encodedList")) {
                encodedList = credentialSubject.get("encodedList").getAsString();
            }

            if (StringUtils.isBlank(encodedList)) {
                throw RevocationCheckException.invalidStatusList(null, "No encodedList found in credential subject");
            }

            return encodedList;

        } catch (RevocationCheckException e) {
            throw e;
        } catch (Exception e) {
            throw RevocationCheckException.invalidStatusList(null, "Failed to parse credential: " + e.getMessage());
        }
    }

    /**
     * Decode the status list from Base64 + GZIP format.
     */
    private byte[] decodeStatusList(String encodedList) throws RevocationCheckException {
        try {
            // Base64 decode
            byte[] compressed = Base64.getDecoder().decode(encodedList);

            // GZIP decompress
            try (ByteArrayInputStream bais = new ByteArrayInputStream(compressed);
                    GZIPInputStream gzis = new GZIPInputStream(bais);
                    ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = gzis.read(buffer)) != -1) {
                    baos.write(buffer, 0, bytesRead);
                }

                byte[] bitstring = baos.toByteArray();

                // Validate minimum size per spec (optional but recommended)
                // Validate minimum size per spec (optional but recommended)
                /*
                 * if (bitstring.length < MIN_BITSTRING_SIZE) {
                 * Log warning or throw exception if strict mode is enabled
                 * }
                 */

                return bitstring;
            }

        } catch (IllegalArgumentException e) {
            throw RevocationCheckException.decodingError(new Exception("Invalid Base64 encoding", e));
        } catch (IOException e) {
            throw RevocationCheckException.decodingError(new Exception("Failed to decompress GZIP", e));
        }
    }

    /**
     * Cached status list entry.
     */
    private static class CachedStatusList {
        private final byte[] bitstring;
        private final long createdAt;

        CachedStatusList(byte[] bitstring) {
            this.bitstring = bitstring;
            this.createdAt = System.currentTimeMillis();
        }

        byte[] getBitstring() {
            return bitstring;
        }

        boolean isExpired() {
            return System.currentTimeMillis() - createdAt > CACHE_TTL_MS;
        }
    }
}
