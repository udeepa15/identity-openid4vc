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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Standardised response DTO returned by the unified Verifiable Presentation
 * verification entry-point.
 *
 * <p>This DTO encapsulates every piece of information a caller needs after
 * invoking
 * {@code VCVerificationService#verifyPresentation(String, String, String,
 * String, String)}:
 * <ul>
 *   <li>{@code valid} – whether the overall verification succeeded</li>
 *   <li>{@code verifiedClaims} – the flat map of claims extracted from the
 *       credential(s) once verification passed</li>
 *   <li>{@code formatDetected} – the VC format string that was detected from
 *       the {@code presentation_submission} descriptor map (e.g.
 *       {@code "vc+sd-jwt"}, {@code "jwt_vp"}, {@code "ldp_vp"})</li>
 *   <li>{@code errorMessage} – a human-readable reason when {@code valid} is
 *       {@code false}</li>
 * </ul>
 *
 * <p><strong>Usage contract:</strong> callers must always check
 * {@link #isValid()} before consuming {@link #getVerifiedClaims()}. When
 * {@code valid} is {@code false} the claims map will be empty and
 * {@link #getErrorMessage()} will contain the failure reason.
 */
public class VPVerificationResponseDTO {

    /** Whether the verifiable presentation passed all verification checks. */
    private final boolean valid;

    /**
     * Flat map of verified claims extracted from the credential(s). Empty when
     * {@code valid} is {@code false}.
     */
    private final Map<String, Object> verifiedClaims;

    /**
     * The VC format string detected from the {@code presentation_submission}
     * descriptor map. May be {@code null} if format detection failed before the
     * presentation could be dispatched.
     */
    private final String formatDetected;

    /**
     * Human-readable error message describing the first failure that caused the
     * verification to be marked invalid. {@code null} when {@code valid} is
     * {@code true}.
     */
    private final String errorMessage;

    /**
     * The nonce extracted from the VP token (KB-JWT {@code nonce} claim for
     * SD-JWT, top-level {@code nonce} claim for JWT VP, or {@code proof.challenge}
     * for JSON-LD VP). The caller (Authenticator) must compare this against the
     * session-bound expected nonce to prevent replay attacks.
     */
    private final String nonce;

    /**
     * The audience extracted from the VP token (KB-JWT {@code aud} claim for
     * SD-JWT, top-level {@code aud} claim for JWT VP, or {@code proof.domain}
     * for JSON-LD VP). The caller must compare this against the expected
     * audience (client ID) to prevent presentation replay.
     */
    private final String audience;

    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /**
     * Private all-args constructor. Use the static factory methods instead.
     *
     * @param valid          Whether verification succeeded
     * @param verifiedClaims Claims extracted during a successful verification
     * @param formatDetected Detected VP token format string
     * @param errorMessage   Failure reason (null on success)
     * @param nonce          Nonce extracted from the VP token (may be null)
     * @param audience       Audience extracted from the VP token (may be null)
     */
    private VPVerificationResponseDTO(boolean valid,
            Map<String, Object> verifiedClaims,
            String formatDetected,
            String errorMessage,
            String nonce,
            String audience) {
        this.valid = valid;
        this.verifiedClaims = verifiedClaims != null
                ? Collections.unmodifiableMap(new HashMap<>(verifiedClaims))
                : Collections.emptyMap();
        this.formatDetected = formatDetected;
        this.errorMessage = errorMessage;
        this.nonce = nonce;
        this.audience = audience;
    }

    // -----------------------------------------------------------------------
    // Static factory methods
    // -----------------------------------------------------------------------

    /**
     * Create a successful verification response.
     *
     * @param verifiedClaims Claims extracted from the credential(s)
     * @param formatDetected The detected VC format string
     * @return A {@code VPVerificationResponseDTO} with {@code valid = true}
     */
    public static VPVerificationResponseDTO success(Map<String, Object> verifiedClaims,
            String formatDetected) {
        return new VPVerificationResponseDTO(true, verifiedClaims, formatDetected, null, null, null);
    }

    /**
     * Create a successful verification response with extracted nonce and audience.
     *
     * <p>The caller (Authenticator) is responsible for comparing {@code nonce}
     * and {@code audience} against the session-bound expected values to prevent
     * replay attacks.
     *
     * @param verifiedClaims Claims extracted from the credential(s)
     * @param formatDetected The detected VC format string
     * @param nonce          Nonce extracted from the VP token; may be {@code null}
     * @param audience       Audience extracted from the VP token; may be {@code null}
     * @return A {@code VPVerificationResponseDTO} with {@code valid = true}
     */
    public static VPVerificationResponseDTO success(Map<String, Object> verifiedClaims,
            String formatDetected,
            String nonce,
            String audience) {
        return new VPVerificationResponseDTO(true, verifiedClaims, formatDetected, null, nonce, audience);
    }

    /**
     * Create a failed verification response.
     *
     * @param errorMessage   Human-readable reason for the failure
     * @param formatDetected The detected VC format string (may be null if
     *                       format detection itself failed)
     * @return A {@code VPVerificationResponseDTO} with {@code valid = false}
     */
    public static VPVerificationResponseDTO failure(String errorMessage, String formatDetected) {
        return new VPVerificationResponseDTO(false, null, formatDetected, errorMessage, null, null);
    }

    /**
     * Create a failed verification response when format could not be detected.
     *
     * @param errorMessage Human-readable reason for the failure
     * @return A {@code VPVerificationResponseDTO} with {@code valid = false} and
     *         {@code formatDetected = null}
     */
    public static VPVerificationResponseDTO failure(String errorMessage) {
        return new VPVerificationResponseDTO(false, null, null, errorMessage, null, null);
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /**
     * Return {@code true} if the verifiable presentation passed all
     * verification checks.
     *
     * @return Verification outcome
     */
    public boolean isValid() {
        return valid;
    }

    /**
     * Return the verified claims extracted from the credential(s).
     *
     * <p>The map is an unmodifiable view. It is never {@code null} but will be
     * empty when {@link #isValid()} returns {@code false}.
     *
     * @return Unmodifiable map of verified claims
     */
    public Map<String, Object> getVerifiedClaims() {
        return verifiedClaims;
    }

    /**
     * Return the VC format string detected from the
     * {@code presentation_submission} descriptor map.
     *
     * <p>Typical values: {@code "vc+sd-jwt"}, {@code "jwt_vp"},
     * {@code "jwt_vp_json"}, {@code "ldp_vp"}.
     *
     * @return Detected format string, or {@code null} if detection failed
     */
    public String getFormatDetected() {
        return formatDetected;
    }

    /**
     * Return the human-readable error message when verification failed.
     *
     * @return Error message, or {@code null} when {@link #isValid()} is
     *         {@code true}
     */
    public String getErrorMessage() {
        return errorMessage;
    }

    /**
     * Return the nonce extracted from the VP token.
     *
     * <p>For SD-JWT this is the {@code nonce} claim from the Key Binding JWT.
     * For JWT VP this is the top-level {@code nonce} claim. For JSON-LD VP
     * this is {@code proof.challenge}. May be {@code null} if the token did
     * not contain a nonce.
     *
     * <p>The caller (Authenticator) must compare this against the session-bound
     * expected nonce to prevent replay attacks.
     *
     * @return Extracted nonce, or {@code null}
     */
    public String getNonce() {
        return nonce;
    }

    /**
     * Return the audience extracted from the VP token.
     *
     * <p>For SD-JWT this is the {@code aud} claim from the Key Binding JWT.
     * For JWT VP this is the top-level {@code aud} claim. For JSON-LD VP
     * this is {@code proof.domain}. May be {@code null} if the token did
     * not contain an audience.
     *
     * <p>The caller (Authenticator) must compare this against the expected
     * audience (client ID) to prevent presentation replay.
     *
     * @return Extracted audience, or {@code null}
     */
    public String getAudience() {
        return audience;
    }

    @Override
    public String toString() {
        return "VPVerificationResponseDTO{"
                + "valid=" + valid
                + ", formatDetected='" + formatDetected + '\''
                + ", errorMessage='" + errorMessage + '\''
                + ", verifiedClaimsCount=" + verifiedClaims.size()
                + '}';
    }
}
