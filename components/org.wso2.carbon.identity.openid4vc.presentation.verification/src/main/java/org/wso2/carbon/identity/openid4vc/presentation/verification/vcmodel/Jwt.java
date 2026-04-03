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

package org.wso2.carbon.identity.openid4vc.presentation.verification.vcmodel;

import java.util.HashMap;
import java.util.Map;

/**
 * Class representing a standard JWT with dynamic claims.
 */
public class Jwt {

    private String iss;

    private Long iat;

    private Long exp;

    private String sub;

    private Map<String, Object> cnf;

    private Map<String, Object> additionalClaims = new HashMap<>();

    /**
     * Returns the issuer claim.
     *
     * @return The {@code iss} claim value
     */
    public String getIss() {
        return iss;
    }

    /**
     * Sets the issuer claim.
     *
     * @param iss The {@code iss} claim value
     */
    public void setIss(String iss) {
        this.iss = iss;
    }

    /**
     * Returns the issued-at claim in epoch milliseconds.
     *
     * @return The {@code iat} claim value
     */
    public Long getIat() {
        return iat;
    }

    /**
     * Sets the issued-at claim in epoch milliseconds.
     *
     * @param iat The {@code iat} claim value
     */
    public void setIat(Long iat) {
        this.iat = iat;
    }

    /**
     * Returns the expiration claim in epoch milliseconds.
     *
     * @return The {@code exp} claim value
     */
    public Long getExp() {
        return exp;
    }

    /**
     * Sets the expiration claim in epoch milliseconds.
     *
     * @param exp The {@code exp} claim value
     */
    public void setExp(Long exp) {
        this.exp = exp;
    }

    /**
     * Returns the subject claim.
     *
     * @return The {@code sub} claim value
     */
    public String getSub() {
        return sub;
    }

    /**
     * Sets the subject claim.
     *
     * @param sub The {@code sub} claim value
     */
    public void setSub(String sub) {
        this.sub = sub;
    }

    /**
     * Returns the holder confirmation claim object.
     *
     * @return The {@code cnf} claim map
     */
    public Map<String, Object> getCnf() {
        return cnf;
    }

    /**
     * Sets the holder confirmation claim object.
     *
     * @param cnf The {@code cnf} claim map
     */
    public void setCnf(Map<String, Object> cnf) {
        this.cnf = cnf;
    }

    /**
     * Returns all non-standard claims captured from the token.
     *
     * @return A map of additional claims
     */
    public Map<String, Object> getAdditionalClaims() {
        return additionalClaims;
    }

    /**
     * Replaces the map of non-standard claims captured from the token.
     *
     * @param additionalClaims A map of additional claims
     */
    public void setAdditionalClaims(Map<String, Object> additionalClaims) {
        this.additionalClaims = additionalClaims;
    }

    /**
     * Adds a single non-standard claim entry.
     *
     * @param key The claim name
     * @param value The claim value
     */
    public void addAdditionalClaim(String key, Object value) {
        this.additionalClaims.put(key, value);
    }
}
