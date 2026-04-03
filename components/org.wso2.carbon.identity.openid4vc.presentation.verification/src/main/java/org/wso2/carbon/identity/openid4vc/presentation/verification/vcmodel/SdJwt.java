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


import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Class representing an SD-JWT with standard and SD-JWT specific claims.
 * Inherits standard JWT fields (iss, iat, exp, sub) from {@link Jwt}.
 */
public class SdJwt extends Jwt {

    private List<String> sd;   

    private String sdAlg; 

    private List<Disclosure> disclosures = new ArrayList<>();

    /**
     * Returns the hashed disclosure digest list from the {@code _sd} claim.
     *
     * @return The list of disclosure digest values
     */
    public List<String> getSd() {
        return sd;
    }

    /**
     * Sets the hashed disclosure digest list from the {@code _sd} claim.
     *
     * @param sd The list of disclosure digest values
     */
    public void setSd(List<String> sd) {
        this.sd = sd;
    }

    /**
     * Returns the disclosure hash algorithm identifier from the {@code _sd_alg} claim.
     *
     * @return The disclosure hash algorithm identifier
     */
    public String getSdAlg() {
        return sdAlg;
    }

    /**
     * Sets the disclosure hash algorithm identifier from the {@code _sd_alg} claim.
     *
     * @param sdAlg The disclosure hash algorithm identifier
     */
    public void setSdAlg(String sdAlg) {
        this.sdAlg = sdAlg;
    }

    /**
     * Returns the decoded disclosures associated with this SD-JWT.
     *
     * @return The list of decoded {@link Disclosure} entries
     */
    public List<Disclosure> getDisclosures() {
        return disclosures;
    }

    /**
     * Replaces the decoded disclosure list associated with this SD-JWT.
     *
     * @param disclosures The list of decoded {@link Disclosure} entries
     */
    public void setDisclosures(List<Disclosure> disclosures) {
        this.disclosures = disclosures;
    }

    /**
     * Adds a decoded disclosure entry.
     *
     * @param disclosure The disclosure to add
     */
    public void addDisclosure(Disclosure disclosure) {
        this.disclosures.add(disclosure);
    }

    /**
     * Returns the plaintext claim map derived from verified disclosures and
     * non-standard JWT claims.
     *
     * @return The plaintext claim map
     */
    public Map<String, Object> getPlaintextClaims() {
        return getAdditionalClaims();
    }

    /**
     * Class representing an SD-JWT disclosure.
     * A disclosure is typically a JSON array: [salt, name, value].
     */
    public static class Disclosure {

        private String salt;
        private String name;
        private Object value;

        /**
         * Creates an SD-JWT disclosure entry.
         *
         * @param salt The disclosure salt value
         * @param name The disclosed claim name
         * @param value The disclosed claim value
         */
        public Disclosure(String salt, String name, Object value) {

            this.salt = salt;
            this.name = name;
            this.value = value;
        }

        /**
         * Returns the disclosure salt.
         *
         * @return The disclosure salt
         */
        public String getSalt() {
            return salt;
        }

        /**
         * Sets the disclosure salt.
         *
         * @param salt The disclosure salt
         */
        public void setSalt(String salt) {
            this.salt = salt;
        }

        /**
         * Returns the disclosed claim name.
         *
         * @return The disclosed claim name
         */
        public String getName() {
            return name;
        }

        /**
         * Sets the disclosed claim name.
         *
         * @param name The disclosed claim name
         */
        public void setName(String name) {
            this.name = name;
        }

        /**
         * Returns the disclosed claim value.
         *
         * @return The disclosed claim value
         */
        public Object getValue() {
            return value;
        }

        /**
         * Sets the disclosed claim value.
         *
         * @param value The disclosed claim value
         */
        public void setValue(Object value) {
            this.value = value;
        }
    }


}
