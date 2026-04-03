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

    public List<String> getSd() {
        return sd;
    }

    public void setSd(List<String> sd) {
        this.sd = sd;
    }

    public String getSdAlg() {
        return sdAlg;
    }

    public void setSdAlg(String sdAlg) {
        this.sdAlg = sdAlg;
    }

    public List<Disclosure> getDisclosures() {
        return disclosures;
    }

    public void setDisclosures(List<Disclosure> disclosures) {
        this.disclosures = disclosures;
    }

    public void addDisclosure(Disclosure disclosure) {
        this.disclosures.add(disclosure);
    }

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

        public Disclosure(String salt, String name, Object value) {
            this.salt = salt;
            this.name = name;
            this.value = value;
        }

        public String getSalt() {
            return salt;
        }

        public void setSalt(String salt) {
            this.salt = salt;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public Object getValue() {
            return value;
        }

        public void setValue(Object value) {
            this.value = value;
        }
    }


}
