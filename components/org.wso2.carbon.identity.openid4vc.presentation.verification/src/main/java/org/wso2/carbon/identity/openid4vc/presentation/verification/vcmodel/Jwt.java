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

    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public Long getIat() {
        return iat;
    }

    public void setIat(Long iat) {
        this.iat = iat;
    }

    public Long getExp() {
        return exp;
    }

    public void setExp(Long exp) {
        this.exp = exp;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public Map<String, Object> getCnf() {
        return cnf;
    }

    public void setCnf(Map<String, Object> cnf) {
        this.cnf = cnf;
    }

    public Map<String, Object> getAdditionalClaims() {
        return additionalClaims;
    }

    public void setAdditionalClaims(Map<String, Object> additionalClaims) {
        this.additionalClaims = additionalClaims;
    }

    public void addAdditionalClaim(String key, Object value) {
        this.additionalClaims.put(key, value);
    }
}
