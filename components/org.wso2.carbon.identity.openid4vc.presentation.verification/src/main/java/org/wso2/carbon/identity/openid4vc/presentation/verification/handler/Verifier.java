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

package org.wso2.carbon.identity.openid4vc.presentation.verification.handler;

import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;

import java.util.Map;

/**
 * Interface for format-specific token verifiers.
 */
public interface Verifier {

    /**
         * Determines whether this verifier supports the given presentation format.
         *
         * @param format The format value from {@code descriptor_map[*].format}
         * @return {@code true} if this verifier can process the format; otherwise {@code false}
     */
    boolean canHandle(String format);

    /**
         * Verifies the supplied VP token using a format-specific strategy.
         *
         * @param submission The {@link PresentationSubmission} metadata for the token
         * @param tenantId The tenant identifier used for tenant-scoped resolution
         * @param vpToken The raw verifiable presentation token
         * @return A map of verified claims extracted from the presentation
         * @throws VerificationException If verification fails due to client or server conditions
     */
    Map<String, Object> handle(PresentationSubmission submission, int tenantId, String vpToken) 
            throws VerificationException;
}
