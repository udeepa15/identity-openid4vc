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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.status;

import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;

import java.util.Set;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;

public class StatusTransitionManagerTest {

    @Test
    public void testIsValidTransition() {
        // Valid transitions
        assertTrue(StatusTransitionManager.isValidTransition(VPRequestStatus.ACTIVE, VPRequestStatus.VP_SUBMITTED));
        assertTrue(StatusTransitionManager.isValidTransition(VPRequestStatus.ACTIVE, VPRequestStatus.EXPIRED));
        assertTrue(StatusTransitionManager.isValidTransition(VPRequestStatus.VP_SUBMITTED, VPRequestStatus.COMPLETED));
        assertTrue(StatusTransitionManager.isValidTransition(VPRequestStatus.VP_SUBMITTED, VPRequestStatus.EXPIRED));

        // Invalid transitions
        assertFalse(StatusTransitionManager.isValidTransition(VPRequestStatus.ACTIVE, VPRequestStatus.COMPLETED));
        assertFalse(StatusTransitionManager.isValidTransition(VPRequestStatus.COMPLETED, VPRequestStatus.ACTIVE));
        assertFalse(StatusTransitionManager.isValidTransition(VPRequestStatus.EXPIRED, VPRequestStatus.ACTIVE));
        assertFalse(StatusTransitionManager.isValidTransition(null, VPRequestStatus.ACTIVE));
    }

    @Test
    public void testGetValidNextStates() {
        Set<VPRequestStatus> nextFromActive = StatusTransitionManager.getValidNextStates(VPRequestStatus.ACTIVE);
        assertEquals(nextFromActive.size(), 2);
        assertTrue(nextFromActive.contains(VPRequestStatus.VP_SUBMITTED));
        assertTrue(nextFromActive.contains(VPRequestStatus.EXPIRED));

        Set<VPRequestStatus> nextFromCompleted = StatusTransitionManager.getValidNextStates(VPRequestStatus.COMPLETED);
        assertTrue(nextFromCompleted.isEmpty());
    }

    @Test
    public void testIsTerminalState() {
        assertTrue(StatusTransitionManager.isTerminalState(VPRequestStatus.COMPLETED));
        assertTrue(StatusTransitionManager.isTerminalState(VPRequestStatus.EXPIRED));
        assertFalse(StatusTransitionManager.isTerminalState(VPRequestStatus.ACTIVE));
        assertFalse(StatusTransitionManager.isTerminalState(VPRequestStatus.VP_SUBMITTED));
    }

    @Test
    public void testTransition() {
        assertEquals(StatusTransitionManager.transition(VPRequestStatus.ACTIVE, VPRequestStatus.VP_SUBMITTED),
                VPRequestStatus.VP_SUBMITTED);
        // Invalid transition returns current status
        assertEquals(StatusTransitionManager.transition(VPRequestStatus.ACTIVE, VPRequestStatus.COMPLETED),
                VPRequestStatus.ACTIVE);
    }

    @Test
    public void testTransitionStrict() throws Exception {
        assertEquals(StatusTransitionManager.transitionStrict(VPRequestStatus.ACTIVE,
                VPRequestStatus.VP_SUBMITTED), VPRequestStatus.VP_SUBMITTED);
        
        assertThrows(StatusTransitionManager.InvalidStatusTransitionException.class,
                () -> StatusTransitionManager.transitionStrict(VPRequestStatus.ACTIVE, VPRequestStatus.COMPLETED));
    }

    @Test
    public void testGetNotificationStatus() {
        assertEquals(StatusTransitionManager.getNotificationStatus(VPRequestStatus.ACTIVE, false), "ACTIVE");
        assertEquals(StatusTransitionManager.getNotificationStatus(VPRequestStatus.VP_SUBMITTED, true),
                "VP_SUBMITTED_ERROR");
        assertEquals(StatusTransitionManager.getNotificationStatus(VPRequestStatus.VP_SUBMITTED, false),
                "VP_SUBMITTED");
        assertEquals(StatusTransitionManager.getNotificationStatus(null, false), "UNKNOWN");
    }

    @Test
    public void testParseStatus() {
        assertEquals(StatusTransitionManager.parseStatus("ACTIVE"), VPRequestStatus.ACTIVE);
        assertEquals(StatusTransitionManager.parseStatus("VP_SUBMITTED_ERROR"),
                VPRequestStatus.VP_SUBMITTED);
        assertEquals(StatusTransitionManager.parseStatus("COMPLETED"), VPRequestStatus.COMPLETED);
        assertNull(StatusTransitionManager.parseStatus("INVALID"));
    }
}
