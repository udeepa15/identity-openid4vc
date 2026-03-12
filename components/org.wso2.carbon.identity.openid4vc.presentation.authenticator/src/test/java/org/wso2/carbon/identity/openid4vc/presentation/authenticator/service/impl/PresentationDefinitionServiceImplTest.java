package org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.impl;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.management.dao.PresentationDefinitionDAO;
import org.wso2.carbon.identity.openid4vc.presentation.management.exception.PresentationDefinitionNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.management.util.PresentationDefinitionUtil;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;

/**
 * Test class for PresentationDefinitionServiceImpl.
 */
public class PresentationDefinitionServiceImplTest {

    @Mock
    private PresentationDefinitionDAO presentationDefinitionDAO;

    private PresentationDefinitionServiceImpl presentationDefinitionService;

    private static final int TENANT_ID = -1234;
    private static final String DEFINITION_ID = "def-123";

    // Build a sample RequestedCredential for tests
    private static PresentationDefinition.RequestedCredential sampleCredential() {
        PresentationDefinition.RequestedCredential cred = new PresentationDefinition.RequestedCredential();
        cred.setType("EmployeeBadge");
        cred.setPurpose("Prove employment");
        cred.setIssuer("did:web:example.com");
        cred.setClaims(Arrays.asList("email", "firstName"));
        return cred;
    }

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        presentationDefinitionService = new PresentationDefinitionServiceImpl(presentationDefinitionDAO);
    }

    @Test
    public void testCreatePresentationDefinition() throws Exception {
        PresentationDefinition definition = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name("Test Def")
                .requestedCredentials(Collections.singletonList(sampleCredential()))
                .tenantId(TENANT_ID)
                .build();

        when(presentationDefinitionDAO.presentationDefinitionExists(DEFINITION_ID, TENANT_ID)).thenReturn(false);
        doNothing().when(presentationDefinitionDAO).createPresentationDefinition(any(PresentationDefinition.class));

        PresentationDefinition created = presentationDefinitionService
                .createPresentationDefinition(definition, TENANT_ID);

        assertNotNull(created);
        assertEquals(created.getDefinitionId(), DEFINITION_ID);
        assertEquals(created.getName(), "Test Def");
    }

    @Test
    public void testCreatePresentationDefinitionMissingName() {
        PresentationDefinition definition = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .requestedCredentials(Collections.singletonList(sampleCredential()))
                .tenantId(TENANT_ID)
                .build();

        assertThrows(VPException.class, () -> presentationDefinitionService
                .createPresentationDefinition(definition, TENANT_ID));
    }

    @Test
    public void testCreatePresentationDefinitionMissingCredentials() {
        PresentationDefinition definition = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name("Test Def")
                .tenantId(TENANT_ID)
                .build();

        assertThrows(VPException.class, () -> presentationDefinitionService
                .createPresentationDefinition(definition, TENANT_ID));
    }

    @Test
    public void testCreatePresentationDefinitionAlreadyExists() throws Exception {
        PresentationDefinition definition = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name("Test Def")
                .requestedCredentials(Collections.singletonList(sampleCredential()))
                .tenantId(TENANT_ID)
                .build();

        when(presentationDefinitionDAO.presentationDefinitionExists(DEFINITION_ID, TENANT_ID)).thenReturn(true);

        assertThrows(VPException.class, () -> presentationDefinitionService
                .createPresentationDefinition(definition, TENANT_ID));
    }

    @Test
    public void testGetPresentationDefinitionById() throws Exception {
        PresentationDefinition definition = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name("Test Def")
                .requestedCredentials(Collections.singletonList(sampleCredential()))
                .tenantId(TENANT_ID)
                .build();

        when(presentationDefinitionDAO.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID)).thenReturn(definition);

        PresentationDefinition result = presentationDefinitionService
                .getPresentationDefinitionById(DEFINITION_ID, TENANT_ID);
        assertNotNull(result);
        assertEquals(result.getDefinitionId(), DEFINITION_ID);
    }

    @Test
    public void testGetPresentationDefinitionByIdNotFound() throws Exception {
        when(presentationDefinitionDAO.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID)).thenReturn(null);

        assertThrows(PresentationDefinitionNotFoundException.class, () -> presentationDefinitionService
                .getPresentationDefinitionById(DEFINITION_ID, TENANT_ID));
    }

    @Test
    public void testGetPresentationDefinitionByIdEmptyId() throws Exception {
        assertThrows(VPException.class, () -> presentationDefinitionService
                .getPresentationDefinitionById("", TENANT_ID));
    }

    @Test
    public void testGetAllPresentationDefinitions() throws Exception {
        PresentationDefinition definition = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name("Test Def")
                .requestedCredentials(Collections.singletonList(sampleCredential()))
                .tenantId(TENANT_ID)
                .build();

        when(presentationDefinitionDAO.getAllPresentationDefinitions(TENANT_ID))
                .thenReturn(Collections.singletonList(definition));

        List<PresentationDefinition> definitions = presentationDefinitionService
                .getAllPresentationDefinitions(TENANT_ID);
        assertNotNull(definitions);
        assertEquals(definitions.size(), 1);
        assertEquals(definitions.get(0).getDefinitionId(), DEFINITION_ID);
    }

    @Test
    public void testUpdatePresentationDefinition() throws Exception {
        PresentationDefinition existingDefinition = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name("Old Name")
                .requestedCredentials(Collections.singletonList(sampleCredential()))
                .tenantId(TENANT_ID)
                .build();

        PresentationDefinition updateRequest = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name("New Name")
                .requestedCredentials(Collections.singletonList(sampleCredential()))
                .tenantId(TENANT_ID)
                .build();

        when(presentationDefinitionDAO.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID))
                .thenReturn(existingDefinition);
        doNothing().when(presentationDefinitionDAO).updatePresentationDefinition(any(PresentationDefinition.class));

        PresentationDefinition updated = presentationDefinitionService
                .updatePresentationDefinition(updateRequest, TENANT_ID);

        assertNotNull(updated);
        assertEquals(updated.getName(), "New Name");
    }

    @Test
    public void testDeletePresentationDefinition() throws Exception {
        PresentationDefinition existingDefinition = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name("Old Name")
                .requestedCredentials(Collections.singletonList(sampleCredential()))
                .tenantId(TENANT_ID)
                .build();

        when(presentationDefinitionDAO.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID))
                .thenReturn(existingDefinition);
        doNothing().when(presentationDefinitionDAO).deletePresentationDefinition(DEFINITION_ID, TENANT_ID);

        presentationDefinitionService.deletePresentationDefinition(DEFINITION_ID, TENANT_ID);
        verify(presentationDefinitionDAO, times(1)).deletePresentationDefinition(DEFINITION_ID, TENANT_ID);
    }

    @Test
    public void testPresentationDefinitionExists() throws Exception {
        when(presentationDefinitionDAO.presentationDefinitionExists(DEFINITION_ID, TENANT_ID)).thenReturn(true);
        assertTrue(presentationDefinitionService.presentationDefinitionExists(DEFINITION_ID, TENANT_ID));
    }

    @Test
    public void testValidatePresentationDefinitionViaUtil() {
        // validatePresentationDefinition is now a static utility on PresentationDefinitionUtil
        String validJson = "{\"id\":\"def-123\",\"input_descriptors\":[{\"id\":\"desc-1\"}]}";
        assertTrue(PresentationDefinitionUtil.isValidPresentationDefinition(validJson));
        assertFalse(PresentationDefinitionUtil.isValidPresentationDefinition("invalid json"));
        assertFalse(PresentationDefinitionUtil.isValidPresentationDefinition(null));
        assertFalse(PresentationDefinitionUtil.isValidPresentationDefinition(""));
    }

    @Test
    public void testBuildDefinitionJsonViaUtil() {
        PresentationDefinition pd = new PresentationDefinition.Builder()
                .definitionId("id-1")
                .name("Test")
                .requestedCredentials(Collections.singletonList(sampleCredential()))
                .build();

        String json = PresentationDefinitionUtil.buildDefinitionJson(pd);
        assertNotNull(json);
        assertTrue(json.contains("\"id-1\""));
    }

    @Test
    public void testGetPresentationDefinitionByName() throws Exception {
        PresentationDefinition definition = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name("Test Def")
                .requestedCredentials(Collections.singletonList(sampleCredential()))
                .tenantId(TENANT_ID)
                .build();

        when(presentationDefinitionDAO.getPresentationDefinitionByName("Test Def", TENANT_ID)).thenReturn(definition);

        PresentationDefinition result = presentationDefinitionService
                .getPresentationDefinitionByName("Test Def", TENANT_ID);
        assertNotNull(result);
        assertEquals(result.getName(), "Test Def");
    }

    @Test
    public void testGetPresentationDefinitionByNameEmpty() throws Exception {
        assertThrows(VPException.class, () -> presentationDefinitionService
                .getPresentationDefinitionByName("", TENANT_ID));
    }

    @Test
    public void testGetClaimsFromPresentationDefinition() throws Exception {
        PresentationDefinition definition = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name("Test Def")
                .requestedCredentials(Collections.singletonList(sampleCredential()))
                .tenantId(TENANT_ID)
                .build();

        when(presentationDefinitionDAO.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID)).thenReturn(definition);

        List<PresentationDefinitionService.InputDescriptorClaimsDTO> claimsList = presentationDefinitionService
                .getClaimsFromPresentationDefinition(DEFINITION_ID, TENANT_ID);
        assertNotNull(claimsList);
        assertEquals(claimsList.size(), 1);
        assertEquals(claimsList.get(0).getInputDescriptorId(), "EmployeeBadge");
        assertEquals(claimsList.get(0).getClaims().size(), 2);
        assertEquals(claimsList.get(0).getClaims().get(0).getName(), "email");
        assertEquals(claimsList.get(0).getClaims().get(0).getPath(), "$.email");
    }
}
