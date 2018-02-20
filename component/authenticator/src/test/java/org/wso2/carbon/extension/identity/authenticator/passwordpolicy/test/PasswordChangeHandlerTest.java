/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.wso2.carbon.extension.identity.authenticator.passwordpolicy.test;

import org.mockito.Matchers;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.event.stream.core.EventStreamService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.ModuleConfiguration;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.policy.password.PasswordChangeEnforceConstants;
import org.wso2.carbon.identity.policy.password.PasswordChangeHandler;
import org.wso2.carbon.identity.policy.password.internal.PasswordResetEnforcerDataHolder;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.Map;
import java.util.Properties;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

@PrepareForTest({IdentityTenantUtil.class})
public class PasswordChangeHandlerTest {
    private PasswordChangeHandler passwordChangeHandler;

    @Mock
    private UserStoreManager userStoreManager;

    @Mock
    private UserRealm userRealm;

    @Mock
    private RealmService realmService;

    @Mock
    private EventStreamService eventStreamService;

    @BeforeMethod
    public void setUp() {
        passwordChangeHandler = new PasswordChangeHandler();
        initMocks(this);
        PasswordResetEnforcerDataHolder.getInstance().setEventStreamService(eventStreamService);
    }

    @Test
    public void testHandlePostUpdateCredentialByAdminEvent() throws UserStoreException {
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

        RealmConfiguration realmConfig = new RealmConfiguration();
        realmConfig.getUserStoreProperties().put("DomainName", "domain");
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfig);

        Event event = new Event("POST_UPDATE_CREDENTIAL_BY_ADMIN");
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_NAME, "user");
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_STORE_MANAGER, userStoreManager);
        event.getEventProperties().put(IdentityEventConstants.EventProperty.TENANT_ID, -1234);

        try {
            passwordChangeHandler.handleEvent(event);   // Shouldn't throw user store exception
        } catch (IdentityEventException e) {
            Assert.fail("The authenticator failed the authentication flow");
        }
    }

    @Test
    public void testHandlePostUpdateCredentialEvent() throws UserStoreException {
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

        RealmConfiguration realmConfig = new RealmConfiguration();
        realmConfig.getUserStoreProperties().put("DomainName", "domain");
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfig);

        Event event = new Event("POST_UPDATE_CREDENTIAL");
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_NAME, "user");
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_STORE_MANAGER, userStoreManager);
        event.getEventProperties().put(IdentityEventConstants.EventProperty.TENANT_ID, -1234);

        try {
            passwordChangeHandler.handleEvent(event);   // Shouldn't throw user store exception
        } catch (IdentityEventException e) {
            Assert.fail("The authenticator failed the authentication flow");
        }
    }

    @Test
    public void testHandleAddUserEvent() throws UserStoreException {
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

        RealmConfiguration realmConfig = new RealmConfiguration();
        realmConfig.getUserStoreProperties().put("DomainName", "domain");
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfig);

        Event event = new Event("POST_UPDATE_CREDENTIAL");
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_NAME, "user");
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_STORE_MANAGER, userStoreManager);
        event.getEventProperties().put(IdentityEventConstants.EventProperty.TENANT_ID, -1234);

        try {
            passwordChangeHandler.handleEvent(event);   // Shouldn't throw user store exception
        } catch (IdentityEventException e) {
            Assert.fail("The authenticator failed the authentication flow");
        }
    }

    @Test
    public void testHandleEventWithUserStoreExceptionInSetLastPasswordUpdateUserClaim() throws Exception {
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

        RealmConfiguration realmConfig = new RealmConfiguration();
        realmConfig.getUserStoreProperties().put("DomainName", "domain");
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfig);

        Event event = new Event("POST_UPDATE_CREDENTIAL");
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_NAME, "user");
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_STORE_MANAGER, userStoreManager);
        event.getEventProperties().put(IdentityEventConstants.EventProperty.TENANT_ID, -1234);

        doThrow(new org.wso2.carbon.user.core.UserStoreException()).when(userStoreManager)
                .setUserClaimValues(eq("user"), Matchers.<Map<String, String>>any(), isNull(String.class));

        passwordChangeHandler.handleEvent(event);   // Shouldn't throw user store exception

        verify(eventStreamService, times(1)).publish(any(org.wso2.carbon.databridge.commons.Event.class));
    }

    @Test
    public void testHandleEventWithUserStoreExceptionInGetEmailUserClaim() throws UserStoreException {
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

        RealmConfiguration realmConfig = new RealmConfiguration();
        realmConfig.getUserStoreProperties().put("DomainName", "domain");
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfig);

        Event event = new Event("POST_UPDATE_CREDENTIAL");
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_NAME, "user");
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_STORE_MANAGER, userStoreManager);
        event.getEventProperties().put(IdentityEventConstants.EventProperty.TENANT_ID, -1234);

        doThrow(new org.wso2.carbon.user.core.UserStoreException()).when(userStoreManager)
                .getUserClaimValue(eq(MultitenantUtils.getTenantAwareUsername("user")),
                        eq(PasswordChangeEnforceConstants.EMAIL_ADDRESS_CLAIM), isNull(String.class));

        try {
            passwordChangeHandler.handleEvent(event);   // Shouldn't throw user store exception
        } catch (IdentityEventException e) {
            Assert.fail("The authenticator failed the authentication flow");
        }

        verify(eventStreamService, times(1)).publish(any(org.wso2.carbon.databridge.commons.Event.class));
    }

    @Test
    public void testGetName() {
        Assert.assertEquals(passwordChangeHandler.getName(),
                PasswordChangeEnforceConstants.PASSWORD_CHANGE_EVENT_HANDLER_NAME);
    }

    @Test
    public void testGetFriendlyName() {
        Assert.assertEquals(passwordChangeHandler.getFriendlyName(),
                PasswordChangeEnforceConstants.CONNECTOR_CONFIG_FRIENDLY_NAME);
    }

    @Test
    public void testGetCategory() {
        Assert.assertEquals(passwordChangeHandler.getCategory(),
                PasswordChangeEnforceConstants.CONNECTOR_CONFIG_CATEGORY);
    }

    @Test
    public void testGetSubCategory() {
        Assert.assertEquals(passwordChangeHandler.getSubCategory(),
                PasswordChangeEnforceConstants.CONNECTOR_CONFIG_SUB_CATEGORY);
    }

    @Test
    public void testGetOrder() {
        Assert.assertEquals(passwordChangeHandler.getOrder(), 0);
    }

    @Test
    public void testGetPropertyNameMapping() {
        Map<String, String> propertyNameMapping = passwordChangeHandler.getPropertyNameMapping();
        Assert.assertEquals(propertyNameMapping.size(), 1);
        Assert.assertEquals(
                propertyNameMapping.get(PasswordChangeEnforceConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS),
                PasswordChangeEnforceConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS_DISPLAYED_NAME
        );
    }

    @Test
    public void testGetPropertyDescriptionMapping() {
        Map<String, String> propertyDescriptionMapping = passwordChangeHandler.getPropertyDescriptionMapping();
        Assert.assertEquals(propertyDescriptionMapping.size(), 1);
        Assert.assertEquals(
                propertyDescriptionMapping.get(PasswordChangeEnforceConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS),
                PasswordChangeEnforceConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS_DESCRIPTION
        );
    }

    @Test
    public void testGetPropertyNames() {
        String[] propertyNames = passwordChangeHandler.getPropertyNames();
        Assert.assertEquals(propertyNames.length, 1);
        Assert.assertEquals(propertyNames[0], PasswordChangeEnforceConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS);
    }

    @Test
    public void testGetDefaultPropertyValues() throws IdentityGovernanceException {
        ModuleConfiguration moduleConfiguration = mock(ModuleConfiguration.class);
        Whitebox.setInternalState(passwordChangeHandler, "configs", moduleConfiguration);
        Properties moduleProperties = new Properties();
        moduleProperties.setProperty(PasswordChangeEnforceConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS, "13");
        when(moduleConfiguration.getModuleProperties()).thenReturn(moduleProperties);

        Properties defaultPropertyValues = passwordChangeHandler.getDefaultPropertyValues("carbon.super");
        Assert.assertEquals(defaultPropertyValues.size(), 1);
        Assert.assertEquals(
                defaultPropertyValues.get(PasswordChangeEnforceConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS),
                "13"
        );
    }

    @Test
    public void testGetDefaultPropertyValuesWithPropertyNames() throws IdentityGovernanceException {
        Assert.assertNull(passwordChangeHandler.getDefaultPropertyValues(
                new String[]{PasswordChangeEnforceConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS},
                "carbon.super"
        ));
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }
}