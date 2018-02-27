/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

package org.wso2.carbon.extension.identity.authenticator.passwordpolicy.test;

import org.mockito.Mockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.policy.password.PasswordPolicyConstants;
import org.wso2.carbon.identity.policy.password.PasswordPolicyUtils;
import org.wso2.carbon.identity.policy.password.internal.PasswordPolicyDataHolder;
import org.wso2.carbon.utils.CarbonUtils;

import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

/**
 * Tests for password change utils
 */
@PrepareForTest({CarbonUtils.class})
public class PasswordPolicyUtilsTest {
    private static final String TENANT_DOMAIN = "carbon.super";

    @Test
    public void testGetPasswordExpiryPropertyNames() {
        mockStatic(CarbonUtils.class);

        String[] passwordExpiryPropertyNames = PasswordPolicyUtils.getPasswordExpiryPropertyNames();

        Assert.assertEquals(passwordExpiryPropertyNames.length, 3);
        Assert.assertEquals(passwordExpiryPropertyNames[0],
                PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS);
        Assert.assertEquals(passwordExpiryPropertyNames[1],
                PasswordPolicyConstants.CONNECTOR_CONFIG_ENABLE_DATA_PUBLISHING);
        Assert.assertEquals(passwordExpiryPropertyNames[2],
                PasswordPolicyConstants.CONNECTOR_CONFIG_PRIOR_NOTICE_TIME_IN_DAYS);
    }

    @Test
    public void testGetIdentityEventProperty() throws IdentityGovernanceException {
        Property[] properties = new Property[1];
        Property property = new Property();
        property.setName("test");
        property.setValue("testValue");
        properties[0] = property;

        IdentityGovernanceService identityGovernanceService = mock(IdentityGovernanceService.class);
        when(identityGovernanceService.getConfiguration(Mockito.any(String[].class), Mockito.eq(TENANT_DOMAIN)))
                .thenReturn(properties);
        PasswordPolicyDataHolder.getInstance().setIdentityGovernanceService(identityGovernanceService);

        Assert.assertEquals(PasswordPolicyUtils.getIdentityEventProperty(TENANT_DOMAIN, "test"), "testValue");
    }
}
