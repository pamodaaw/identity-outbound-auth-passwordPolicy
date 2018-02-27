/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.policy.password;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.event.stream.core.EventStreamService;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.identity.policy.password.internal.PasswordPolicyDataHolder;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * Event Handler class which handles password update by user, password update by admin and add user events.
 * <p>
 * This updates the http://wso2.org/claims/lastPasswordChangedTimestamp claim upon the password change.
 * This also publishes the password change event to IS Analytics.
 */
public class PasswordChangeHandler extends AbstractEventHandler implements IdentityConnectorConfig {
    private static final Log log = LogFactory.getLog(PasswordChangeHandler.class);

    @Override
    public void handleEvent(Event event) throws IdentityEventException {
        // Fetching event properties
        String username = (String) event.getEventProperties().get(IdentityEventConstants.EventProperty.USER_NAME);
        String tenantDomain = (String) event.getEventProperties()
                .get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);
        UserStoreManager userStoreManager = (UserStoreManager) event.getEventProperties()
                .get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);

        String userStoreDomain = UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration());
        long timestamp = System.currentTimeMillis();

        // Updating the last password changed claim
        Map<String, String> claimMap = new HashMap<>();
        claimMap.put(PasswordPolicyConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM,
                Long.toString(timestamp));
        try {
            userStoreManager.setUserClaimValues(username, claimMap, null);
            if (log.isDebugEnabled()) {
                log.debug("The claim uri "
                        + PasswordPolicyConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM + " of "
                        + username + " updated with the current timestamp");
            }
        } catch (UserStoreException e) {
            log.error("Failed to update claim value for "
                    + PasswordPolicyConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM
                    + " claim due to " + e.getMessage(), e);
            throw new IdentityEventException("An Error Occurred in updating the password. Please contact admin.", e);
        }

        // Getting the data publishing enabled property
        String dataPublishingEnabledProperty = PasswordPolicyUtils.getIdentityEventProperty(tenantDomain,
                PasswordPolicyConstants.CONNECTOR_CONFIG_ENABLE_DATA_PUBLISHING);
        boolean isPublishingToISAnalyticsEnabled =
                PasswordPolicyConstants.CONNECTOR_CONFIG_ENABLE_DATA_PUBLISHING_DEFAULT_VALUE;
        if (dataPublishingEnabledProperty != null) {
            isPublishingToISAnalyticsEnabled = Boolean.parseBoolean(dataPublishingEnabledProperty);
        }

        if (isPublishingToISAnalyticsEnabled) {
            // Getting the number of days before password expiry in days property
            String passwordExpiryInDaysProperty = PasswordPolicyUtils.getIdentityEventProperty(tenantDomain,
                    PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS);
            int passwordExpiryInDays =
                    PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS_DEFAULT_VALUE;
            if (passwordExpiryInDaysProperty != null) {
                passwordExpiryInDays = Integer.parseInt(passwordExpiryInDaysProperty);
            }

            // Getting the number of days before which prior notice should be given
            String priorNoticeInDaysProperty = PasswordPolicyUtils.getIdentityEventProperty(tenantDomain,
                    PasswordPolicyConstants.CONNECTOR_CONFIG_PRIOR_NOTICE_TIME_IN_DAYS);
            int priorNoticeInDays =
                    PasswordPolicyConstants.CONNECTOR_CONFIG_PRIOR_NOTICE_TIME_IN_DAYS_DEFAULT_VALUE;
            if (priorNoticeInDaysProperty != null) {
                priorNoticeInDays = Integer.parseInt(priorNoticeInDaysProperty);
            }

            long timeStampToSendNotification = timestamp +
                    (passwordExpiryInDays - priorNoticeInDays) * 24 * 60 * 60 * 1000;

            publishToISAnalytics(username, userStoreDomain, tenantDomain, userStoreManager,
                    timeStampToSendNotification);
        }
    }

    /**
     * Publish the password change event to IS Analytics
     *
     * @param username                    The username of the user
     * @param userStoreDomain             The user store domain of the user
     * @param tenantDomain                The tenant domain of the user
     * @param userStoreManager            The user store manager of the user
     * @param timestampToSendNotification The time at which the notification should be sent
     */
    private void publishToISAnalytics(String username, String userStoreDomain, String tenantDomain,
                                      UserStoreManager userStoreManager, long timestampToSendNotification) {
        // Fetching the email
        String email = null;
        try {
            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            email = userStoreManager.getUserClaimValue(tenantAwareUsername,
                    PasswordPolicyConstants.EMAIL_ADDRESS_CLAIM, null);
        } catch (UserStoreException e) {
            log.error("Failed to fetch the email due to " + e.getMessage(), e);
        }

        EventStreamService service = PasswordPolicyDataHolder.getInstance().getEventStreamService();

        // Creating the event to be sent
        org.wso2.carbon.databridge.commons.Event dataBridgeEvent = new org.wso2.carbon.databridge.commons.Event();
        dataBridgeEvent.setTimeStamp(timestampToSendNotification);
        dataBridgeEvent.setStreamId(PasswordPolicyConstants.PASSWORD_CHANGE_STREAM_NAME);

        // Creating the payload data
        Object[] payloadData = new Object[5];
        payloadData[0] = tenantDomain;
        payloadData[1] = userStoreDomain;
        payloadData[2] = username;
        payloadData[3] = email;
        payloadData[4] = timestampToSendNotification;
        dataBridgeEvent.setPayloadData(payloadData);

        service.publish(dataBridgeEvent);
        if (log.isDebugEnabled()) {
            log.debug("Published " + dataBridgeEvent.toString() + " to IS Analytics");
        }
    }

    @Override
    public String getName() {
        return PasswordPolicyConstants.PASSWORD_CHANGE_EVENT_HANDLER_NAME;
    }

    @Override
    public String getFriendlyName() {
        return PasswordPolicyConstants.CONNECTOR_CONFIG_FRIENDLY_NAME;
    }

    @Override
    public String getCategory() {
        return PasswordPolicyConstants.CONNECTOR_CONFIG_CATEGORY;
    }

    @Override
    public String getSubCategory() {
        return PasswordPolicyConstants.CONNECTOR_CONFIG_SUB_CATEGORY;
    }

    @Override
    public int getOrder() {
        return 0;
    }

    @Override
    public Map<String, String> getPropertyNameMapping() {
        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS,
                PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS_DISPLAYED_NAME);
        nameMapping.put(PasswordPolicyConstants.CONNECTOR_CONFIG_ENABLE_DATA_PUBLISHING,
                PasswordPolicyConstants.CONNECTOR_CONFIG_ENABLE_DATA_PUBLISHING_DISPLAYED_NAME);
        nameMapping.put(PasswordPolicyConstants.CONNECTOR_CONFIG_PRIOR_NOTICE_TIME_IN_DAYS,
                PasswordPolicyConstants.CONNECTOR_CONFIG_PRIOR_NOTICE_TIME_IN_DAYS_DISPLAYED_NAME);
        return nameMapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {
        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS,
                PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS_DESCRIPTION);
        nameMapping.put(PasswordPolicyConstants.CONNECTOR_CONFIG_ENABLE_DATA_PUBLISHING,
                PasswordPolicyConstants.CONNECTOR_CONFIG_ENABLE_DATA_PUBLISHING_DESCRIPTION);
        nameMapping.put(PasswordPolicyConstants.CONNECTOR_CONFIG_PRIOR_NOTICE_TIME_IN_DAYS,
                PasswordPolicyConstants.CONNECTOR_CONFIG_PRIOR_NOTICE_TIME_IN_DAYS_DESCRIPTION);
        return nameMapping;
    }

    @Override
    public String[] getPropertyNames() {
        return PasswordPolicyUtils.getPasswordExpiryPropertyNames();
    }

    @Override
    public Properties getDefaultPropertyValues(String tenantDomain) throws IdentityGovernanceException {
        Properties properties = new Properties();
        properties.put(PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS,
                PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS_DEFAULT_VALUE);
        properties.put(PasswordPolicyConstants.CONNECTOR_CONFIG_ENABLE_DATA_PUBLISHING,
                PasswordPolicyConstants.CONNECTOR_CONFIG_ENABLE_DATA_PUBLISHING_DEFAULT_VALUE);
        properties.put(PasswordPolicyConstants.CONNECTOR_CONFIG_PRIOR_NOTICE_TIME_IN_DAYS,
                PasswordPolicyConstants.CONNECTOR_CONFIG_PRIOR_NOTICE_TIME_IN_DAYS_DEFAULT_VALUE);
        return properties;
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] propertyNames, String tenantDomain)
            throws IdentityGovernanceException {
        return null;
    }
}
