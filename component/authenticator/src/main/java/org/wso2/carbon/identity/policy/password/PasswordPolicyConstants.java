/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.policy.password;

/**
 * Password Change authenticator's constants
 */
public class PasswordPolicyConstants {
    public static final String AUTHENTICATOR_NAME = "password-reset-enforcer";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Password Reset Enforcer";
    public static final String AUTHENTICATOR_TYPE = "LOCAL";
    public static final String STATE = "state";

    public static final String CURRENT_PWD = "CURRENT_PWD";
    public static final String NEW_PWD = "NEW_PWD";
    public static final String NEW_PWD_CONFIRMATION = "NEW_PWD_CONFIRMATION";

    public static final String LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM =
            "http://wso2.org/claims/identity/lastPasswordUpdateTime";
    public static final String EMAIL_ADDRESS_CLAIM = "http://wso2.org/claims/emailaddress";

    public static final String PASSWORD_CHANGE_STREAM_NAME =
            "org.wso2.carbon.identity.policy.password.PendingNotifications:1.0.0";
    public static final String PASSWORD_CHANGE_EVENT_HANDLER_NAME = "passwordExpiry";

    public static final String CONNECTOR_CONFIG_FRIENDLY_NAME = "Password Expiry";
    public static final String CONNECTOR_CONFIG_CATEGORY = "Password Policies";
    public static final String CONNECTOR_CONFIG_SUB_CATEGORY = "DEFAULT";

    public static final String CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS = "passwordExpiry.passwordExpiryInDays";
    public static final String CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS_DISPLAYED_NAME = "Password Expiry In Days";
    public static final String CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS_DESCRIPTION =
            "Number of days after which the password will expire";
    public static final int CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS_DEFAULT_VALUE = 30;

    public static final String CONNECTOR_CONFIG_ENABLE_DATA_PUBLISHING = "passwordExpiry.enableDataPublishing";
    public static final String CONNECTOR_CONFIG_ENABLE_DATA_PUBLISHING_DISPLAYED_NAME =
            "Enable Pending Email Notification Data Publishing";
    public static final String CONNECTOR_CONFIG_ENABLE_DATA_PUBLISHING_DESCRIPTION =
            "Enable to publish pending notification events to IS Analytics to enable email notifications";
    public static final boolean CONNECTOR_CONFIG_ENABLE_DATA_PUBLISHING_DEFAULT_VALUE = false;

    public static final String CONNECTOR_CONFIG_PRIOR_NOTICE_TIME_IN_DAYS = "passwordExpiry.priorNoticeTimeInDays";
    public static final String CONNECTOR_CONFIG_PRIOR_NOTICE_TIME_IN_DAYS_DISPLAYED_NAME =
            "Prior Notice Time In Days";
    public static final String CONNECTOR_CONFIG_PRIOR_NOTICE_TIME_IN_DAYS_DESCRIPTION =
            "Number of days before which the users should be notified of password expiry";
    public static final int CONNECTOR_CONFIG_PRIOR_NOTICE_TIME_IN_DAYS_DEFAULT_VALUE = 0;

    private PasswordPolicyConstants() {      // To prevent instantiation
    }
}
