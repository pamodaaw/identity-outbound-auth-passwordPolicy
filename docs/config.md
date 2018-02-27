# Configuring Password Policy

> Password Reset Enforcer 1.0.5 is supported by WSO2 Identity Server 5.4.0

* [Setting up Password Policy](#setting-up-password-policy)
* [Enabling the Password History Feature](#enabling-the-password-history-feature)
* [Enabling Email Notifications](#enabling-email-notifications)

## Setting up Password Reset Enforcer

### Deploying Artifacts

1. Download the Password Reset Enforcer and its artifacts from [WSO2 Store](https://store.wso2.com/store/assets/isconnector/details/502efeb1-cc59-4b62-a197-8c612797933c).
2. Add the following lines to `<IS_HOME>/repository/conf/identity/identity-event.properties` file
   ```
   module.name.11=passwordExpiry
   passwordExpiry.subscription.1=POST_UPDATE_CREDENTIAL
   passwordExpiry.subscription.2=POST_UPDATE_CREDENTIAL_BY_ADMIN
   passwordExpiry.subscription.3=POST_ADD_USER
   passwordExpiry.passwordExpiryInDays=30
   passwordExpiry.enableDataPublishing=false
   passwordExpiry.priorNoticeTimeInDays=0
   ```
   > Replace the module number `11` in `module.name.11=passwordExpiry` to one higher than the largest module number in the `identity-event.properties` file.
3. Copy the authentication page (`<PASSWORD_RESET_ENFORCER_ARTIFACTS>/is/pwd-reset.jsp`) to the `<IS_HOME>/repository/deployment/server/webapps/authenticationendpoint/` directory.
   
   > This directory is created after the first time you run Identity Server. If this is your first time, start the server once first.
4. Copy the connector (`org.wso2.carbon.extension.identity.authenticator.passwordpolicy.connector-1.0.5.jar`) to the `<IS_HOME>/repository/components/dropins/` directory.

> Please note that the Identity Server needs to be restarted after doing the above steps for the changes to take effect.

### Configuring the Expiration Policy

Follow the steps given below to configure the number of days after which the password should expire.

1. [Start](https://docs.wso2.com/display/IS540/Running+the+Product) the Identity Server and log in. (If you have not already done so)
2. In the `Identity` section under the `Main` tab, click `Resident` under `Identity Providers`.
3. Go to `Password Expiry` under `Password Policies`.
4. Change `Password Expiry In Days` according to your requirements.
   
   > By default, the Password Reset Enforcer will expire passwords in 30 days.
5. Click `Update` to save the changes.

> `Enable Pending Email Notification Data Publshing` and `Prior Notice Time In Days` configurations are used for configuring [email notifications](#enabling-email-notifications).

![Configuring the Expiration Policy](./img/password-expiry-policy-config.png "Configuring the Expiration Policy")

### Deploying the Sample App

This section explains how to use the Password Reset Enforcer using a sample app.
Deploy the sample web app [travelocity](https://docs.wso2.com/display/ISCONNECTORS/Deploying+the+Sample+App).
Once this is done the next step is to configure the service provider.

#### Configuring the Service Provider for the Sample App

1. [Start](https://docs.wso2.com/display/IS540/Running+the+Product) the Identity Server and log in. (If you have not already done so)
2. In the `Identity` section under the `Main` tab, click `Add` under `Service Providers`.
3. Enter `travelocity.com` in the `Service Provider Name` text box and click `Register`.
   ![Adding Service Provider](./img/add-service-provider.png "Adding Service Provider")
4. In the `Inbound Authentication Configuration` section, click `Configure` under the `SAML2 Web SSO Configuration` section.
5. Add the following line to the `/etc/hosts` file.
   ```
   127.0.0.1       wso2is.local
   ```
   > Some browsers do not allow you to create cookies for a naked hostname, such as localhost. Cookies are required when working with SSO. Therefore, to ensure that the SSO capabilities work as expected in this tutorial, you need to configure the etc/host file as explained in this step.
5. Configure the sample application (travelocity) as the service provider.
   * Issuer: `travelocity.com`
   * Assertion Consumer URL: `http://wso2is.local:8080/travelocity.com/home.jsp`
6. Enable the following options.
   * Response Signing
   * Single Logout
   * Attribute Profile
   * Include Attributes in the Response Always
   
   > The above options should be enabled or disabled according to your service provider. For travelocity, the relevant properties file (`travelocity.properties`) can be found inside the webapp `travelocy.com/WEB-INF/classes/`.
7. Click `Register` to save the changes. Now you will be sent back to the Service Providers page.
   ![Configuring SAML SSO](./img/configure-saml-sso.png "Configuring SAML SSO")


Follow the next few steps to add the password policy to the sample app

1. Go to `Local and Outbound Authentication Configuration` section in the Service Providers page.
2. Select the `Advanced Configuration` radio button option.
3. Add the `basic` authentication as the first step and `Password Reset Enforcer` authentication as the second step.
   * Select `User subject identifier from this step` under `basic` authentication.
   * Select `Use attributes from this step` under `Password Reset Enforcer`.
   ![Authentication Configuration](img/authentication-configuration.png "Authentication Configuration")

#### Testing the Sample App

Follow the steps given below to test the Password Reset Enforcer.

> These steps should not be followed in a production environment.

1. In the `Identity` section under the `Main` tab, click `List` under `Claims`.
2. Click `http://wso2.org/claims`.
3. Click `Edit` next to `Last Password Update Time` claim.
4. To test the sample, the password needs be expired manually. To edit the claim manually later, select `Supported by Default` checkbox.
5. Click `Update` to save the changes.
   ![Updating the Claim](img/update-claim.png "Updating the Claim")
6. In the `Identity` section under the `Main` tab, click `List` under `Users and Roles` and then click `Users`.
7. Click `User Profile` next to the `admin` user (Or any preferred user).
8. Edit `Last Password Update` to a lower number (This is the last password change timestamp in milliseconds).
9. Click `Update` to save the changes.
   ![Updating the Claim Value](img/update-claim-value.png "Updating the Claim Value")
10. Now try to log in to travelocity by going to `http://wso2is.local:8080/travelocity.com` and selecting a SAML SSO login option.
11. You will be requested to change the password.

## Enabling the Password History Feature

You can use the password history feature available on the Identity Server along with the password policy.
This will force the users to not use a previously used password again for a number of times into the future.
Please follow the instructions given in the [Password History Validation Policy](https://docs.wso2.com/display/IS540/Password+History+Validation) to enable this feature.

## Enabling Email Notifications

To enable email notifications you need [WSO2 IS Analytics](https://wso2.com/identity-and-access-management) Instance running alongside the WSO2 Identity Server.

> Password Reset Enforcer 1.0.5 is supported by WSO2 IS Analytics 5.4.0.

> Please note that the users need to have an email specified in the Identity Server. Otherwise, the expired passwords will only be logged in IS Analytics.

> Email notifications won't be sent to existing users until they change the password again.

### Setting up Identity Server

#### Deploying Artifacts

1. Copy the password changes stream (`<PASSWORD_RESET_ENFORCER_ARTIFACTS>/is/org.wso2.carbon.identity.policy.password.PendingNotifications_1.0.0.json`) to the `<IS_HOME>/repository/deployment/server/eventstreams/` directory.
2. Copy the password changes publisher (`<PASSWORD_RESET_ENFORCER_ARTIFACTS>/is/PasswordPolicy-Publisher-wso2event-PendingNotifications.xml`) to the `<IS_HOME>/repository/deployment/server/eventpublishers/` directory.

#### Configuring Identity Server

Follow the steps given below to enable notifications

1. [Start](https://docs.wso2.com/display/IS540/Running+the+Product) the Identity Server and log in. (If you have not already done so)
2. In the `Identity` section under the `Main` tab, click `Resident` under `Identity Providers`.
3. Go to `Password Expiry` under `Password Policies`.
4. Enable the `Enable Pending Email Notification Data Publishing` option.
4. Change `Prior Notice Time In Days` according to your requirements.
   
   > By default, the Password Reset Enforcer will send notifications 0 days prior to the password expiry (after password expiry).
5. Click `Update` to save the changes.

![Configuring the Email Notifications](./img/enable-email-notification-config.png "Configuring the Email Notifications")

### Setting up IS Analytics

#### Configuring Email Adapter

To enable IS Analytics to send emails the email output adapter needs to be configured. Follow the steps given below to configure it.

Edit the `<IS_ANALYTICS_HOME>/repository/conf/output-event-adapters.xml` file and change the following lines. Valid SMTP configuration should be provided to enable emails.
```xml
<adapterConfig type="email">
    <property key="mail.smtp.from">email-address</property>
    <property key="mail.smtp.user">user-name</property>
    <property key="mail.smtp.password">password</property>
    <property key="mail.smtp.host">smtp.gmail.com</property>
    <property key="mail.smtp.port">587</property>
    <property key="mail.smtp.starttls.enable">true</property>
    <property key="mail.smtp.auth">true</property>
    <!-- Thread Pool Related Properties -->
    <property key="maxThread">100</property>
    <property key="keepAliveTimeInMillis">20000</property>
    <property key="jobQueueSize">10000</property>
</adapterConfig>
```

Please note that the server needs to be restarted for the changes to take effect. (We can restart the server in the next section deploying artifacts.)

#### Deploying Artifacts

The following artifacts need to be deployed for IS Analytics to work properly

1. Copy the domain template (`<PASSWORD_RESET_ENFORCER_ARTIFACTS>/is-analytics/password-policy-notifications.xml`) to the `<IS_ANALYTICS_HOME>/repository/conf/template-manager/domain-template/` directory.
2. Copy the email event publisher (`<PASSWORD_RESET_ENFORCER_ARTIFACTS>/is-analytics/PasswordRotationPolicy-Publisher-email-Notifications-1.0.0.xml`) to the `<IS_ANALYTICS_HOME>/repository/deployment/server/eventpublishers/` directory.
   You may edit the `<inline>` tag in this file to change the email template according to your requirements.
3. [Start](https://docs.wso2.com/display/DAS310/Running+the+Product) the IS Analytics Server and log in. (Restart the server if the server is already running)
4. Install Password Reset Enforcer Carbon App (`<PASSWORD_RESET_ENFORCER_ARTIFACTS>/is-analytics/password_policy-1.0.0.car`)

#### Configuring IS Analytics

For IS Analytics to send notifications a new scenario needs to be added in the Template Manager. Follow the steps given below to create a new scenario.

1. [Start](https://docs.wso2.com/display/DAS310/Running+the+Product) the IS Analytics Server and log in. (If you have not already done so)
2. In the `Dashboard` section under the `Main` tab, click the `Template Manager`.
3. In the new window that appears, Select the PasswordRotationPolicyNotifications domain.
4. Click `Create New Scenario`.
5. Enter the following parameters.
   * Scenario Name - A name to recognize the scenario
   * Description - A description of the scenario
   * Pending Notifications check interval in days - The interval between two pending notifications check task runs
6. Click `Add Scenario`.
   ![Adding Scenario](img/add-scenario.png "Adding Scenario")

Now IS Analytics will check for expired passwords at the interval specified and send email notifications to the relevant users.
