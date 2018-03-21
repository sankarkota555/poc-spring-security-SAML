# Spring-Security-SAML POC for WAR
POC for Spring Security SAML demo application

Spring saml security documentation and quick start you can found at https://projects.spring.io/spring-security-saml/

# Building
Install maven

Clone this repo in eclipse or STS

# Running
Please find doncumentation for running spring boot app at https://docs.spring.io/spring-boot/docs/current/reference/html/using-boot-running-your-application.html

Once apllication is started running, goto application url http://localhost:8087/

1) Now you are redirected to SSO page from ssocircle, if you are a new user you can register and login into it.
2) After successfull login ssocircle will ask for recaptcha, verify captach and click on 'Continue SAML Single Sign On' button.
3) Here you will be redirected to our poc application.
4) You can see logged in user details.
4) Using logout link you can logout from application.

# Integrate in your app
Please follow below steps and change beans and variables in your [SAMLSecurityConfig.java](src/main/java/com/aa/security/saml/config/SAMLSecurityConfig.java) as per your requirement.
1) Change ENTITY_ID to your unique ID.

 Example: 
```java
           private static final String ENTITY_ID = "urn:test:yourname:yourcity";
```
2) I mentioned keymanager in below code, this is for only POC purpose. In real time we usually installing certificates in server. While integrating spring security saml in your application please don't maintain certificates in your code you can use java keytool command for importing certificates.

```java
    @Bean
    public KeyManager keyManager() {
        DefaultResourceLoader loader = new DefaultResourceLoader();
        Resource storeFile = loader.getResource("classpath:/saml/samlKeystore.jks");
        String storePass = "nalle123";
        Map<String, String> passwords = new HashMap<String, String>();
        passwords.put("apollo", "nalle123");
        String defaultKey = "apollo";
        return new JKSKeyManager(storeFile, storePass, passwords, defaultKey);
    }
```
3) Below bean is for retrieving IDP metadata, please change "http://idp.ssocircle.com/idp-meta.xml" to your IDP provided URL. We have another way to retrieve IDP metadata also please find it here https://docs.spring.io/spring-security-saml/docs/1.0.4.BUILD-SNAPSHOT/reference/htmlsingle/#chapter-idp-guide-adfs-idp
```java
    @Bean
    public ExtendedMetadataDelegate ssoCircleExtendedMetadataProvider() throws MetadataProviderException {
        // If you want to use HTTPS, you need to import SSL certificates
        String idpSSOCircleMetadataURL = "http://idp.ssocircle.com/idp-meta.xml";
        HTTPMetadataProvider httpMetadataProvider = new HTTPMetadataProvider(this.backgroundTaskTimer, httpClient(),
                idpSSOCircleMetadataURL);
        httpMetadataProvider.setParserPool(parserPool());
        ExtendedMetadataDelegate extendedMetadataDelegate = new ExtendedMetadataDelegate(httpMetadataProvider,
                extendedMetadata());
        extendedMetadataDelegate.setMetadataTrustCheck(false);
        extendedMetadataDelegate.setMetadataRequireSignature(false);
        backgroundTaskTimer.purge();
        return extendedMetadataDelegate;
    }
```

4) Please make sure you installed all the certificates provided by your IDP or SAML team.

# References
https://projects.spring.io/spring-security-saml/

Documentation: https://docs.spring.io/spring-security-saml/docs/1.0.4.BUILD-SNAPSHOT/reference/htmlsingle/

Sample application: https://github.com/spring-projects/spring-security-saml/tree/develop/sample
