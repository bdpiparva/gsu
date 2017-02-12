package com.thoughtworks.go.server.security;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.Collection;
import java.util.Iterator;

import static org.junit.Assert.fail;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {
        "classpath:WEB-INF/applicationContext-global.xml",
        "classpath:WEB-INF/applicationContext-dataLocalAccess.xml",
        "classpath:WEB-INF/applicationContext-acegi-security.xml",
        "classpath:WEB-INF/spring-rest-servlet.xml"
})
public class AcegiSecurityConfigTest {
    @Autowired
    private FilterSecurityInterceptor filterInvocationInterceptor;
    private DefaultFilterInvocationSecurityMetadataSource objectDefinitionSource;

    @Before
    public void setUp() throws Exception {
        objectDefinitionSource = (DefaultFilterInvocationSecurityMetadataSource) filterInvocationInterceptor.obtainSecurityMetadataSource();
    }

    @Test
    public void shouldAllowOnlyRoleUserToHaveAccessToWildcardUrls() {
        verifyGetAccessToUrlPatternIsAvailableToRole(objectDefinitionSource, "/**", "ROLE_USER");
        verifyGetAccessToUrlPatternIsAvailableToRole(objectDefinitionSource, "/**/*.js", "ROLE_USER");
        verifyGetAccessToUrlPatternIsAvailableToRole(objectDefinitionSource, "/**/*.css", "ROLE_USER");
        verifyGetAccessToUrlPatternIsAvailableToRole(objectDefinitionSource, "/**/*.png", "ROLE_USER");
    }

    @Test
    public void shouldAllowAnonymousAccessToAssets() {
        verifyGetAccessToUrlPatternIsAvailableToRole(objectDefinitionSource, "/assets/**", "IS_AUTHENTICATED_ANONYMOUSLY");
        verifyGetAccessToUrlPatternIsAvailableToRole(objectDefinitionSource, "/assets/**/*.js", "IS_AUTHENTICATED_ANONYMOUSLY");
        verifyGetAccessToUrlPatternIsAvailableToRole(objectDefinitionSource, "/assets/**/*.css", "IS_AUTHENTICATED_ANONYMOUSLY");
        verifyGetAccessToUrlPatternIsAvailableToRole(objectDefinitionSource, "/assets/**/*.jpg", "IS_AUTHENTICATED_ANONYMOUSLY");
    }

    @Test
    public void shouldNotAllowAnonymousAccessToWildcardAuthUrl(){
        verifyGetAccessToUrlPatternIsAvailableToRole(objectDefinitionSource, "/auth/login", "IS_AUTHENTICATED_ANONYMOUSLY");
        verifyGetAccessToUrlPatternIsAvailableToRole(objectDefinitionSource, "/auth/logout", "IS_AUTHENTICATED_ANONYMOUSLY");
    }

    private void verifyGetAccessToUrlPatternIsAvailableToRole(DefaultFilterInvocationSecurityMetadataSource objectDefinitionSource, String urlPattern, String role) {
        Collection definition = objectDefinitionSource.getAllConfigAttributes();
        Iterator iterator = definition.iterator();
        StringBuilder allowedAccess = new StringBuilder();
        while (iterator.hasNext()) {
            SecurityConfig securityConfig = (SecurityConfig) iterator.next();
            if (securityConfig.getAttribute().equals(role))
                return;
            else
                allowedAccess.append(securityConfig.getAttribute() + ",");
        }
        fail(String.format("Expected access to url %s only by %s but found %s", urlPattern, role, allowedAccess.toString()));
    }
}
