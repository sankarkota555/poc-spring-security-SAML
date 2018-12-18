package com.aa.security.saml.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@DependsOn("metadataGeneratorFilter")
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private SAMLEntryPoint samlEntryPoint;

    @Autowired
    private MetadataGeneratorFilter metadataGeneratorFilter;

    @Autowired
    private SAMLAuthenticationProvider samlAuthenticationProvider;

    @Autowired
    private SAMLLogoutProcessingFilter samlLogoutProcessingFilter;

    @Autowired
    private SAMLLogoutFilter samlLogoutFilter;

    @Autowired
    private SavedRequestAwareAuthenticationSuccessHandler savedRequestAwareAuthenticationSuccessHandler;

    @Autowired
    private SimpleUrlAuthenticationFailureHandler simpleUrlAuthenticationFailureHandler;

    /**
     * Defines the web based security configuration.
     * 
     * @param http
     *            It allows configuring web based security for specific http
     *            requests.
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic().authenticationEntryPoint(samlEntryPoint);

        http.csrf().disable();
        http.addFilterBefore(metadataGeneratorFilter, ChannelProcessingFilter.class);

       /* http.authorizeRequests().antMatchers("/").authenticated().antMatchers("/saml/**").permitAll().anyRequest()
                .authenticated();*/
        
        http.authorizeRequests().antMatchers("/health").permitAll().antMatchers("/saml/**").permitAll().antMatchers("/admin/**").hasRole("ADMIN")
        .antMatchers("/**").hasRole("USER").anyRequest().authenticated();

        http.logout().logoutSuccessUrl("/");
    }

    /**
     * Sets a custom authentication provider.
     * 
     * @param auth
     *            SecurityBuilder used to create an AuthenticationManager.
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(samlAuthenticationProvider);
    }

    /**
     * Returns the authentication manager currently used by Spring. It
     * represents a bean definition with the aim allow wiring from other classes
     * performing the Inversion of Control (IoC).
     * 
     * @throws Exception
     */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    // Processing filter for WebSSO profile messages
    @Bean
    public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
        SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
        samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());
        samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(savedRequestAwareAuthenticationSuccessHandler);
        samlWebSSOProcessingFilter.setAuthenticationFailureHandler(simpleUrlAuthenticationFailureHandler);
        return samlWebSSOProcessingFilter;
    }

    /**
     * Define the security filter chain in order to support SSO Auth by using
     * SAML 2.0
     * 
     * @return Filter chain proxy
     * @throws Exception
     */
    @Bean
    public FilterChainProxy samlFilter() throws Exception {
        List<SecurityFilterChain> chains = new ArrayList<>();
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/login/**"), samlEntryPoint));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/logout/**"), samlLogoutFilter));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSO/**"),
                samlWebSSOProcessingFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SingleLogout/**"),
                samlLogoutProcessingFilter));

        return new FilterChainProxy(chains);
    }

}
