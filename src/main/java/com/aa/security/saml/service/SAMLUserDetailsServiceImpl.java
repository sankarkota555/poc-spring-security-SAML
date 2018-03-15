package com.aa.security.saml.service;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class SAMLUserDetailsServiceImpl implements SAMLUserDetailsService {

    // Logger
    private static final Logger log = LoggerFactory.getLogger(SAMLUserDetailsServiceImpl.class);

    public Object loadUserBySAML(SAMLCredential credential) {

        // The method is supposed to identify local account of user referenced
        // by
        // data in the SAML assertion and return UserDetails object describing
        // the user.
        log.info("All attributes available in credential");
        credential.getAttributes().stream().forEach(attr -> log.info("name: {} ", attr.getName()));

        String userID = credential.getNameID().getValue();
        log.info("logged in user ID:{}", userID);
        List<GrantedAuthority> authorities = new ArrayList<>();
        GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
        authorities.add(authority);

        // In a real scenario, this implementation has to locate user in a
        // arbitrary
        // dataStore based on information present in the SAMLCredential and
        // returns such a date in a form of application specific UserDetails
        // object.
        return new User(userID, "****", true, true, true, true, authorities);
    }

}
