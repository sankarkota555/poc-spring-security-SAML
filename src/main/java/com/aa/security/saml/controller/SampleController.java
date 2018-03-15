package com.aa.security.saml.controller;

import java.security.Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.aa.security.saml.pojo.User;

@RestController
public class SampleController {

    private static final Logger log = LoggerFactory.getLogger(SampleController.class);

    @GetMapping(value = "/getUser")
    public User getUser(Principal principal) {
        log.info("Principal objectL:{}", principal);
        User user = new User();
        if (principal != null)
            user.setName(principal.getName());
        return user;
    }

}
