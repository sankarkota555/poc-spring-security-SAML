package com.aa.security.saml.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SampleController {

    @GetMapping(path = "/hello")
    public String sayHello() {
        return "Hello world!!";
    }

}
