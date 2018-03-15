package com.aa.security.saml.pojo;

import java.io.Serializable;

public class User implements Serializable {

    private static final long serialVersionUID = 8919331504794100140L;
    private String name;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

}
