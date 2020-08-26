package com.springboot.jwt.models;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "roles")
public class Role {

    @Id
    private String id;

    private RoleEnum name;

    public Role(){}

    public Role(RoleEnum roleEnum){
        this.name = roleEnum;
    }

    public Role(String id, RoleEnum name) {
        this.id = id;
        this.name = name;
    }

    public String getId() {
        return id;
    }

    public RoleEnum getName() {
        return name;
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setName(RoleEnum name) {
        this.name = name;
    }


}
