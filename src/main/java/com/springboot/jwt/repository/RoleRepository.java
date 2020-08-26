package com.springboot.jwt.repository;

import com.springboot.jwt.models.Role;
import com.springboot.jwt.models.RoleEnum;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface RoleRepository extends MongoRepository<Role, String> {

    Optional<Role> findByName(RoleEnum name);

}
