package com.app.SpringSecurityApp.repository;

import com.app.SpringSecurityApp.persistence.entity.UserEntity;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends CrudRepository<UserEntity, Long> {

    //Query method de JPA para traer un usuario por username
    Optional<UserEntity> findUserEntityByUsername(String username);

}
