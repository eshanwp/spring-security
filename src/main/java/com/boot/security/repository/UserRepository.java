package com.boot.security.repository;

import com.boot.security.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserRepository extends JpaRepository<User, Long> {

    @Query("SELECT email FROM User WHERE email=:email")
    String isExistEmail(@Param("email") String email);

    User findByEmail(String email);
}
