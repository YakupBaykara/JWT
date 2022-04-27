package com.spring.jwt_.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.spring.jwt_.model.User;

public interface UserRepo extends JpaRepository<User, Long>{

	User findByUsername(String username);
}
