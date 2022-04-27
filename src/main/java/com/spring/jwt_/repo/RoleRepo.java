package com.spring.jwt_.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.spring.jwt_.model.Role;

public interface RoleRepo extends JpaRepository<Role, Long>{

	Role findByName(String name);
}
