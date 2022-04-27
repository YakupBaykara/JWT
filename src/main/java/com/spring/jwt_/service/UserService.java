package com.spring.jwt_.service;

import java.util.List;

import com.spring.jwt_.model.Role;
import com.spring.jwt_.model.User;

public interface UserService {

	User saveUser(User user);
	Role saveRole(Role role);
	void addRoleToUser(String username, String roleName);
	User getUser(String username);
	List<User> getUsers();
}
