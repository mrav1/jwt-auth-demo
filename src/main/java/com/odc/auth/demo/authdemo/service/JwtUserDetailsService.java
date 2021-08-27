package com.odc.auth.demo.authdemo.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class JwtUserDetailsService implements UserDetailsService {

    public UserDetails loadUserByUsername(String username) {
        final String password = new BCryptPasswordEncoder().encode("demo#1");
        final UserDetails userDetails = new User(username, password, new ArrayList<>());
        return userDetails;
    }

}
