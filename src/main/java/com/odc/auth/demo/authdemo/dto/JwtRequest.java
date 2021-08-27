package com.odc.auth.demo.authdemo.dto;

import lombok.Data;

@Data
public class JwtRequest {

    private String username;
    private String password;

}
