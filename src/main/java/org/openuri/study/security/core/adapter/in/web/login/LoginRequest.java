package org.openuri.study.security.core.adapter.in.web.login;

import lombok.Data;

@Data
public class LoginRequest {
    private String username;
    private String password;
}
