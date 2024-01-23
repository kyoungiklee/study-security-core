package org.openuri.study.security.core.adapter.in.web.user;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class RegisterUserResponse {

    private Long id;
    private String username;
    private String password;
    private String email;
    private int age;
    private String role;

}
