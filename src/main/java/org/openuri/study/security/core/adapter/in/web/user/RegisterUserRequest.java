package org.openuri.study.security.core.adapter.in.web.user;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.PositiveOrZero;
import lombok.Data;

@Data
public class RegisterUserRequest {

    @NotBlank(message = "Username is mandatory")
    private String username;
    @NotBlank(message = "Password is mandatory")
    private String password;
    @NotBlank(message = "Email is mandatory")
    private String email;
    @PositiveOrZero(message = "Age must be positive or zero")
    private int age;
    @NotBlank(message = "Role is mandatory")
    private String role;



    @Override
    public String toString() {
        return "RegisterUserRequest{" +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", email='" + email + '\'' +
                ", age=" + age +
                ", role='" + role + '\'' +
                '}';
    }
}
