package org.openuri.study.security.core.application.port.in;


import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.PositiveOrZero;
import lombok.*;
import org.openuri.study.security.core.common.SelfValidation;

@Data
@EqualsAndHashCode(callSuper = false)
@Builder
@NoArgsConstructor
public class RegisterUserCommand extends SelfValidation<RegisterUserCommand> {
    @NotBlank
    private String username;
    @NotBlank
    private String password;
    @NotBlank @Email
    private String email;
    @PositiveOrZero
    private int age;
    @NotBlank
    private String role;

    public RegisterUserCommand(@NotBlank String username, @NotBlank String password, @NotBlank @Email String email, @PositiveOrZero int age, @NotBlank String role) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.age = age;
        this.role = role;
        validateSelf();
    }
}
