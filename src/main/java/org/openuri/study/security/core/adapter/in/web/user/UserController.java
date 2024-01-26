package org.openuri.study.security.core.adapter.in.web.user;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.openuri.study.security.core.application.port.in.RegisterUserCommand;
import org.openuri.study.security.core.application.port.in.RegisterUserUseCase;
import org.openuri.study.security.core.domain.Account;
import org.springframework.stereotype.Controller;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@Slf4j
@RequiredArgsConstructor
public class UserController {
    private final RegisterUserUseCase registerUserUseCase;
    @GetMapping("/mypage")
    public String user() {
        return "user/mypage";
    }

    @GetMapping("/users")
    public String register() {
        return "user/register";
    }

    @PostMapping("/users")
    public String register(@Valid RegisterUserRequest request, Errors errors) {
        if (errors.hasErrors()) {
            return "user/register";
        }
        log.info("request: {}", request);

        RegisterUserCommand command = RegisterUserCommand.builder()
                .username(request.getUsername())
                .password(request.getPassword())
                .email(request.getEmail())
                .age(request.getAge())
                .role(request.getRole())
                .build();
        Account register = registerUserUseCase.register(command);
        log.info("register: {}", register);

        return "redirect:/";
    }

    public static void main(String[] args) {
        System.out.println("Hello, world!");

    }
}
