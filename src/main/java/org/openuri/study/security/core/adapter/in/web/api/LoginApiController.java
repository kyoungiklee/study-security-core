package org.openuri.study.security.core.adapter.in.web.api;

import jakarta.servlet.http.HttpSession;
import org.openuri.study.security.core.adapter.in.web.login.LoginResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginApiController {
    @GetMapping("/api/messages")
    public ResponseEntity<LoginResponse> messages(HttpSession session) {
        LoginResponse response = LoginResponse.builder()
                .username("user")
                .result("success")
                .build();
        return new ResponseEntity<>(response, null, HttpStatus.OK);
    }
}
