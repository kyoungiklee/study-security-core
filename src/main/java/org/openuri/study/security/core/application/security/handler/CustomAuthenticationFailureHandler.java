package org.openuri.study.security.core.application.security.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import java.io.IOException;

public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String message = "Invalid Username or Password";
        if (exception instanceof BadCredentialsException) {
            setDefaultFailureUrl("/login?error=true&exception=" + message);
        }else{
            message = "Invalid Secret Key";
            setDefaultFailureUrl("/login?error=true&exception=" + message);
        }
        super.onAuthenticationFailure(request, response, exception);
    }
}
