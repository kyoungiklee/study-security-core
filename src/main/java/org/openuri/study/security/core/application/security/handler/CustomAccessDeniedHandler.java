package org.openuri.study.security.core.application.security.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Setter
@Getter
@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    private String errorPage;
    @Override
    public void handle(HttpServletRequest request
            , HttpServletResponse response
            , AccessDeniedException accessDeniedException) throws IOException, ServletException {
        // 에러 페이지로 이동 시 에러 메시지를 전달하기 위해 파라미터를 추가한다.
        String deniedUrl = errorPage + "?exception=" + accessDeniedException.getMessage();
        // deniedUrl로 redirect
        response.sendRedirect(deniedUrl);
    }
}
