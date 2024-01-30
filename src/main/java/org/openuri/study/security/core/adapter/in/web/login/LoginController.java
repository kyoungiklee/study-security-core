package org.openuri.study.security.core.adapter.in.web.login;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.openuri.study.security.core.domain.Account;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@Slf4j
public class LoginController {

    /**
     * 로그인 페이지로 이동한다.
     * <p>인증 실패시 로그인 페이지로 리다아렉트 된다
     * 에러시 전달된 파라미터는 모델에 담아 뷰에 전달 된다.
     * </p>
     *
     * @param error     로그인 실패시 error 파라미터가 존재한다.
     * @param exception 로그인 실패시 exception 파라미터가 존재한다.
     * @param model     뷰에 전달할 데이터
     * @return 로그인 페이지
     */
    @GetMapping(value = {"/login", "/api/login"})
    public String login(@RequestParam(value = "error", required = false) String error,
                        @RequestParam(value = "exception", required = false) String exception,
                        Model model) {

        log.info("error : {}", error);
        log.info("exception : {}", exception);
        if (error != null) {
            model.addAttribute("error", error);
        }
        if (exception != null) {
            model.addAttribute("exception", exception);
        }
        return "login/loginForm";
    }


    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }
        return "redirect:/login";
    }

    @GetMapping(value = {"/denied", "/api/denied"})
    public String denied(@RequestParam(value = "exception", required = false) String exception,
                         Model model) {
        log.info("exception : {}", exception);
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Account principal = (Account) authentication.getPrincipal();
        model.addAttribute("username", principal.getUsername());
        model.addAttribute("exception", exception);
        return "login/denied";
    }
}
