package org.openuri.study.security.core.adapter.in.web.user;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @WithMockUser(authorities = {"ROLE_USER"})
    void user() throws Exception {
        mockMvc.perform(get("/mypage"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(authorities = {"ROLE_ANONYMOUS"})
    void testCreateUser() throws Exception {
        mockMvc.perform(post("/users")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("username", "test")
                .param("password", "test")
                .param("email", "mail@gmail.com")
                .param("age", "10")
                .param("role", "USER"))
                .andExpect(status().isForbidden());
    }

    @Test
    void testGetUsers() throws Exception {
        mockMvc.perform(get("/users"))
            .andExpect(status().isOk());
    }

    @Test
    void testRegister() {

        // code for testRegister test
    }

}