package com.project.demo;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AuthControllerIntegrationTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private static String accessToken;
    private static String refreshToken;
    private static Cookie refreshTokenCookie;

    @BeforeAll
    static void cleanup() {
        new File("data/users.json").delete();
        new File("data/refresh_tokens.json").delete();
    }

    @Test
    @Order(1)
    @DisplayName("POST /auth/register - Should register a new user successfully")
    void shouldRegisterUser() throws Exception {
        Map<String, String> user = new HashMap<>();
        user.put("username", "testuser");
        user.put("password", "password123");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(user)))
                .andExpect(status().isOk());
    }

    @Test
    @Order(2)
    @DisplayName("POST /auth/login - Should log in and return tokens")
    void shouldLoginAndReturnTokens() throws Exception {
        Map<String, String> loginRequest = new HashMap<>();
        loginRequest.put("username", "testuser");
        loginRequest.put("password", "password123");

        MvcResult result = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String responseBody = result.getResponse().getContentAsString();
        Map<String, String> responseMap = objectMapper.readValue(responseBody, new TypeReference<>() {});
        accessToken = responseMap.get("accessToken");
        refreshToken = responseMap.get("refreshToken");
        refreshTokenCookie = result.getResponse().getCookie("refreshToken");

        assertNotNull(accessToken);
        assertNotNull(refreshTokenCookie);
    }

    @Test
    @Order(3)
    @DisplayName("GET /api/hello - Should access protected route with valid token")
    void shouldAccessProtectedRoute() throws Exception {
        assertNotNull(accessToken, "Login test must run first to get an access token.");

        mockMvc.perform(get("/api/hello")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(content().string("Hello, testuser! This is a protected resource."));
    }

    /**
     * THIS TEST IS CORRECTED
     */
    @Test
    @Order(4)
    @DisplayName("POST /auth/refreshtoken - Should rotate tokens and new token should be valid")
    void shouldRefreshToken() throws Exception {
        assertNotNull(refreshTokenCookie, "Login test must run first to get a refresh token cookie.");

        MvcResult result = mockMvc.perform(post("/auth/refreshtoken")
                        .cookie(refreshTokenCookie))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andExpect(cookie().exists("refreshToken"))
                .andReturn();

        // Extract new tokens
        String responseBody = result.getResponse().getContentAsString();
        Map<String, String> responseMap = objectMapper.readValue(responseBody, new TypeReference<>() {});
        String newAccessToken = responseMap.get("accessToken");
        String newRefreshToken = responseMap.get("refreshToken");
        Cookie newRefreshTokenCookie = result.getResponse().getCookie("refreshToken");

        // A more robust test: Prove the NEW access token actually works
        mockMvc.perform(get("/api/hello")
                        .header("Authorization", "Bearer " + newAccessToken))
                .andExpect(status().isOk())
                .andExpect(content().string("Hello, testuser! This is a protected resource."));

        // Update all static variables for the final logout test
        accessToken = newAccessToken;
        refreshToken = newRefreshToken;
        refreshTokenCookie = newRefreshTokenCookie;
    }

    @Test
    @Order(5)
    @DisplayName("POST /auth/logout - Should log out and invalidate tokens")
    void shouldLogout() throws Exception {
        assertNotNull(refreshTokenCookie, "Login and Refresh tests must run first.");

        mockMvc.perform(post("/auth/logout")
                        .cookie(refreshTokenCookie))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Successfully logged out"))
                .andExpect(cookie().maxAge("refreshToken", 0));

        // After logging out, attempting to refresh again should fail
        mockMvc.perform(post("/auth/refreshtoken")
                        .cookie(refreshTokenCookie))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Invalid refresh token"));
    }
}