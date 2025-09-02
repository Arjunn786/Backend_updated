package com.project.demo.repository;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.project.demo.model.RefreshToken;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Repository
public class RefreshTokenRepository {

    private final ObjectMapper mapper;
    private final File file;

    public RefreshTokenRepository(@Value("${refresh.tokens.file.path:data/refresh_tokens.json}") String path) {
        this.mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule()); // Important for serializing the 'Instant' object
        this.file = new File(path);
        try {
            Files.createDirectories(file.toPath().getParent());
            if (!file.exists()) {
                mapper.writerWithDefaultPrettyPrinter().writeValue(file, new ArrayList<RefreshToken>());
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to init refresh tokens file", e);
        }
    }

    private synchronized List<RefreshToken> loadAll() {
        try {
            if (!file.exists()) return new ArrayList<>();
            return mapper.readValue(file, new TypeReference<List<RefreshToken>>() {});
        } catch (IOException e) {
            throw new RuntimeException("Failed to read refresh tokens file", e);
        }
    }

    private synchronized void saveAll(List<RefreshToken> tokens) {
        try {
            mapper.writerWithDefaultPrettyPrinter().writeValue(file, tokens);
        } catch (IOException e) {
            throw new RuntimeException("Failed to write refresh tokens file", e);
        }
    }

    public Optional<RefreshToken> findByToken(String token) {
        return loadAll().stream().filter(rt -> rt.getToken().equals(token)).findFirst();
    }

    public synchronized void save(RefreshToken refreshToken) {
        List<RefreshToken> tokens = loadAll();
        tokens.removeIf(rt -> rt.getUsername().equalsIgnoreCase(refreshToken.getUsername()));
        tokens.add(refreshToken);
        saveAll(tokens);
    }

    public synchronized void deleteByToken(String token) {
        List<RefreshToken> tokens = loadAll();
        tokens.removeIf(rt -> rt.getToken().equals(token));
        saveAll(tokens);
    }
}