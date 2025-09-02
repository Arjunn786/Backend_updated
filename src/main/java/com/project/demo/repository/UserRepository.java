package com.project.demo.repository;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.project.demo.model.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Repository
public class UserRepository {

    private final ObjectMapper mapper = new ObjectMapper();
    private final File file;

    public UserRepository(@Value("${users.file.path:data/users.json}") String path) {
        this.file = new File(path);
        try {
            Files.createDirectories(file.toPath().getParent());
            if (!file.exists()) {
                mapper.writerWithDefaultPrettyPrinter().writeValue(file, new ArrayList<User>());
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to init users file", e);
        }
    }

    private synchronized List<User> loadAll() {
        try {
            if (!file.exists()) return new ArrayList<>();
            return mapper.readValue(file, new TypeReference<List<User>>() {});
        } catch (IOException e) {
            throw new RuntimeException("Failed to read users file", e);
        }
    }

    private synchronized void saveAll(List<User> users) {
        try {
            mapper.writerWithDefaultPrettyPrinter().writeValue(file, users);
        } catch (IOException e) {
            throw new RuntimeException("Failed to write users file", e);
        }
    }

    public Optional<User> findByUsername(String username) {
        return loadAll().stream().filter(u -> u.getUsername().equalsIgnoreCase(username)).findFirst();
    }

    public synchronized void save(User user) {
        List<User> users = loadAll();
        users.removeIf(u -> u.getUsername().equalsIgnoreCase(user.getUsername()));
        users.add(user);
        saveAll(users);
    }
}