package com.pblgllgs.springsecurity.controllers;

import jakarta.annotation.security.RolesAllowed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@RestController
public class TodoResource {

    private Logger logger = LoggerFactory.getLogger(getClass());

    private static List<Todo> TODOS = Arrays.asList(
            new Todo("username", "AWS"),
            new Todo("username", "DOCKER")
    );

    @GetMapping("/todos")
    public List<Todo> retrieveTodos() {
        return TODOS;
    }

    @GetMapping("/users/{username}/todos-all")
    @PreAuthorize("hasRole('USER') and #username == authentication.name")
    public List<Todo> retrieveTodosListForSpecificUser(@PathVariable String username) {
        return TODOS.stream().filter(x -> Objects.equals(x.name(), "username")).collect(Collectors.toList());
    }

    @GetMapping("/users/{username}/todos")
    @PreAuthorize("hasRole('USER') and #username == authentication.name")
    @PostAuthorize("returnObject.name() == 'username'")
    @RolesAllowed({"ADMIN", "USER"})
    @Secured({"ROLE_ADMIN", "ROLE_USER"})
    public Todo retrieveTodosForSpecificUser(@PathVariable String username) {
        return TODOS.get(0);
    }

    @PostMapping("/users/{username}/todos")
    public void createTodosForSpecificUser(@PathVariable String username, @RequestBody Todo todo) {
        logger.info("Create {} for {}", todo, username);
    }


}

record Todo(String name, String description) {
}
