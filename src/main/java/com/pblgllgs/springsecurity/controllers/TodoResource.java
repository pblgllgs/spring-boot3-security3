package com.pblgllgs.springsecurity.controllers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@RestController
public class TodoResource {

    private Logger logger = LoggerFactory.getLogger(getClass());

    private static List<Todo> TODOS = Arrays.asList(
            new Todo("pblgllgs", "AWS"),
            new Todo("pblgllgs", "DOCKER")
    );

    @GetMapping("/todos")
    public List<Todo> retrieveTodos() {
        return TODOS;
    }

    @GetMapping("/users/{username}/todos")
    public List<Todo> retrieveTodosForSpecificUser(@PathVariable String username) {
        return TODOS.stream().filter(x -> Objects.equals(x.name(), "pblgllgs")).collect(Collectors.toList());
    }

    @PostMapping("/users/{username}/todos")
    public void createTodosForSpecificUser(@PathVariable String username, @RequestBody Todo todo) {
        logger.info("Create {} for {}", todo, username);
    }


}

record Todo(String name, String description) {
}
