package dev.igorsily.course.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("teste")
public class CourseController {

    @GetMapping
    private String index(){
        return "TESTE OK";
    }
}
