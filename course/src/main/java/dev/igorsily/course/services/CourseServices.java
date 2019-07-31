package dev.igorsily.course.services;

import dev.igorsily.core.repositories.CourseRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CourseServices {

    @Autowired
    private CourseRepository courseRepository;
}
