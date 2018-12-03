package com.boot.security.validation.validator;

import com.boot.security.service.UserService;
import com.boot.security.validation.UniqueEmail;
import org.springframework.beans.factory.annotation.Autowired;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class UniqueEmailValidator implements ConstraintValidator<UniqueEmail, String> {

    @Autowired
    private UserService userService;

    @Override
    public void initialize(final UniqueEmail constraintAnnotation) {
    }

    @Override
    public boolean isValid(final String email, final ConstraintValidatorContext context) {

        return (isExistEmail(email));
    }

    private boolean isExistEmail(final String email) {

        return userService.isExistEmail(email);

    }
}
