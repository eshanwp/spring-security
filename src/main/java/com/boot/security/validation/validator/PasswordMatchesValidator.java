package com.boot.security.validation.validator;

import com.boot.security.dto.UserDto;
import com.boot.security.validation.PasswordMatches;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;


/*********************************************************************************************************
 * The PasswordMatchesValidator Custom Validator
 * *******************************************************************************************************/

public class PasswordMatchesValidator implements ConstraintValidator<PasswordMatches, Object> {

    @Override
    public void initialize(final PasswordMatches constraintAnnotation) {
        //
    }

    @Override
    public boolean isValid(final Object obj, final ConstraintValidatorContext context) {
        final UserDto user = (UserDto) obj;
        System.out.println(user.getPassword().equals(user.getMatchingPassword()));
        return user.getPassword().equals(user.getMatchingPassword());
    }

}
