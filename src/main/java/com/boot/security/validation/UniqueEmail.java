package com.boot.security.validation;

import com.boot.security.validation.validator.UniqueEmailValidator;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.*;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

/**************************************************************************************************************
 * @Constraint(…) —indicates what class is implementing the constraint for validation
 *
 * @Target(…) — indicates where this annotation can be applied, i.e. on a class, field, method.
 *
 * @Retention(…) — in short, it indicates how long annotation will be making impact on our code(before or after
 * compilation), in above case — RetentionPolicy.RUNTIME — it means that this annotation will be available after the
 * runtime
 **************************************************************************************************************/

@Documented
@Constraint(validatedBy = UniqueEmailValidator.class)
@Target({FIELD })
@Retention(RUNTIME)
public @interface UniqueEmail {

    String message() default "The email has already been taken.";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

}
