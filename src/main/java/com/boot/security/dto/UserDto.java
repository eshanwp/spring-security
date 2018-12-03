package com.boot.security.dto;

import com.boot.security.validation.PasswordMatches;
import com.boot.security.validation.UniqueEmail;
import com.boot.security.validation.ValidEmail;
import com.boot.security.validation.ValidPassword;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.io.Serializable;

@PasswordMatches
public class UserDto implements Serializable {

    @NotNull
    @NotEmpty
    @Size(min=2, message="first name should have at least 2 characters")
    @Pattern(regexp = "^[A-Za-z0-9]*$", message = "The first name format is invalid.")
    private String firstName;

    @NotNull
    @NotEmpty
    private String lastName;

    @NotNull
    @NotEmpty
    @ValidEmail
//    @UniqueEmail
    private String email;

    @NotNull
    @NotEmpty
    @ValidPassword
    private String password;
    private String matchingPassword;

//    @NotNull
    private String isUsing2FA;

    private boolean brr;

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getMatchingPassword() {
        return matchingPassword;
    }

    public void setMatchingPassword(String matchingPassword) {
        this.matchingPassword = matchingPassword;
    }

    public String getIsUsing2FA() {
        return isUsing2FA;
    }

    public void setIsUsing2FA(String isUsing2FA) {
        this.isUsing2FA = isUsing2FA;
    }

    public boolean isBrr() {
        return brr;
    }

    public void setBrr(boolean brr) {
        this.brr = brr;
    }

    @Override
    public String toString() {
        return "UserDto{" +
                "firstName='" + firstName + '\'' +
                ", lastName='" + lastName + '\'' +
                ", email='" + email + '\'' +
                ", password='" + password + '\'' +
                ", matchingPassword='" + matchingPassword + '\'' +
                ", brr=" + brr +
                '}';
    }
}
