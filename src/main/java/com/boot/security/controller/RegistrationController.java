package com.boot.security.controller;

import com.boot.security.auth.event.OnRegistrationCompleteEvent;
import com.boot.security.auth.service.implementation.ISecurityUserService;
import com.boot.security.dto.PasswordDto;
import com.boot.security.dto.UserDto;
import com.boot.security.entity.User;
import com.boot.security.entity.VerificationToken;
import com.boot.security.error.auth.InvalidOldPasswordException;
import com.boot.security.error.auth.UserNotFoundException;
import com.boot.security.service.implementation.IUserService;
import com.boot.security.util.GenericResponse;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.MessageSource;
import org.springframework.core.env.Environment;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.util.Calendar;
import java.util.Locale;
import java.util.UUID;

@RestController
@RequestMapping("/api")
public class RegistrationController {

    // Define the log object for this class
    private final Logger log = Logger.getLogger(this.getClass());

    @Autowired
    private ISecurityUserService securityUserService;

    @Autowired
    private IUserService userService;

    @Autowired
    ApplicationEventPublisher eventPublisher;

    @Autowired
    private IUserService service;

    @Autowired
    private MessageSource messages;

    @Autowired
    private JavaMailSender mailSender;

    @Autowired
    private Environment env;

    @Autowired
    private AuthenticationManager authenticationManager;


    private String getAppUrl(HttpServletRequest request) {
        return "http://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath();
    }

    //A Sign-Up link on the login page will take the user to the registration page.
    @GetMapping(value = "/user/registration")
    public String showRegistrationForm(){
        return null;
    }

    //Using a Spring Event to Create the Token and Send the Verification Email and save data
    @PostMapping(value = "/user/registration")
    public GenericResponse register(@Valid @RequestBody UserDto userDto, final HttpServletRequest request){
        System.out.println(userDto.toString());
        log.debug("Registering user account with information: "+userDto.toString());

        User user =  userService.registerNewUserAccount(userDto);

        try {

            String appUrl = getAppUrl(request);

            eventPublisher.publishEvent(new OnRegistrationCompleteEvent
                    (user, request.getLocale(), appUrl));

        }catch (Exception e){
            e.printStackTrace();
        }
        return new GenericResponse("User has been successfully created");
    }

    /*****************************************************************************************************
     *
     * The user will be redirected to an error page with the corresponding message if:
     * 1. The VerificationToken does not exist, for some reason or
     * 2. The VerificationToken has expired
     *
     * There are two opportunities for improvement in handling the VerificationToken checking and expiration scenarios:
     * We can use a Cron Job to check for token expiration in the background
     * We can give the user the opportunity to get a new token once it has expired
     *
     * The confirmRegistration controller will extract the value of the token parameter in the resulting GET
     * request and will use it to enable the User.
     *
     * ***************************************************************************************************/

    @GetMapping(value = "/user/registration-confirm")
    public String confirmRegistration
            (final HttpServletRequest request, @RequestParam("token") String token, Model model) {

        Locale locale = request.getLocale();

        VerificationToken verificationToken = service.getVerificationToken(token);
        if (verificationToken == null) {
            String message = messages.getMessage("auth.message.invalidToken", null, locale);
            return message;
//            model.addAttribute("message", message);
//            return "redirect:/badUser.html?lang=" + locale.getLanguage();
        }

        User user = verificationToken.getUser();
        Calendar cal = Calendar.getInstance();
        if ((verificationToken.getExpiryDate().getTime() - cal.getTime().getTime()) <= 0) {
            String messageValue = messages.getMessage("auth.message.expired", null, locale);
            model.addAttribute("expired", true);
            model.addAttribute("token", token);
            return messageValue;
//            model.addAttribute("message", messageValue);
//            return "redirect:/badUser.html?lang=" + locale.getLanguage();
        }

        //If no errors are found, the user is enabled.
        user.setEnabled(true);
        service.saveRegisteredUser(user);
        model.addAttribute("message", messages.getMessage("message.accountVerified", null, locale));
        return "login.page";
//        return "redirect:/login.html?lang=" + request.getLocale().getLanguage();

    }

    //we’ll reset the existing token with a new expireDate. The, we’ll send the user a new email,
    //with the new link/token
    @GetMapping(value = "/user/resend-registration-token")
    public GenericResponse resendRegistrationToken(
            HttpServletRequest request, @RequestParam("token") String existingVerificationToken) {
        VerificationToken newToken = userService.generateNewVerificationToken(existingVerificationToken);

        User user = userService.getUser(newToken.getToken());

        String appUrl = getAppUrl(request);

        SimpleMailMessage email =
                constructResendVerificationTokenEmail(appUrl, request.getLocale(), newToken, user);
        mailSender.send(email);

        return new GenericResponse(
                messages.getMessage("message.resendToken", null, request.getLocale()));
    }

    //we’ll reset the password with a new token. The, we’ll send the user a new email, with the new link/token
    @GetMapping(value = "/user/reset-password")
    public GenericResponse resetPassword(HttpServletRequest request,
                                         @RequestParam("email") String userEmail) {

        User user = userService.findUserByEmail(userEmail);

        if (user == null) {
            throw new UserNotFoundException();
        }
        String token = UUID.randomUUID().toString();
        userService.createPasswordResetTokenForUser(user, token);
        mailSender.send(constructResetTokenEmail(getAppUrl(request),
                request.getLocale(), token, user));
        return new GenericResponse(
                messages.getMessage("message.resetPasswordEmail", null,
                        request.getLocale()));
    }

    @GetMapping(value = "/user/change-password")
    public String showChangePasswordPage(
            Locale locale, Model model,
            @RequestParam("id") long id,
            @RequestParam("token") String token
    ) {
        String result = securityUserService.validatePasswordResetToken(id, token);
        if (result != null) {
            model.addAttribute("message",
                    messages.getMessage("auth.message." + result, null, locale));

            return "redirect to login page";

//            return "redirect:/login?lang=" + locale.getLanguage();
        }
        //At this point, the user sees the simple Password Reset page – where the only
        //possible option is to provide a new password
        return "redirect to change password page";
    }

    //Save User Password
    @PostMapping(value = "/user/save-password")
    public GenericResponse savePassword(
            Locale locale,
            @Valid @RequestBody PasswordDto passwordDto) {

        final User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        userService.changeUserPassword(user, passwordDto.getNewPassword());
        return new GenericResponse(messages.getMessage("message.resetPasswordSuc", null, locale));
    }

    //Notice how the method is secured via the @PreAuthorize annotation, since it should only accessible to
    //logged in users.
    @GetMapping(value = "/user/update-password")
    public GenericResponse changeUserPassword(
            Locale locale,
            @RequestParam("password") String password,
            @RequestParam("oldpassword") String oldPassword
    ) {
        System.out.println(">>password"+password);
        System.out.println(">>oldpassword"+oldPassword);
        System.out.println(">>>> "+SecurityContextHolder.getContext().getAuthentication().getPrincipal());

        final User user = userService.findUserByEmail(((User) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getEmail());
        System.out.println(">>USer"+user.toString());

        if (!userService.checkIfValidOldPassword(user, oldPassword)) {
            throw new InvalidOldPasswordException();
        }
        userService.changeUserPassword(user, password);
        return new GenericResponse(messages.getMessage("message.updatePasswordSuc", null, locale));
    }

    @RequestMapping(value = "/user/update/2fa", method = RequestMethod.POST)
    @ResponseBody
    public GenericResponse modifyUser2FA(@RequestParam("use2FA") final boolean use2FA) throws UnsupportedEncodingException {
        final User user = userService.updateUser2FA(use2FA);
        if (use2FA) {
            return new GenericResponse(userService.generateQRUrl(user));
        }
        return null;
    }

    /**************************************************************
     * NON - API
     **************************************************************/

    private SimpleMailMessage constructResendVerificationTokenEmail
    (String contextPath, Locale locale, VerificationToken newToken, User user) {
        String confirmationUrl =
                contextPath + "/regitrationConfirm.html?token=" + newToken.getToken();
        String message = messages.getMessage("message.resendToken", null, locale);
        SimpleMailMessage email = new SimpleMailMessage();
        email.setSubject("Resend Registration Token");
        email.setText(message + " rn" + confirmationUrl);
        email.setFrom(env.getProperty("support.email"));
        email.setTo(user.getEmail());
        return email;
    }

    //used to send an email with the reset token
    private SimpleMailMessage constructResetTokenEmail(
            String contextPath, Locale locale, String token, User user) {
        String url = contextPath + "/user/change-password?id=" +
                user.getId() + "&token=" + token;
        String message = messages.getMessage("message.resetPassword",
                null, locale);
        return constructEmail("Reset Password", message + " \r\n" + url, user);
    }

    private SimpleMailMessage constructEmail(String subject, String body,
                                             User user) {
        SimpleMailMessage email = new SimpleMailMessage();
        email.setSubject(subject);
        email.setText(body);
        email.setTo(user.getEmail());
        email.setFrom(env.getProperty("support.email"));
        return email;
    }
}
