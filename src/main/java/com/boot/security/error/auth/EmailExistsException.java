package com.boot.security.error.auth;

public final class EmailExistsException extends RuntimeException {

    private static final long serialVersionUID = 5861310537366287163L;

    public EmailExistsException() {
        super();
    }

    public EmailExistsException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public EmailExistsException(final String message) {
        super(message);
    }

    public EmailExistsException(final Throwable cause) {
        super(cause);
    }

}
