package com.mycompany.myapp.service;

/**
 * Exception thrown when a password does not meet the strength requirements.
 */
public class WeakPasswordException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Creates a new WeakPasswordException with the specified message.
     *
     * @param message the message
     */
    public WeakPasswordException(String message) {
        super(message);
    }
}
