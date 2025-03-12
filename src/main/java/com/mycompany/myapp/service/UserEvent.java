package com.mycompany.myapp.service;

import com.mycompany.myapp.domain.User;

/**
 * Event class for user-related events.
 * This class is used to publish events when user-related actions occur.
 */
public class UserEvent {

    /**
     * The type of user event.
     */
    private final Type type;

    /**
     * The user associated with the event.
     */
    private final User user;

    /**
     * Types of user events.
     */
    public enum Type {
        REGISTERED,
        ACTIVATED,
        CREATED,
        UPDATED,
        DELETED,
        SUSPENDED,
        PASSWORD_CHANGED,
        PASSWORD_RESET,
        PASSWORD_RESET_REQUESTED,
        LOGIN_ATTEMPT_FAILED,
        LOGIN_SUCCESS
    }

    /**
     * Creates a new UserEvent.
     *
     * @param type the event type
     * @param user the user associated with the event
     */
    public UserEvent(Type type, User user) {
        this.type = type;
        this.user = user;
    }

    /**
     * Gets the event type.
     *
     * @return the event type
     */
    public Type getType() {
        return type;
    }

    /**
     * Gets the user associated with the event.
     *
     * @return the user
     */
    public User getUser() {
        return user;
    }
}
