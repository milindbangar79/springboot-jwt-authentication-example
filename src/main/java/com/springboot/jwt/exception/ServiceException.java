package com.springboot.jwt.exception;

public class ServiceException extends Exception {

    private static final long serialVersionUID = 1L;

    public ServiceException() {
        super();
    }

    /**
     * @param e
     *
     */

    public ServiceException(Exception e) {
        super(e);
    }

    /**
     *
     * @param message
     *
     */
    public ServiceException(String message) {
        super(message);
    }

    /**
     *
     * @param cause
     */

    public ServiceException(Throwable cause){
        super(cause);
    }

    /**
     *
     * @param message
     * @param cause
     * @param enableSuppression
     * @param writableStackTrace
     */
    public ServiceException(String message,Throwable cause, boolean enableSuppression, boolean writableStackTrace){
        super(message,cause,enableSuppression,writableStackTrace);
    }


    /**
     *
     * @param message
     * @param cause
     */
    public ServiceException(String message, Throwable cause){
        super(message,cause);
    }

}
