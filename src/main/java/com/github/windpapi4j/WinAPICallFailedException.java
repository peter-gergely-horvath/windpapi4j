/* Copyright (c) 2016-2023 Peter G. Horvath, All Rights Reserved
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 */

package com.github.windpapi4j;

/**
 * Thrown to indicate that the call to Windows DPAPI has failed
 * due to an unexpected error condition.
 *
 * @author Peter G. Horvath
 */
public class WinAPICallFailedException extends Exception {

    /**
     * Required for serialization.
     */
    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new {@code WinAPICallFailedException} with the specified message and cause.
     *
     * @param message the detail message.
     * @param cause the root cause of this exception (might be {@code null})
     */
    WinAPICallFailedException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new {@code WinAPICallFailedException} with the specified message.
     *
     * @param message the detail message.
     */
    WinAPICallFailedException(String message) {
        super(message);
    }
}
