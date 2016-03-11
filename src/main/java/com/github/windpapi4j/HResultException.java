/* Copyright (c) 2016 Peter G. Horvath, All Rights Reserved
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
 * Thrown to indicate that the JNA call to Windows DPAPI
 * was successful, however the native method itself
 * reported an error.
 *
 * @author Peter G. Horvath
 */
public class HResultException extends RuntimeException {

    /**
     * Required for serialization.
     */
    private static final long serialVersionUID = 1L;

    /**
     * Stores the HRESULT error indicator value.
     */
    private final int hResult;

    /** Constructs a new {@code HResultException} with the specified message and HResult value.
     *
     * @param message the detail message.
     * @param hresult the HRESULT value from Windows API.
     *
     */
    HResultException(String message, int hresult) {
        super(String.format("%s HRESULT=%s", message, hresult));
        this.hResult = hresult;
    }

    /**
     * Returns the Windows HRESULT value represented by this exception.
     * @return the Windows HRESULT value represented by this exception.
     */
    public final int getHResult() {
        return hResult;
    }

}
