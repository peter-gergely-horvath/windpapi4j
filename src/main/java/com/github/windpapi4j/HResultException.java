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
 * Thrown to indicate that the JNA call to Windows DPAPI
 * was successful, however the native method itself
 * reported an error.
 *
 * @author Peter G. Horvath
 */
public class HResultException extends RuntimeException {

    /**
     * Retrieved from com.sun.jna.platform.win32.W32Errors, used to
     * calculate Windows HRESULT from Win32 error return code.
     */
    private static final short FACILITY_WIN32 = 7;


    /**
     * Required for serialization.
     */
    private static final long serialVersionUID = 1L;

    /**
     * Stores the HRESULT error indicator value.
     */
    private final int hResult;

    /**
     * Constructs a new {@code HResultException} with the specified message and HResult value.
     *
     * @param message the detail message.
     * @param hResult the HRESULT value from Windows API.
     */
    HResultException(String message, int hResult) {
        super(String.format("%s HRESULT=%s", message, hResult));
        this.hResult = hResult;
    }

    /**
     * Constructs a new {@code HResultException} with the specified HResult value.
     *
     * @param hResult the HRESULT value from Windows API.
     */
    HResultException(int hResult) {
        super(String.format("HRESULT=%s", hResult));
        this.hResult = hResult;
    }

    public static HResultException forLastErrorCode(int lastErrorCode) {
        return new HResultException(convertToHResult(lastErrorCode));
    }

    public static HResultException forLastErrorCode(String message, int lastErrorCode) {
        return new HResultException(message, convertToHResult(lastErrorCode));
    }

    private static int convertToHResult(int lastErrorCode) {
        //CHECKSTYLE.OFF: MagicNumber|InnerAssignment -- based on existing implementation
        return (lastErrorCode <= 0 ? lastErrorCode
                : (lastErrorCode & 0x0000FFFF) | ((int) FACILITY_WIN32 << 16) | 0x80000000);
        //CHECKSTYLE.ON: MagicNumber|InnerAssignment
    }

    /**
     * Returns the Windows HRESULT value represented by this exception.
     *
     * @return the Windows HRESULT value represented by this exception.
     */
    public final int convertToHResult() {
        return hResult;
    }

}
