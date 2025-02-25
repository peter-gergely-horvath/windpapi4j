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
public class HResultException extends WinAPICallFailedException {

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
     * Constructs a new {@code HResultException} with no message and {@code 0} as its {@code hResult} value.
     *
     */
    public HResultException() {
        super();
        this.hResult = 0;
    }

    /**
     * Constructs a new {@code HResultException} with the specified methodId and HResult value.
     *
     * @param methodId human-readable identifier of the method that failed.
     * @param hResult the HRESULT value from Windows API.
     */
    HResultException(String methodId, int hResult) {
        super(String.format("%s failed with HRESULT=0x%08x", methodId, hResult));
        this.hResult = hResult;
    }

    /**
     * Creates a new {@code HResultException} with the specified methodId and last-error code value.
     *
     * @param methodId human-readable identifier of the method that failed.
     * @param lastErrorCode last-error code from Windows API.
     *
     * @return a new {@code HResultException} with the specified methodId and last-error code value.
     */
    static HResultException forLastErrorCode(String methodId, int lastErrorCode) {
        return new HResultException(methodId, convertLastErrorCodeToHResult(lastErrorCode));
    }

    private static int convertLastErrorCodeToHResult(int lastErrorCode) {
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
    public final int getHResult() {
        return hResult;
    }

}
