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
 *
 * This file is derived from the JNA Platform library project project,
 * which is licensed under LGPL 2.1 or later and Apache License 2.0.
 *
 * The original code is available at:
 * https://github.com/java-native-access/jna
 *
 * This file is derived from com.sun.jna.platform.win32.Kernel32
 * https://github.com/java-native-access/jna/blob/5.16.0/contrib/platform/src/com/sun/jna/platform/win32/Kernel32.java
 *
 * The following modifications have been made:
 * - Only the two methods, GetLastError and LocalFree are mapped in the interface
 * - The interface is package-protected, restricting its usage to this library
 *
 * The original copyright notice follows below.
 */

/* Copyright (c) 2007, 2013 Timothy Wall, Markus Karg, All Rights Reserved
 *
 * The contents of this file is dual-licensed under 2
 * alternative Open Source/Free licenses: LGPL 2.1 or later and
 * Apache License 2.0. (starting with JNA version 4.0.0).
 *
 * You can freely decide which license you want to apply to
 * the project.
 *
 * You may obtain a copy of the LGPL License at:
 *
 * http://www.gnu.org/licenses/licenses.html
 *
 * A copy is also included in the downloadable source code package
 * containing JNA, in file "LGPL2.1".
 *
 * You may obtain a copy of the Apache License at:
 *
 * http://www.apache.org/licenses/
 *
 * A copy is also included in the downloadable source code package
 * containing JNA, in file "AL2.0".
 */
package com.github.windpapi4j;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.win32.W32APIOptions;

/**
 * Interface definitions for <code>kernel32.dll</code>.
 */
interface Kernel32 extends StdCallLibrary {

    /** The instance. */
    Kernel32 INSTANCE = Native.load("kernel32", Kernel32.class, W32APIOptions.DEFAULT_OPTIONS);

    /**
     * The GetLastError function retrieves the calling thread's last-error code
     * value. The last-error code is maintained on a per-thread basis. Multiple
     * threads do not overwrite each other's last-error code.
     *
     * @return The return value is the calling thread's last-error code value.
     */
    int GetLastError();

    /**
     * Frees the specified local memory object and invalidates its handle.
     *
     * @param hMem
     *            A handle to the local memory object. If the <tt>hMem</tt> parameter
     *            is NULL, {@code LocalFree} ignores the parameter and returns NULL.
     * @return If the function succeeds, the return value is NULL. If the
     *         function fails, the return value is equal to a handle to the
     *         local memory object. To get extended error information, call
     *         {@code GetLastError}.
     * @see <A HREF="https://msdn.microsoft.com/en-us/library/windows/desktop/aa366730(v=vs.85).aspx">LocalFree</A>
     */
    Pointer LocalFree(Pointer hMem);
}
