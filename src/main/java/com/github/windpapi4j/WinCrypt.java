/* Copyright (c) 2016-2025 Peter G. Horvath, All Rights Reserved
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
 * This file is derived from com.sun.jna.platform.win32.WinCrypt
 * https://github.com/java-native-access/jna/blob/5.16.0/contrib/platform/src/com/sun/jna/platform/win32/WinCrypt.java
 *
 * The following modifications have been made:
 * - The only structure described is DATA_BLOB
 * - The interface is package-protected, restricting its usage to this library
 *
 * The original copyright notice follows below.
 */

/* Copyright (c) 2010 Daniel Doubrovkine, All Rights Reserved
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

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.Structure.FieldOrder;

/**
 * Ported from WinCrypt.h.
 * Microsoft Windows SDK 6.0A.
 * @author dblock[at]dblock.org
 */
interface WinCrypt {

    /**
     * The CryptoAPI CRYPTOAPI_BLOB structure is used for an arbitrary array of bytes.
     */
    @FieldOrder({"cbData", "pbData"})
    class DATA_BLOB extends Structure {

        /**
         * The count of bytes in the buffer pointed to by pbData.
         */
        public int cbData;
        /**
         * A pointer to a block of data bytes.
         */
        public Pointer pbData;

        public DATA_BLOB() {
            super();
        }

        public DATA_BLOB(Pointer memory) {
            super(memory);
            read();
        }

        public DATA_BLOB(byte [] data) {
            super();
            if (data.length > 0) {
                pbData = new Memory(data.length);
                pbData.write(0, data, 0, data.length);
                cbData = data.length;
            } else {
                // We allocate 1 byte memory region because `malloc` may return `NULL` if requested size is 0.
                // However, `CryptProtectData` and `CryptUnprotectData` consider `NULL` as invalid data.
                // The fact that we allocate 1 byte does not affect the final result because
                // we pass the correct size explicitly on `cbData` field.
                pbData = new Memory(1);
                cbData = 0;
            }
        }

        public DATA_BLOB(String s) {
            this(Native.toByteArray(s));
        }

        /**
         * Get byte data.
         * @return
         *  Byte data or null.
         */
        public byte[] getData() {
            return pbData == null ? null : pbData.getByteArray(0, cbData);
        }
    }

}
