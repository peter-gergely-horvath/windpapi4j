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
 *
 *
 * Notice: The implementation is derived from the following classes
 * in the JNA Platform library, version 4.2.1, as of 2016-02-29:
 *   - com.sun.jna.platform.win32.Crypt32Util
 *   - com.sun.jna.platform.win32.WinCrypt
 *   - com.sun.jna.platform.win32.Kernel32
 *   - com.sun.jna.platform.win32.W32Errors
 *
 * The original authors of these parts are Daniel Doubrovkine
 * (dblock[at]dblock.org), Timothy Wall and Markus Karg.
 *
 * The original JNA source codes are available on GitHub:
 * https://github.com/java-native-access/jna
 *
 */
package com.github.windpapi4j;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.win32.W32APIOptions;
import java.util.Arrays;
import java.util.List;

/**
 * <p>
 * Starting from Microsoft(R) Windows(R) XP, Windows operating systems provide a
 * built-in cryptographic feature called "Windows Data Protection API" (DPAPI),
 * which allows any application to securely encrypt confidential user data using
 * the user's credentials in a way that it can only be decrypted by the same
 * user.
 * </p>
 *
 * <p>
 * This Java library exposes Windows Data Protection encryption and decryption
 * features as an easy to use Java API. Behind the scenes, JNA (Java Native
 * Access) library is used to invoke the native Windows CryptoAPI
 * {@code CryptProtectData} and {@code CryptUnprotectData} functions. Only an
 * essential subset of Windows Data Protection API (DPAPI) is supported by this
 * library: advanced cases involving showing prompts to the user etc. are not
 * implemented.
 * </p>
 *
 * <p>
 * As described in <i>Microsoft Development Network Documentation on
 * Cryptography Functions </i>, both
 * <a href="https://msdn.microsoft.com/en-us/library/windows/desktop/aa380882(v=vs.85).aspx">
 * CryptProtectData</a> and
 * <a href="https://msdn.microsoft.com/en-us/library/windows/desktop/aa380882(v=vs.85).aspx">
 * CryptUnprotectData</a> functions accept optional flag values, which control
 * their behaviour. These optional flag values are defined in
 * {@link WinDPAPI.CryptProtectFlag} as enum constants and can be passed to the
 * static factory method {@link WinDPAPI#newInstance(CryptProtectFlag...)}}
 * after which the {@code WinDPAPI} instance returned will pass them to the
 * target native Windows DPAPI method.
 * </p>
 *
 * <p>
 * The methods provided by this class call the corresponding Windows Data
 * Protection API native methods according to the following: </p>
 * <table border="1" summary="Overview of mapping between WindDPAPI and Windows CrpytoAPI methods">
 * <tr>
 * <th>
 * WinDPAPI library methods
 * </th>
 * <th>
 * Windows CryptoAPI method
 * </th>
 * </tr>
 * <tr>
 * <td>
 * <ul>
 * <li>{@link WinDPAPI#protectData(byte[])}</li>
 * <li>{@link WinDPAPI#protectData(byte[], byte[])}</li>
 * <li>{@link WinDPAPI#protectData(byte[], byte[], java.lang.String)}</li>
 * </ul>
 * </td>
 * <td> {@code CryptProtectData}
 * </td>
 * </tr>
 * <tr>
 * <td>
 * <ul>
 * <li>{@link WinDPAPI#unprotectData(byte[])}</li>
 * <li>{@link WinDPAPI#unprotectData(byte[], byte[])}</li>
 * </ul>
 * </td>
 * <td> {@code CryptUnprotectData}
 * </td>
 * </tr>
 *
 * </table>
 *
 *
 *
 *
 * <h3>Sample Code</h3>
 *
 *
 * <pre><code>
 * package test;
 *
 * import com.github.windpapi4j.WinDPAPI;
 * import com.github.windpapi4j.WinDPAPI.CryptProtectFlag;
 *
 * public class Sample {
 *
 *      public static void main(String[] args) throws Exception {
 *
 *          if(WinDPAPI.isPlatformSupported()) {
 *               WinDPAPI winDPAPI = WinDPAPI.newInstance(CryptProtectFlag.CRYPTPROTECT_UI_FORBIDDEN);
 *
 *               String message = "Hello World!";
 *               String charsetName = "UTF-8";
 *
 *               byte[] clearTextBytes = message.getBytes(charsetName);
 *
 *               byte[] cipherTextBytes = winDPAPI.protectData(clearTextBytes);
 *
 *               byte[] decryptedBytes = winDPAPI.unprotectData(cipherTextBytes);
 *
 *               String decryptedMessage = new String(decryptedBytes, charsetName);
 *
 *               if(! message.equals(decryptedMessage) ) {
 *                    throw new IllegalStateException(message + " != " + decryptedMessage); // should not happen
 *               }
 *
 *               System.out.println(decryptedMessage);
 *
 *          } else {
 *               System.err.println("ERROR: platform not supported");
 *          }
 *      }
 * }
 * </code></pre>
 *
 * @author Peter G. Horvath
 *
 * @see #isPlatformSupported()
 * @see #newInstance(CryptProtectFlag...)
 * @see #protectData(byte[])
 * @see #protectData(byte[], byte[])
 * @see #protectData(byte[], byte[], String)
 * @see #unprotectData(byte[])
 * @see #unprotectData(byte[], byte[])
 *
 */
public final class WinDPAPI {

    /**
     * Windows Crypto API JNA wrapper.
     */
    private final Crypt32 cryptoApi = Crypt32.INSTANCE;
    /**
     * Windows Kernel API JNA wrapper.
     */
    private final Kernel32 kernelApi = Kernel32.INSTANCE;

    /**
     * Retrieved from com.sun.jna.platform.win32.W32Errors, used to calculate
     * Windows HRESULT from Win32 error return code.
     */
    private static final short FACILITY_WIN32 = 7;

    /**
     * Indicates if we are being invoked on a Windows operating system, where
     * DPAPI should be present. (Not considering ancient 9x, ME and other
     * obsolete platforms)
     */
    private static final boolean IS_WINDOWS_OPERATING_SYSTEM;

    static {
        String operatingSystemName = System.getProperty("os.name");
        IS_WINDOWS_OPERATING_SYSTEM = operatingSystemName != null && operatingSystemName.startsWith("Windows");
    }

    /**
     * The numeric representation of flag values used within this
     * {@code WindDPAPI} instance.
     */
    private final int flags;

    /**
     * Constructs a new {@code WinDPAPI} with the flag values applied.
     *
     * @param flagValue the flag values to be used for the incoking
     */
    private WinDPAPI(int flagValue) {
        this.flags = flagValue;
    }

    /**
     * <p>
     * Create a new instance of the {@link WinDPAPI} class.</p>
     * <p>
     * This static method creates a new {@link WinDPAPI} instance. If there are
     * {@link CryptProtectFlag}s specified as arguments, the returned
     * {@code WinDPAPI} instance will pass the flag value to Windows Data
     * Protection API {@code CryptProtectData} and {@code CryptUnprotectData}
     * functions for both the encryption      ({@link #protectData(byte[])}), {@link #protectData(byte[], byte[])},
     * {@link #protectData(byte[], byte[], String)} and decryption      {@link #unprotectData(byte[])},
     * {@link #unprotectData(byte[], byte[])}) methods are called.</p>
     *
     *
     * <p>
     * <b>NOTE:</b>
     * <ul>
     * <li>Passing <i>any</i> flag value to this method is <b>optional</b>
     * and in most of the cases unnecessary.</li>
     * <li>Some of the available flag values control behaviour or features not
     * exposed in this library.</li>
     * </ul>
     *
     * @param cryptProtectFlags the (optional) flags to apply when Windows Data
     * Protection API methods {@code CryptProtectData} and
     * {@code CryptUnprotectData} are called
     *
     * @return a {@code WinDPAPI} instance, which (if there is any) applies the
     * passed flags to Windows Data Protection API {@code CryptProtectData} and
     * {@code CryptUnprotectData} method calls.
     *
     * @throws InitializationFailedException in case the {@code WinDPAPI} could
     * not be initialized. (for example if it is called on a non-Windows
     * platform or the loading of the JNA dispatcher fails)
     *
     * @see WinDPAPI.CryptProtectFlag
     */
    public static WinDPAPI newInstance(CryptProtectFlag... cryptProtectFlags) throws InitializationFailedException {

        try {

            if (!isPlatformSupported()) {
                throw new IllegalStateException("This library only works on Windows operating systems.");
            }

            int flagValue = 0;
            for (CryptProtectFlag cryptProtectFlag : cryptProtectFlags) {
                flagValue |= cryptProtectFlag.value;
            }

            return new WinDPAPI(flagValue);

        } catch (Throwable t) {
            throw new InitializationFailedException("Initialization failed", t);
        }
    }

    /**
     * <p>
     * Returns an indication whether the current platform supports Windows Data
     * Protection API and this library can be used or not.
     * </p>
     *
     * <p>
     * <b>NOTE:</b> end-of-life Windows platforms are not considered: as a
     * result, this method practically checks only if the current platform is
     * Windows or not.
     * </p>
     *
     * @return {@code true} if the system is supported and this class can be
     * used, {@code false} otherwise
     */
    public static boolean isPlatformSupported() {
        return IS_WINDOWS_OPERATING_SYSTEM;
    }

    /**
     * <p>
     * Possible flag values that can be passed to Windows Data Protection API
     * {@code CryptProtectData} and {@code CryptUnprotectData} methods.
     * </p>
     *
     * <p>
     * <b>NOTE:</b> Some of the available flag values control behaviour or
     * features not exposed in this library. Check <i>Microsoft Developer
     * Network</i> documentation for further reference:
     * <ul>
     * <li>
     * <a href="http://msdn.microsoft.com/en-us/library/ms995355.aspx">
     * Windows Data Protection</a>
     * </li>
     * <li>
     * <a href="https://msdn.microsoft.com/en-us/library/windows/desktop/aa380261(v=vs.85).aspx">
     * CryptProtectData function</a>
     * </li>
     * <li>
     * <a href="https://msdn.microsoft.com/en-us/library/windows/desktop/aa380882(v=vs.85).aspx">
     * CryptUnprotectData function</a>
     * </li>
     * </ul>
     */
    public enum CryptProtectFlag {
        /**
         * For remote-access situations where ui is not an option, if UI was
         * specified on protect or unprotect operation, the call will fail and
         * GetLastError() will indicate ERROR_PASSWORD_RESTRICTION.
         */
        CRYPTPROTECT_UI_FORBIDDEN(0x1),
        /**
         * Per machine protected data -- any user on machine where
         * CryptProtectData took place may CryptUnprotectData.
         */
        CRYPTPROTECT_LOCAL_MACHINE(0x4),
        /**
         * Force credential synchronize during CryptProtectData() Synchronize is
         * only operation that occurs during this operation.
         */
        CRYPTPROTECT_CRED_SYNC(0x8),
        /**
         * Generate an Audit on protect and unprotect operations.
         */
        CRYPTPROTECT_AUDIT(0x10),
        /**
         * Protect data with a non-recoverable key.
         */
        CRYPTPROTECT_NO_RECOVERY(0x20),
        /**
         * Verify the protection of a protected blob.
         */
        CRYPTPROTECT_VERIFY_PROTECTION(0x40),
        /**
         * Regenerate the local machine protection.
         */
        CRYPTPROTECT_CRED_REGENERATE(0x80);

        /**
         * The numeric representation of this flag.
         */
        private final int value;

        /**
         * Constructs a enum constant with the value associated to it.
         *
         * @param flagValue the numeric representation of this enum constant
         *
         */
        CryptProtectFlag(int flagValue) {
            this.value = flagValue;
        }
    }

    /**
     * <p>
     * Encrypts the provided data using <i>Windows Data Protection API</i>
     * {@code CryptProtectData} method.
     * </p>
     *
     * <p>
     * If any flags were specified in {@link #newInstance(CryptProtectFlag...)},
     * then they are passed to the underlying {@code CryptProtectData} method
     * call.
     * </p>
     *
     * @param data the data to encrypt (cannot be {@code null})
     * @return the encrypted data
     *
     * @throws NullPointerException if argument {@code data} is {@code null}
     * @throws WinAPICallFailedException in case the invocation of Windows DPAPI
     * {@code CryptProtectData} fails
     *
     * @see WinDPAPI#unprotectData(byte[])
     */
    public byte[] protectData(byte[] data) throws WinAPICallFailedException {
        return protectData(data, null);
    }

    /**
     * <p>
     * Encrypts the provided data using <i>Windows Data Protection API</i>
     * {@code CryptProtectData} method. The (optional) entropy parameter allows
     * an additional secret to be specified, which will be required to decrypt
     * the data.
     * </p>
     *
     * <p>
     * If any flags were specified in {@link #newInstance(CryptProtectFlag...)},
     * then they are passed to the underlying {@code CryptProtectData} method
     * call.
     * </p>
     *
     * @param data the data to encrypt (cannot be {@code null})
     * @param entropy password or other additional entropy used to encrypt the
     * data (might be {@code null})
     *
     * @return the encrypted data
     *
     * @throws WinAPICallFailedException in case the invocation of Windows DPAPI
     * {@code CryptProtectData} fails
     * @throws NullPointerException if argument {@code data} is {@code null}
     *
     * @see WinDPAPI#unprotectData(byte[], byte[])
     */
    public byte[] protectData(byte[] data, byte[] entropy) throws WinAPICallFailedException {
        return protectData(data, entropy, null);
    }

    /**
     * <p>
     * Encrypts the provided data using <i>Windows Data Protection API</i>
     * {@code CryptProtectData} method. The (optional) entropy parameter allows
     * an additional secret to be specified, which will be required to decrypt
     * the data.
     * </p>
     *
     * <p>
     * If any flags were specified in {@link #newInstance(CryptProtectFlag...)},
     * then they are passed to the underlying {@code CryptProtectData} method
     * call.
     * </p>
     *
     * @param data the data to encrypt (cannot be {@code null})
     * @param entropy password or other additional entropy used to encrypt the
     * data (might be {@code null})
     * @param description a human readable description of data to be encrypted,
     * which will be included with the encrypted data (might be {@code null})
     *
     * @return the encrypted data
     *
     * @throws WinAPICallFailedException in case the invocation of Windows DPAPI
     * {@code CryptProtectData} fails
     * @throws NullPointerException if argument {@code data} is {@code null}
     *
     * @see WinDPAPI#unprotectData(byte[], byte[])
     */
    public byte[] protectData(byte[] data, byte[] entropy, String description) throws WinAPICallFailedException {

        checkNotNull(data, "Argument data cannot be null");

        try {
            Crypt32.DATA_BLOB pDataIn = new Crypt32.DATA_BLOB(data);
            Crypt32.DATA_BLOB pDataProtected = new Crypt32.DATA_BLOB();
            //CHECKSTYLE.OFF: AvoidInlineConditionals
            Crypt32.DATA_BLOB pEntropy = (entropy == null) ? null : new Crypt32.DATA_BLOB(entropy);
            //CHECKSTYLE.ON: AvoidInlineConditionals

            try {
                final boolean apiCallSuccessful = cryptoApi.CryptProtectData(pDataIn, description,
                        pEntropy, null, null, flags, pDataProtected);

                if (!apiCallSuccessful) {
                    raiseHResultExceptionForLastError("CryptProtectData");
                }

                return pDataProtected.getData();
            } finally {
                if (pDataProtected.pbData != null) {
                    kernelApi.LocalFree(pDataProtected.pbData);
                }
            }
        } catch (Throwable t) {
            throw new WinAPICallFailedException("Invocation of CryptProtectData failed", t);
        }
    }

    /**
     * <p>
     * Decrypts the provided encrypted data and performs an integrity check
     * using
     * <i>Windows Data Protection API</i> {@code CryptUnprotectData} method.
     * </p>
     *
     * <p>
     * If any flags were specified in {@link #newInstance(CryptProtectFlag...)},
     * then they are passed to the underlying {@code CryptUnprotectData} method
     * call.
     * </p>
     *
     * @param data the data to decrypt (cannot be {@code null})
     *
     * @return the decrypted data
     *
     * @throws WinAPICallFailedException in case the invocation of Windows DPAPI
     * {@code CryptUnprotectData} fails
     * @throws NullPointerException if argument {@code data} is {@code null}
     *
     * @see WinDPAPI#protectData(byte[])
     */
    public byte[] unprotectData(byte[] data) throws WinAPICallFailedException {
        return unprotectData(data, null);
    }

    /**
     * <p>
     * Decrypts the provided encrypted data and performs an integrity check
     * using
     * <i>Windows Data Protection API</i> {@code CryptUnprotectData} method. The
     * (optional) entropy parameter is required if the data was encrypted using
     * an additional secret.
     * </p>
     *
     * <p>
     * If any flags were specified in {@link #newInstance(CryptProtectFlag...)},
     * then they are passed to the underlying {@code CryptUnprotectData} method
     * call.
     * </p>
     *
     * @param data the data to decrypt (cannot be {@code null})
     * @param entropy password or other additional entropy that was used to
     * encrypt the data (might be {@code null})
     *
     * @return the decrypted data
     *
     * @throws WinAPICallFailedException in case the invocation of Windows DPAPI
     * {@code CryptUnprotectData} fails
     * @throws NullPointerException if argument {@code data} is {@code null}
     *
     * @see WinDPAPI#protectData(byte[], byte[])
     */
    public byte[] unprotectData(byte[] data, byte[] entropy) throws WinAPICallFailedException {

        checkNotNull(data, "Argument data cannot be null");

        try {
            Crypt32.DATA_BLOB pDataIn = new Crypt32.DATA_BLOB(data);
            Crypt32.DATA_BLOB pDataUnprotected = new Crypt32.DATA_BLOB();
            //CHECKSTYLE.OFF: AvoidInlineConditionals
            Crypt32.DATA_BLOB pEntropy = (entropy == null) ? null : new Crypt32.DATA_BLOB(entropy);
            //CHECKSTYLE.ON

            PointerByReference pDescription = new PointerByReference();

            try {
                boolean apiCallSuccessful = cryptoApi.CryptUnprotectData(pDataIn, pDescription,
                        pEntropy, null, null, flags, pDataUnprotected);

                if (!apiCallSuccessful) {
                    raiseHResultExceptionForLastError("CryptUnprotectData");
                }
                return pDataUnprotected.getData();
            } finally {
                if (pDataUnprotected.pbData != null) {
                    kernelApi.LocalFree(pDataUnprotected.pbData);
                }
                if (pDescription.getValue() != null) {
                    kernelApi.LocalFree(pDescription.getValue());
                }
            }
        } catch (Throwable t) {
            throw new WinAPICallFailedException("Invocation of CryptUnprotectData failed", t);
        }

    }

    //CHECKSTYLE.OFF: JavadocMethod -- internal methods
    private void checkNotNull(Object object, String message) {
        if (object == null) {
            throw new NullPointerException(message);
        }
    }

    private void raiseHResultExceptionForLastError(String methodName) {

        final int winApiErrorCode = kernelApi.GetLastError();
        // based on com.sun.jna.platform.win32.W32Errors.HRESULT_FROM_WIN32(int) with minor changes

        //CHECKSTYLE.OFF: MagicNumber|InnerAssignment -- based on existing implementation
        final int hResult = (winApiErrorCode <= 0 ? winApiErrorCode
                : ((winApiErrorCode) & 0x0000FFFF) | ((int) FACILITY_WIN32 << 16) | 0x80000000);
        //CHECKSTYLE.ON: MagicNumber|InnerAssignment

        throw new HResultException(String.format("%s call signalled an error.", methodName), hResult);
    }
    //CHECKSTYLE.ON: JavadocMethod -- internal methods

    //CHECKSTYLE.OFF: TypeName|MethodName|VisibilityModifier|JavadocType|JavadocMethod|JavadocVariable -- JNA wrapper
    interface Kernel32 extends StdCallLibrary {

        Kernel32 INSTANCE = loadNativeLibraryJNAFacade("Kernel32", Kernel32.class);

        Pointer LocalFree(Pointer hLocal);

        int GetLastError();
    }

    interface Crypt32 extends StdCallLibrary {

        Crypt32 INSTANCE = loadNativeLibraryJNAFacade("Crypt32", Crypt32.class);

        boolean CryptProtectData(DATA_BLOB pDataIn, String szDataDescr,
                DATA_BLOB pOptionalEntropy, Pointer pvReserved,
                Pointer pPromptStruct,
                int dwFlags,
                DATA_BLOB pDataOut);

        boolean CryptUnprotectData(DATA_BLOB pDataIn, PointerByReference szDataDescr,
                DATA_BLOB pOptionalEntropy, Pointer pvReserved,
                Pointer pPromptStruct,
                int dwFlags,
                DATA_BLOB pDataOut);

        class DATA_BLOB extends Structure {

            DATA_BLOB() {
                super();
            }

            DATA_BLOB(byte[] data) {
                pbData = new Memory(data.length);
                pbData.write(0, data, 0, data.length);
                cbData = data.length;
                allocateMemory();
            }

            public int cbData;
            public Pointer pbData;

            @Override
            protected List<String> getFieldOrder() {
                return Arrays.asList("cbData", "pbData");
            }

            public byte[] getData() {
                return pbData == null ? null : pbData.getByteArray(0, cbData);
            }
        }
    }

    //CHECKSTYLE.OFF: JavadocMethod -- internal method
    @SuppressWarnings("unchecked")
    private static <T> T loadNativeLibraryJNAFacade(String name, Class<T> clazz) {
        return (T) Native.loadLibrary(name, clazz, W32APIOptions.UNICODE_OPTIONS);
    }
    //CHECKSTYLE.ON: JavadocMethod
}
