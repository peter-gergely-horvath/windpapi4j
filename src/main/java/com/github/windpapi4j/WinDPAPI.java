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
 * This file contains code derived from the JNA Platform library
 * class com.sun.jna.platform.win32.Crypt32Util:
 * https://github.com/java-native-access/jna/blob/5.16.0/contrib/platform/src/com/sun/jna/platform/win32/Crypt32Util.java
 *
 */

package com.github.windpapi4j;

import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.Objects;

/**
 * <p>
 * Starting from Microsoft(R) Windows(R) 2000, Windows operating systems provide
 * a built-in cryptographic feature called "Windows Data Protection API" (DPAPI),
 * which allows any application to securely encrypt confidential user data using
 * the user's credentials in a way that it can only be decrypted by the same user.
 * </p>
 *
 * <p>
 * This Java library exposes Windows Data Protection encryption and decryption
 * features as an easy to use Java API. Behind the scenes, JNA (Java Native
 * Access) library is used to invoke the native  Windows CryptoAPI
 * {@code CryptProtectData} and {@code CryptUnprotectData} functions. Only an
 * essential subset of Windows Data Protection API (DPAPI) is supported by this
 * library: advanced cases involving showing prompts to the user etc. are not
 * implemented.
 * </p>
 *
 * <p>
 * As described in <i>Microsoft Development Network Documentation on Cryptography
 * Functions </i>, both
 * <a href="https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata">
 * CryptProtectData</a> and
 * <a href="https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata">
 * CryptUnprotectData</a> functions accept optional flag values, which control their behaviour.
 * These optional flag values are defined in
 * {@link WinDPAPI.CryptProtectFlag} as enum constants
 * and can be passed to the static factory method {@link WinDPAPI#newInstance(CryptProtectFlag...)}}
 * after which the {@code WinDPAPI} instance returned will pass them to the target native
 * Windows DPAPI method.
 * </p>
 *
 * <p>
 * The methods provided by this class call the corresponding Windows Data Protection API
 * native methods according to the following: </p>
 * <table border="1">
 *     <caption>Overview of mapping between WindDPAPI and Windows CrpytoAPI methods</caption>
 *     <tr>
 *         <th>
 *             WinDPAPI library methods
 *         </th>
 *         <th>
 *             Windows CryptoAPI method
 *         </th>
 *     </tr>
 *     <tr>
 *         <td>
 *             <ul>
 *                 <li>{@link WinDPAPI#protectData(byte[])}</li>
 *                 <li>{@link WinDPAPI#protectData(byte[], byte[])}</li>
 *                 <li>{@link WinDPAPI#protectData(byte[], byte[], java.lang.String)}</li>
 *             </ul>
 *         </td>
 *         <td>
 *             {@code CryptProtectData}
 *         </td>
 *     </tr>
 *     <tr>
 *         <td>
 *             <ul>
 *                 <li>{@link WinDPAPI#unprotectData(byte[])}</li>
 *                 <li>{@link WinDPAPI#unprotectData(byte[], byte[])}</li>
 *             </ul>
 *         </td>
 *         <td>
 *             {@code CryptUnprotectData}
 *         </td>
 *     </tr>
 * </table>
 *
 *
 *
 *
 * <h2>Sample Code</h2>
 *
 *
 * <pre><code>
 * package sample;
 *
 * import com.github.windpapi4j.WinDPAPI;
 * import com.github.windpapi4j.WinDPAPI.CryptProtectFlag;
 *
 * import java.nio.charset.StandardCharsets;
 *
 * public class Sample {
 *
 *     public static void main(String[] args) throws Exception {
 *
 *         if(WinDPAPI.isPlatformSupported()) {
 *             WinDPAPI winDPAPI = WinDPAPI.newInstance(CryptProtectFlag.CRYPTPROTECT_UI_FORBIDDEN);
 *
 *             String message = "Hello World!";
 *
 *             byte[] clearTextBytes = message.getBytes(StandardCharsets.UTF_8);
 *
 *             byte[] cipherTextBytes = winDPAPI.protectData(clearTextBytes);
 *
 *             byte[] decryptedBytes = winDPAPI.unprotectData(cipherTextBytes);
 *
 *             String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);
 *
 *             if(! message.equals(decryptedMessage) ) {
 *                 throw new IllegalStateException(message + " != " + decryptedMessage); // should not happen
 *             }
 *
 *             System.out.println(decryptedMessage);
 *
 *         } else {
 *             System.err.println("ERROR: platform not supported");
 *         }
 *     }
 * }
 * </code></pre>
 *
 * @author Peter G. Horvath
 * @see #isPlatformSupported()
 * @see #newInstance(CryptProtectFlag...)
 * @see #protectData(byte[])
 * @see #protectData(byte[], byte[])
 * @see #protectData(byte[], byte[], String)
 * @see #unprotectData(byte[])
 * @see #unprotectData(byte[], byte[])
 */
public final class WinDPAPI {

    /**
     * Indicates if we are being invoked on a Windows operating
     * system, where DPAPI should be present. (Not considering
     * ancient 9x, ME and other obsolete platforms)
     */
    private static final boolean IS_WINDOWS_OPERATING_SYSTEM;

    static {
        String operatingSystemName = System.getProperty("os.name");
        IS_WINDOWS_OPERATING_SYSTEM = operatingSystemName != null && operatingSystemName.startsWith("Windows");
    }

    /**
     * The numeric representation of flag values used within this {@code WindDPAPI} instance.
     */
    private final int flags;
    private final Crypt32 crypt32Api;
    private final Kernel32 kernel32Api;

    /**
     * Constructs a new {@code WinDPAPI} with the flag values applied.
     *
     * @param flagValue the flag values to be used for the invocations
     */
    private WinDPAPI(int flagValue) {
        // passing those singleton instances here causes their initialisation:
        // if they cannot be created, we fail fast, without creating an apparently
        // operational WinDPAPI instance.

        this(flagValue, Crypt32.INSTANCE, Kernel32.INSTANCE);
    }

    /**
     * Constructs a new {@code WinDPAPI} with the flag values applied.
     *
     * @param flagValue   the flag values to be used for the invocations
     * @param crypt32Api  the {@link Crypt32} API instance
     * @param kernel32Api the {@link Kernel32} API instance
     */
    private WinDPAPI(int flagValue, Crypt32 crypt32Api, Kernel32 kernel32Api) {
        // While currently private, it could be made package-protected
        // so that these API interfaces can be injeced from test cases, too
        this.flags = flagValue;
        this.crypt32Api = crypt32Api;
        this.kernel32Api = kernel32Api;
    }

    /**
     * <p>
     * Create a new instance of the {@link WinDPAPI} class.</p>
     * <p>
     * This static method creates a new {@link WinDPAPI} instance.
     * If there are {@link CryptProtectFlag}s specified as arguments, the
     * returned {@code WinDPAPI} instance will pass the flag value
     * to Windows Data Protection API {@code CryptProtectData}
     * and {@code CryptUnprotectData} functions for both the encryption
     * ({@link #protectData(byte[])}), {@link #protectData(byte[], byte[])},
     * {@link #protectData(byte[], byte[], String)} and decryption
     * {@link #unprotectData(byte[])},
     * {@link #unprotectData(byte[], byte[])}) methods are called.</p>
     *
     *
     * <p>
     * <b>NOTE:</b>
     * <ul>
     *     <li>Passing <i>any</i> flag value to this method is <b>optional</b>
     *          and in most of the cases  unnecessary.</li>
     *     <li>Some of the available flag values control behaviour or features not exposed in this library.</li>
     * </ul>
     *
     * @param cryptProtectFlags the (optional) flags to apply when Windows Data Protection API methods
     *                          {@code CryptProtectData} and {@code CryptUnprotectData} are called
     * @return a {@code WinDPAPI} instance, which (if there is any) applies the passed flags to
     * Windows Data Protection API {@code CryptProtectData} and {@code CryptUnprotectData} method calls.
     * @throws InitializationFailedException in case the {@code WinDPAPI} could not be initialized.
     *                                       (for example if it is called on a non-Windows platform or
     *                                       the loading of the JNA dispatcher fails)
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
            // This catches UnsatisfiedLinkError too, which can be thrown if the
            // JNA dispatcher is not there or fails to load the native libraries
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
     * <b>NOTE:</b> end-of-life Windows platforms are not considered: as a result,
     * this method practically checks only if the current platform is Windows or not.
     * </p>
     *
     * @return {@code true} if the system is supported and this class can be used, {@code false} otherwise
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
     * features not exposed in this library.
     * Check <i>Microsoft Developer Network</i> documentation for further reference:
     * <ul>
     *   <li>
     *      <a href="http://msdn.microsoft.com/en-us/library/ms995355.aspx">
     *          Windows Data Protection</a>
     *   </li>
     *   <li>
     *      <a href="https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata">
     *          CryptProtectData function</a>
     *   </li>
     *   <li>
     *      <a href="https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata">
     *          CryptUnprotectData function</a>
     *   </li>
     * </ul>
     */
    public enum CryptProtectFlag {
        /**
         * For remote-access situations where ui is not an option, if UI was specified
         * on protect or unprotect operation, the call will fail and GetLastError() will
         * indicate ERROR_PASSWORD_RESTRICTION.
         */
        CRYPTPROTECT_UI_FORBIDDEN(0x1),
        /**
         * Per machine protected data -- any user on machine where CryptProtectData
         * took place may CryptUnprotectData.
         */
        CRYPTPROTECT_LOCAL_MACHINE(0x4),
        /**
         * Force credential synchronize during CryptProtectData()
         * Synchronize is only operation that occurs during this operation.
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
         * Constructs an enum constant with the value associated to it.
         *
         * @param flagValue the numeric representation of this enum constant
         */
        CryptProtectFlag(int flagValue) {
            this.value = flagValue;
        }
    }


    /**
     * <p>
     * Encrypts the provided data using <i>Windows Data Protection API</i> {@code CryptProtectData} method.
     * </p>
     *
     * <p>
     * If any flags were specified in {@link #newInstance(CryptProtectFlag...)}, then they are passed to
     * the underlying {@code CryptProtectData} method call.
     * </p>
     *
     * @param data the data to encrypt (cannot be {@code null})
     * @return the encrypted data
     * @throws NullPointerException      if argument {@code data} is {@code null}
     * @throws HResultException          in case the invocation of Windows DPAPI {@code CryptProtectData} fails
     *                                   and a HRESULT error code was available
     * @throws WinAPICallFailedException in case the invocation of Windows DPAPI {@code CryptProtectData} fails
     * @see WinDPAPI#unprotectData(byte[])
     */
    public byte[] protectData(byte[] data)
            throws HResultException, WinAPICallFailedException {

        return protectData(data, null);
    }


    /**
     * <p>
     * Encrypts the provided data using <i>Windows Data Protection API</i> {@code CryptProtectData} method.
     * The (optional) entropy parameter allows an additional secret to be specified, which will be required
     * to decrypt the data.
     * </p>
     *
     * <p>
     * If any flags were specified in {@link #newInstance(CryptProtectFlag...)}, then they are passed to
     * the underlying {@code CryptProtectData} method call.
     * </p>
     *
     * @param data    the data to encrypt (cannot be {@code null})
     * @param entropy password or other additional entropy used to encrypt the data (might be {@code null})
     * @return the encrypted data
     * @throws NullPointerException      if argument {@code data} is {@code null}
     * @throws HResultException          in case the invocation of Windows DPAPI {@code CryptProtectData} fails
     *                                   and a HRESULT error code was available
     * @throws WinAPICallFailedException in case the invocation of Windows DPAPI {@code CryptProtectData} fails
     * @see WinDPAPI#unprotectData(byte[], byte[])
     */
    public byte[] protectData(byte[] data, byte[] entropy)
            throws HResultException, WinAPICallFailedException {

        return protectData(data, entropy, null);
    }

    /**
     * <p>
     * Encrypts the provided data using <i>Windows Data Protection API</i> {@code CryptProtectData} method.
     * The (optional) entropy parameter allows an additional secret to be specified, which will be required
     * to decrypt the data.
     * </p>
     *
     * <p>
     * If any flags were specified in {@link #newInstance(CryptProtectFlag...)}, then they are passed to
     * the underlying {@code CryptProtectData} method call.
     * </p>
     *
     * @param data        the data to encrypt (cannot be {@code null})
     * @param entropy     password or other additional entropy used to encrypt the data (might be {@code null})
     * @param description a human-readable description of data to be encrypted,
     *                    which will be included with the encrypted data (might be {@code null})
     * @return the encrypted data
     * @throws NullPointerException      if argument {@code data} is {@code null}
     * @throws HResultException          in case the invocation of Windows DPAPI {@code CryptProtectData} fails
     *                                   and a HRESULT error code was available
     * @throws WinAPICallFailedException in case the invocation of Windows DPAPI {@code CryptProtectData} fails
     * @see WinDPAPI#unprotectData(byte[], byte[])
     */
    public byte[] protectData(byte[] data, byte[] entropy, String description)
            throws HResultException, WinAPICallFailedException {

        Objects.requireNonNull((Object) data, "Argument data cannot be null");

        try {
            return doProtectData(data, entropy, description);

        } catch (HResultException hResultException) {
            throw hResultException;

        } catch (Throwable throwable) {
            throw new WinAPICallFailedException("Invocation of CryptProtectData failed", throwable);
        }
    }

    private byte[] doProtectData(byte[] data, byte[] entropy, String description) throws HResultException {

        WinCrypt.DATA_BLOB pDataIn = new WinCrypt.DATA_BLOB(data);
        WinCrypt.DATA_BLOB pDataProtected = new WinCrypt.DATA_BLOB();
        WinCrypt.DATA_BLOB pEntropy = (entropy == null) ? null : new WinCrypt.DATA_BLOB(entropy);
        HResultException err = null;
        byte[] protectedData = null;
        try {
            boolean apiCallSuccessful = crypt32Api.CryptProtectData(pDataIn, description,
                    pEntropy, null, null, flags, pDataProtected);

            if (!apiCallSuccessful) {

                err = HResultException.forLastErrorCode(
                        "Crypt32.CryptProtectData", kernel32Api.GetLastError());
            } else {
                protectedData = pDataProtected.getData();
            }
        } finally {
            if (pDataIn.pbData != null) {
                pDataIn.pbData.clear(pDataIn.cbData);
            }
            if (pEntropy != null && pEntropy.pbData != null) {
                pEntropy.pbData.clear(pEntropy.cbData);
            }
            if (pDataProtected.pbData != null) {
                pDataProtected.pbData.clear(pDataProtected.cbData);
                try {
                    freeLocalMemory(pDataProtected.pbData);
                } catch (HResultException e) {
                    if (err == null) {
                        err = e;
                    } else {
                        err.addSuppressed(e);
                    }
                }
            }
        }

        if (err != null) {
            if (protectedData != null) {
                Arrays.fill(protectedData, (byte) 0);
            }
            throw err;
        }

        return protectedData;
    }

    /**
     * <p>
     * Decrypts the provided encrypted data and performs an integrity check using
     * <i>Windows Data Protection API</i> {@code CryptUnprotectData} method.
     * </p>
     *
     * <p>
     * If any flags were specified in {@link #newInstance(CryptProtectFlag...)}, then they are passed to
     * the underlying {@code CryptUnprotectData} method call.
     * </p>
     *
     * @param data the data to decrypt (cannot be {@code null})
     * @return the decrypted data
     * @throws HResultException          in case the invocation of Windows DPAPI {@code CryptUnprotectData} fails
     *                                   and a HRESULT error code was available
     * @throws WinAPICallFailedException in case the invocation of Windows DPAPI {@code CryptUnprotectData} fails
     * @throws NullPointerException      if argument {@code data} is {@code null}
     * @see WinDPAPI#protectData(byte[])
     */
    public byte[] unprotectData(byte[] data)
            throws HResultException, WinAPICallFailedException {

        return unprotectData(data, null);
    }

    /**
     * <p>
     * Decrypts the provided encrypted data and performs an integrity check using
     * <i>Windows Data Protection API</i> {@code CryptUnprotectData} method.
     * The (optional) entropy parameter is required if the data was encrypted
     * using an additional secret.
     * </p>
     *
     * <p>
     * If any flags were specified in {@link #newInstance(CryptProtectFlag...)}, then they are passed to
     * the underlying {@code CryptUnprotectData} method call.
     * </p>
     *
     * @param data    the data to decrypt (cannot be {@code null})
     * @param entropy password or other additional entropy that was used to encrypt the data (might be {@code null})
     * @return the decrypted data
     * @throws HResultException          in case the invocation of Windows DPAPI {@code CryptUnprotectData} fails
     *                                   and a HRESULT error code was available
     * @throws WinAPICallFailedException in case the invocation of Windows DPAPI {@code CryptUnprotectData} fails
     * @throws NullPointerException      if argument {@code data} is {@code null}
     * @see WinDPAPI#protectData(byte[], byte[])
     */
    public byte[] unprotectData(byte[] data, byte[] entropy)
            throws HResultException, WinAPICallFailedException {

        Objects.requireNonNull((Object) data, "Argument data cannot be null");

        try {
            return doUnprotectData(data, entropy);

        } catch (HResultException hResultException) {
            throw hResultException;

        } catch (Throwable throwable) {
            throw new WinAPICallFailedException("Invocation of CryptUnprotectData failed", throwable);
        }

    }

    private byte[] doUnprotectData(byte[] data, byte[] entropy) throws HResultException {
        WinCrypt.DATA_BLOB pDataIn = new WinCrypt.DATA_BLOB(data);
        WinCrypt.DATA_BLOB pDataUnprotected = new WinCrypt.DATA_BLOB();
        WinCrypt.DATA_BLOB pEntropy = (entropy == null) ? null : new WinCrypt.DATA_BLOB(entropy);
        HResultException err = null;
        byte[] unProtectedData = null;
        try {
            boolean apiCallSuccessful = Crypt32.INSTANCE.CryptUnprotectData(pDataIn, null,
                    pEntropy, null, null, flags, pDataUnprotected);

            if (!apiCallSuccessful) {
                err = HResultException.forLastErrorCode(
                        "Crypt32.CryptUnprotectData", Kernel32.INSTANCE.GetLastError());
            } else {
                unProtectedData = pDataUnprotected.getData();
            }
        } finally {
            if (pDataIn.pbData != null) {
                pDataIn.pbData.clear(pDataIn.cbData);
            }
            if (pEntropy != null && pEntropy.pbData != null) {
                pEntropy.pbData.clear(pEntropy.cbData);
            }
            if (pDataUnprotected.pbData != null) {
                pDataUnprotected.pbData.clear(pDataUnprotected.cbData);
                try {
                    freeLocalMemory(pDataUnprotected.pbData);
                } catch (HResultException e) {
                    if (err == null) {
                        err = e;
                    } else {
                        err.addSuppressed(e);
                    }
                }
            }
        }

        if (err != null) {
            if (unProtectedData != null) {
                Arrays.fill(unProtectedData, (byte) 0);
            }
            throw err;
        }

        return unProtectedData;
    }

    private static void freeLocalMemory(Pointer pbData) throws HResultException {
        Pointer res = Kernel32.INSTANCE.LocalFree(pbData);
        if (res != null) {
            throw HResultException.forLastErrorCode("Kernel32.LocalFree", Kernel32.INSTANCE.GetLastError());
        }
    }

}
