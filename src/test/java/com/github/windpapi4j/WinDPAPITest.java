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

import com.github.windpapi4j.HResultException;
import com.github.windpapi4j.InitializationFailedException;
import com.github.windpapi4j.WinAPICallFailedException;
import com.github.windpapi4j.WinDPAPI;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import java.io.UnsupportedEncodingException;

public class WinDPAPITest {

    private int HRESULT_CORRUPTED_DATA = -2147024883;

    private WinDPAPI winDPAPI;

    @BeforeTest
    public void beforeTestMethod() throws InitializationFailedException {

        this.winDPAPI = WinDPAPI.newInstance(WinDPAPI.CryptProtectFlag.CRYPTPROTECT_UI_FORBIDDEN);

    }

    @Test(expectedExceptions = NullPointerException.class)
    public void testProtectDataNPE() throws WinAPICallFailedException {

        winDPAPI.protectData(null);
        winDPAPI.protectData(null, convertStringToByteArray("xxx"));
        winDPAPI.protectData(null, convertStringToByteArray("xxx"), "test");
    }

    @Test(expectedExceptions = NullPointerException.class)
    public void testUnprotectDataNPE() throws WinAPICallFailedException {

        winDPAPI.unprotectData(null);
        winDPAPI.unprotectData(null, convertStringToByteArray("xxx"));
    }




    @Test
    public void testSimpleEncryption() throws WinAPICallFailedException {

        String originalString = "FooBar";

        byte[] input = convertStringToByteArray(originalString);

        byte[] protectedData = winDPAPI.protectData(input);

        byte[] unprotectedData = winDPAPI.unprotectData(protectedData);

        String unprotectedString = convertByteArrayToString(unprotectedData);


        Assert.assertEquals(input, unprotectedData);
        Assert.assertEquals(originalString, unprotectedString);
    }

    @Test
    public void testSimpleDecryptionWithCorruptedData() throws WinAPICallFailedException {

        String originalString = "FooBar";

        byte[] input = convertStringToByteArray(originalString);

        byte[] protectedData = winDPAPI.protectData(input);
        protectedData[2] = (byte)(~(int) protectedData[2]); // simulate data corruption

        try
        {
            winDPAPI.unprotectData(protectedData);
            Assert.fail("Expected to throw exception");
        } catch ( WinAPICallFailedException e) {
            Throwable cause = e.getCause();

            Assert.assertTrue(cause instanceof HResultException,
                    "Cause should have been HResultException, but was " + cause);

            int hResult = ((HResultException) cause).getHResult();

            Assert.assertEquals(HRESULT_CORRUPTED_DATA, hResult);
        }

    }

    @Test
    public void testEncryptionWithEntropy() throws WinAPICallFailedException {

        String passwordString = "myPassword";

        byte[] entropy = convertStringToByteArray(passwordString);

        String originalString = "FooBar";

        byte[] input = convertStringToByteArray(originalString);

        byte[] protectedData = winDPAPI.protectData(input, entropy);

        byte[] unprotectedData = winDPAPI.unprotectData(protectedData, entropy);

        String unprotectedString = convertByteArrayToString(unprotectedData);


        Assert.assertEquals(input, unprotectedData);
        Assert.assertEquals(originalString, unprotectedString);
    }

    @Test
    public void testEncryptedWithEntropyCannotBeDecryptedWithoutEntropy() throws WinAPICallFailedException {

        String passwordString = "myPassword";

        byte[] entropy = convertStringToByteArray(passwordString);

        String originalString = "FooBar";

        byte[] input = convertStringToByteArray(originalString);

        byte[] protectedData = winDPAPI.protectData(input, entropy);

        try
        {
            winDPAPI.unprotectData(protectedData);
            Assert.fail("Expected to throw exception");
        } catch ( WinAPICallFailedException e) {
            Throwable cause = e.getCause();

            Assert.assertTrue(cause instanceof HResultException,
                    "Cause should have been HResultException, but was " + cause);

            int hResult = ((HResultException) cause).getHResult();

            Assert.assertEquals(HRESULT_CORRUPTED_DATA, hResult);
        }
    }

    @Test
    public void testEncryptedWithEntropyCannotBeDecryptedWithCorruptedEntropy() throws WinAPICallFailedException {

        String passwordString = "myPassword";

        byte[] entropy = convertStringToByteArray(passwordString);

        String originalString = "FooBar";

        byte[] input = convertStringToByteArray(originalString);

        byte[] protectedData = winDPAPI.protectData(input, entropy);

        try
        {
            entropy[2] = (byte)(~(int) entropy[2]); // simulate data corruption
            winDPAPI.unprotectData(protectedData, entropy);
            Assert.fail("Expected to throw exception");
        } catch ( WinAPICallFailedException e) {
            Throwable cause = e.getCause();

            Assert.assertTrue(cause instanceof HResultException,
                    "Cause should have been HResultException, but was " + cause);

            int hResult = ((HResultException) cause).getHResult();

            Assert.assertEquals(HRESULT_CORRUPTED_DATA, hResult);
        }
    }




    private static byte[] convertStringToByteArray(String string) {
        try {
            return string.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("The JVM should always support UTF-8", e); // should not happen
        }
    }

    private String convertByteArrayToString(byte[] byteArray) {
        try {
            return new String(byteArray, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("The JVM should always support UTF-8", e); // should not happen
        }
    }
}
