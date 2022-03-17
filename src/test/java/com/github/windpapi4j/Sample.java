package com.github.windpapi4j;

import com.github.windpapi4j.WinDPAPI;
import com.github.windpapi4j.WinDPAPI.CryptProtectFlag;

import java.nio.charset.StandardCharsets;

public class Sample {

    public static void main(String[] args) throws Exception {

        if(WinDPAPI.isPlatformSupported()) {
            WinDPAPI winDPAPI = WinDPAPI.newInstance(CryptProtectFlag.CRYPTPROTECT_UI_FORBIDDEN);

            String message = "Hello World!";

            byte[] clearTextBytes = message.getBytes(StandardCharsets.UTF_8);

            byte[] cipherTextBytes = winDPAPI.protectData(clearTextBytes);

            byte[] decryptedBytes = winDPAPI.unprotectData(cipherTextBytes);

            String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);

            if(! message.equals(decryptedMessage) ) {
                throw new IllegalStateException(message + " != " + decryptedMessage); // should not happen
            }

            System.out.println(decryptedMessage);

        } else {
            System.err.println("ERROR: platform not supported");
        }
    }
}