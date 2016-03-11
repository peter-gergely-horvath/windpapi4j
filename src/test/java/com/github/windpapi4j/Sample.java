package com.github.windpapi4j;

import com.github.windpapi4j.WinDPAPI;
import com.github.windpapi4j.WinDPAPI.CryptProtectFlag;

public class Sample {

    public static void main(String[] args) throws Exception {

        if(WinDPAPI.isPlatformSupported()) {
            WinDPAPI winDPAPI = WinDPAPI.newInstance(CryptProtectFlag.CRYPTPROTECT_UI_FORBIDDEN);

            String message = "Hello World!";
            String charsetName = "UTF-8";

            byte[] clearTextBytes = message.getBytes(charsetName);

            byte[] cipherTextBytes = winDPAPI.protectData(clearTextBytes);

            byte[] decryptedBytes = winDPAPI.unprotectData(cipherTextBytes);

            String decryptedMessage = new String(decryptedBytes, charsetName);

            if(! message.equals(decryptedMessage) ) {
                throw new IllegalStateException(message + " != " + decryptedMessage); // should not happen
            }

            System.out.println(decryptedMessage);

        } else {
            System.err.println("ERROR: platform not supported");
        }
    }
}