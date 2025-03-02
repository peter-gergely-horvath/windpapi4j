package com.github.windpapi4j;

import com.github.windpapi4j.WinDPAPI;
import com.github.windpapi4j.WinDPAPI.CryptProtectFlag;

import java.nio.charset.StandardCharsets;

public class Sample {

    public static void main(String[] args) {

        if (!WinDPAPI.isPlatformSupported()) {
            System.err.println("ERROR: platform is not supported");
            System.exit(-1);
        }

        try {
            WinDPAPI winDPAPI = WinDPAPI.newInstance(CryptProtectFlag.CRYPTPROTECT_UI_FORBIDDEN);

            String message = "Hello World!";

            byte[] clearTextBytes = message.getBytes(StandardCharsets.UTF_8);

            byte[] cipherTextBytes = winDPAPI.protectData(clearTextBytes);

            byte[] decryptedBytes = winDPAPI.unprotectData(cipherTextBytes);

            String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);

            if (!message.equals(decryptedMessage)) {
                throw new IllegalStateException(message + " != " + decryptedMessage); // should not happen
            }

            System.out.println(decryptedMessage);

        } catch (InitializationFailedException initializationFailedException) {
            initializationFailedException.printStackTrace();

            System.exit(1);
        } catch (HResultException hResultException) {
            System.err.println(hResultException.getMessage());
            System.err.format("Value of HRESULT is: %s %n", hResultException.getHResult());

            System.exit(2);

        } catch (WinAPICallFailedException winAPICallFailedException) {
            winAPICallFailedException.printStackTrace();

            System.exit(3);
        }
    }
}