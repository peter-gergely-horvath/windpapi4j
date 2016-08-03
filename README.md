# WinDPAPI4J: A Windows DPAPI Wrapper for Java

## Introduction

Starting from Microsoft(R) Windows(R) 2000, Windows operating systems provide 
a built-in cryptographic feature called ["Windows Data Protection API" (DPAPI)](https://msdn.microsoft.com/en-us/library/ms995355.aspx), 
which allows any application to securely encrypt confidential user data using 
the user's credentials in a way that it can only be decrypted by the same user.

This Java library exposes Windows Data Protection encryption and decryption
features as an easy to use Java API. Behind the scenes, [JNA (Java Native
Access)](https://github.com/java-native-access/jna/blob/master/www/GettingStarted.md)
library is used to invoke the native  Windows CryptoAPI
`CryptProtectData` and `CryptUnprotectData` functions. 

**Note**:
 * Since this library exposes a Windows feature, it will only work, when called from a Java application running on Windows
 * Only an essential subset of Windows Data Protection API (DPAPI) is supported  by this library: advanced cases involving showing prompts to the user etc. 
are not implemented.

###

The JavaDoc is part of the Maven Central installation and can be viewed online via [javadoc.io](http://javadoc.io/doc/com.github.peter-gergely-horvath/windpapi4j/1.0)
## Passing special flags to Windows DPAPI

As described in _Microsoft Development Network Documentation on Cryptography
Functions_, both [CryptProtectData](https://msdn.microsoft.com/en-us/library/windows/desktop/aa380882(v=vs.85).aspx) and
[CryptUnprotectData](https://msdn.microsoft.com/en-us/library/windows/desktop/aa380882(v=vs.85).aspx) 
functions accept optional flag values, which control their behaviour. 

These optional flag values are defined in `WinDPAPI.CryptProtectFlag` as enum 
constants and can be passed to the static factory method 
`WinDPAPI#newInstance(CryptProtectFlag...)`
after which the `WinDPAPI` instance returned will pass them to the target native 
Windows DPAPI method.

## Mapping of methods

**Methods for encryption**

| WinDPAPI library methods                                 | Windows CryptoAPI method    |
| -------------------------------------------------------- | --------------------------- |
| `WinDPAPI#protectData(byte[])`                           | `CryptProtectData`          |
| `WinDPAPI#protectData(byte[], byte[])`                   | `CryptProtectData`          |
| `WinDPAPI#protectData(byte[], byte[], java.lang.String)` | `CryptProtectData`          |


**Methods for decryption**

| WinDPAPI library methods                                 | Windows CryptoAPI method    |
| -------------------------------------------------------- | --------------------------- |
| `WinDPAPI#unprotectData(byte[])`                         | `CryptUnprotectData`        |
| `WinDPAPI#unprotectData(byte[], byte[])`                 | `CryptUnprotectData`        |


## Sample Code

```
package test;
  
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
```

## Availability

This library has been made available in [Maven Central Repository](http://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.github.peter-gergely-horvath%22).  

