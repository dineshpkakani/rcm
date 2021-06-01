package com.ecw.rcm.utils;


import java.security.MessageDigest;
import java.util.Formatter;

/**
 * Created by amitkumard on 07/14/17.
 */
public class EcwHashUtill {
    /**
     * This function returns SHA1 hashed value of String input
     * @param message
     * @return SHA1 hashed value of String
     */
    public static synchronized String getSHA1Hash(String message) {
        String strHash = "";
        try {
        	 /*
             * suppressing the squid id : squid:S2070 SHA-1 and Message-Digest hash algorithms should not be used in secure contexts
             * Reason for suppression : This encryption is an additional non-critical layer of protection and communication happens over HTTPS only.
             */
        	@SuppressWarnings("squid:S2070")
            MessageDigest messagedigest = MessageDigest.getInstance("SHA-1");
            messagedigest.update(message.getBytes());
            byte digest[] = messagedigest.digest();
            strHash = convertToHex(digest);
        } catch (Exception e) {
          e.printStackTrace();
        }
        return strHash;
    }

    /**
     * This function returns hex representation of byte[] in String
     * @param data
     * @return String value of byte[]
     */
    private static String convertToHex(byte[] data) {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < data.length; i++) {
            int halfbyte = (data[i] >>> 4) & 0x0F;
            int two_halfs = 0;
            do {
                if ((0 <= halfbyte) && (halfbyte <= 9))
                    buf.append((char) ('0' + halfbyte));
                else
                    buf.append((char) ('a' + (halfbyte - 10)));
                halfbyte = data[i] & 0x0F;
            } while (two_halfs++ < 1);
        }
        return buf.toString();
    }

    /**
     * This function returns SHA2 hash of string passed
     * @param message : String input value
     * @return SHA2 hashed value of string passed as input
     */
    public static synchronized String getSHA256Hash(String message) {
        String strHash = "";
        try {
            MessageDigest messagedigest = MessageDigest.getInstance("SHA-256");
            messagedigest.update(message.getBytes());
            byte digest[] = messagedigest.digest();
            strHash = convertToHex(digest);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return strHash;
    }

    /**
     * @param algorithm : Algorithm to be used for hashing
     * @param message   : String to be encoded
     * @return String value :  Calculated hash value of message
     */

    //Added by Sujal Shah to apply Hashing (MD5)
    public static String calculateHash(String algorithm, String message) throws Exception {
        if (algorithm == null || message == null) {
            return null;
        }

        MessageDigest algo = MessageDigest.getInstance(algorithm);
        algo.update(message.getBytes());
        byte[] hash = algo.digest();
        return byteArray2Hex(hash);
    }

    /**
     * Below function gets the byte[] and returns the string representation of it
     *
     * @param hash
     * @return
     */
    public static String byteArray2Hex(byte[] hash) {
        if (hash == null) {
            return null;
        }

        Formatter formatter = new Formatter();
        for (byte b : hash) {
            formatter.format("%02x", b);
        }
        String retValue = formatter.toString();
        formatter.close();
        return retValue;
    }

}
