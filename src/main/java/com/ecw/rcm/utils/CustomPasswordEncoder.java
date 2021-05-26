package com.ecw.rcm.utils;


import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.regex.Pattern;


public class CustomPasswordEncoder extends BCryptPasswordEncoder {
    private final Pattern BCRYPT_PATTERN = Pattern.compile("\\A\\$2a?\\$\\d\\d\\$[./0-9A-Za-z]{53}");

    /**
     * This is default constructor, it does following thing
     * 1. Sets the Alogorithm strength to 12, i.e. 12 rounds of encoding for each password
     */
    public CustomPasswordEncoder() {
        super(12);
    }

    /**
     * @param passwordToEncode : This value must be in MD5(plain password)
     * @return returns either Bcrypt encoded password i.e. BCrypt(SHA2(SHA1(passwordToEncode))) or MD5 value
     */
    @Override
    public String encode(CharSequence passwordToEncode) {
        if (passwordToEncode == null) {
            return null;
        }
        if (passwordToEncode.length() == 32) { //This is in MD5 format
            return super.encode(EcwHashUtill.getSHA256Hash(EcwHashUtill.getSHA1Hash(passwordToEncode.toString())));
        } else if (passwordToEncode.length() == 40) {   //Password received is in SHA1 format
            return super.encode(EcwHashUtill.getSHA256Hash(passwordToEncode.toString()));
        }else { //For all other cases
            return super.encode(EcwHashUtill.getSHA256Hash(EcwHashUtill.getSHA1Hash(passwordToEncode.toString())));
        }
    }

    /**
     * @param passwordReceived : Must be in SHA1(MD5(plain password)) format
     * @param passwordInDb     : Could be either bcrypt or MD5 value
     * @return boolean value :  indicating whether password matched or not..
     */
    @Override
    public boolean matches(CharSequence passwordReceived, String passwordInDb) {
        return (checkPassword(passwordReceived.toString(), passwordInDb) != 0);
    }

    /**
     * @param passwordReceived : Must be in SHA1(MD5(plain password)) format
     * @param passwordInDb     : Could be either bcrypt or MD5 value
     * @return 0 if passwords didn't match, 1 if password matched, 2 if password matched and upgrade needed
     */
    public int checkPassword(String passwordReceived, String passwordInDb) {
        if (passwordReceived == null || passwordInDb == null) {
            return 0;
        }

    	if (BCRYPT_PATTERN.matcher(passwordInDb).matches()) {
    		if (super.matches(EcwHashUtill.getSHA256Hash(passwordReceived), passwordInDb)) {
    			return 1;
    		}
	   	}
    	return 0;
    }

}
