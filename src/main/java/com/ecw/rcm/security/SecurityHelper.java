package com.ecw.rcm.security;

import org.apache.tomcat.util.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;



import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.security.*;
import java.util.*;



public class SecurityHelper {

	public static final String RSA_PUB_KEY= "RsaPubKey";
	public static final String RSA_PRIVATE_KEY = "RsaPrivateKey";
	public static final String REQUEST_ENC_KEY_NAME = "crypto_aesKey_requestEnc";
	public static final String REQUEST_ENC_IV_NAME = "crypto_aesIv_requestEnc";

	private static final String IPV6_PATTERN = "([0-9a-f]{1,4}:){7}([0-9a-f]){1,4}"; //For extract IPV6 from URL
	private static final int NUMBER_TWO = 2;
	private static final int CASE_AND_VALUE_SIXTY = 60;
	private static final int CASE_FORTY_FIVE = 45;
	private static final int CASE_THIRTY = 30;
	private static HashMap<String, String> sessionLessUrls = null;
	private static final String MCOOKIETEMP = "eCW_ULT";
	private static final String ADMINISTRATION="Administration";
	private static final String MANAGE_SECURITY="ManageSecurity";
	private static final String SHOW_ADMIN_BAND="ShowAdminBand";
	private static final String ALGORITHM = "AES/CBC/NoPadding";
	public static final String MOBILEDOC_SESSION_LOGGING_OUT_URL = "/mobiledoc/jsp/webemr/security/setRemoteSessionParameter";
	public static final String REQUEST_VALUE_FOR_PARAMVALUE_FORCE_LOGOUT = "true";
	public static final String REQUEST_VALUE_FOR_PARAMNAME_FORCE_LOGOUT = "isForceLogout";
	private static final int HARD_LOCK_MIN = -99;
	private static final int NUMBER_THREE = 3;
	private static final int SOFT_LOCK_LIMIT = -NUMBER_THREE;
	private static final int AUTO_UNLOCK_MIN = 15;
	private static final int NUMBER_FOUR = 4;
	private static final int CASE_AND_SIZE_FIVE = 5;
	private static final int CASE_SIX = 6;
	private static final int CASE_SEVEN = 7;
	private static final int CASE_AND_LENGTH_EIGHT = 8;
	private static final int CASE_AND_INDEX_NINE = 9;
	private static final int NUMBER_TEN = 10;
	private static final int CASE_TWELVE = 12;
	private static final int CASE_THIRTEEN = 13;
	private static final int FIFTEEN_MINUTES = 15;
	private static final int NUMBER_NINETY_NINE = 99;
	private static final int RANDOM_AND_SIZE_SIXTEEN = 16;
	private static final int RANDOM_32 = 32;
	private static final int BITS_128 = 128;
	private static final int BITS_256 = 256;
	private static final int INIT_KEY_SIZE = 2048;
	private static final int HARD_LOCK_LIMIT = -NUMBER_FOUR;
	private final String OLD_PD_ERROR_MESSEAGE_WEB ="Old Password does not match in the database, so can not update the new password.</br> Please enter the correct old password.</br>";
	private final String OLD_PD_ERROR_MESSEAGE_EXE ="Old Password does not match in the database, so can not update the new password.\nPlease enter the correct old password.\n";
	private static final Logger LOGGER=LoggerFactory.getLogger(SecurityHelper.class);
	private static final int DEFAULT_SESSION_TIMEOUT_MIN = 30;
	private static final int SIXTY = 60;

	public static KeyPair pair = null;
	public static PrivateKey pvtKey = null;
	public static Key pubKey = null;




	/**
	 * This function generates and stores a new _csrf token if there was none
	 * and if session already had a _csrf token resets it
	 * @param request   HttpServletRequest object received for this request
	 * @param response  HttpServletResponse object received for this request
	 */
	public static void setCsrfToken(HttpServletRequest request, HttpServletResponse response) {
		// Generate and set CSRF token
		HttpSessionCsrfTokenRepository tokenRepository = new HttpSessionCsrfTokenRepository();
		CsrfToken csrfToken = tokenRepository.loadToken(request);
		if (csrfToken == null) {
			tokenRepository.saveToken(tokenRepository.generateToken(request), request, response);
		}
	}

	/**
	 * This function returns object of CsrfToken class
	 * @param request
	 * @return
	 */
	public static CsrfToken getCsrfToken(HttpServletRequest request){
		HttpSessionCsrfTokenRepository httpSessionCsrfTokenRepository = new HttpSessionCsrfTokenRepository();
		return httpSessionCsrfTokenRepository.loadToken(request);
	}





	//Added by Sujal Sha to get a list of whitelisted urls


	public static String getEncryptionKeyFromSession(String usage,HttpServletRequest request){
	    HttpSession session = null;
        if(request==null || (session =  request.getSession(false)) == null){
            return null;
        }

        String keyName =  "jCryptionKey";
        if(usage!=null && !"".equalsIgnoreCase(usage.trim())){
            keyName = keyName + "_"+usage;
        }
        return ((String) session.getAttribute(keyName));
    }



	public static String getValueFromSession(HttpServletRequest request, String keyValue) {
		String requestedSessionValue = null;
		try {
			HttpSession session = request.getSession(false);

			if (session != null) {
				requestedSessionValue = (String) session.getAttribute(keyValue);
			}

		}catch(Exception ex) {
			LOGGER.error(ex.getMessage(), ex);
		}

		return requestedSessionValue;
	}

	public static boolean removeValueFromSession(HttpServletRequest request, String keyValue) {
		try {
			HttpSession session = request.getSession(false);

			if (session != null) {
				session.removeAttribute(keyValue);
				return true;
			}
			return false;
		}catch(Exception ex) {
			LOGGER.error(ex.getMessage(), ex);
			return false;
		}
	}
	public KeyPair generateRSAKeyPair() {
    	KeyPair pair = null;
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(INIT_KEY_SIZE, new SecureRandom());
		    pair = generator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error(e.getMessage(), e);
		}
		return pair;
    }
	public static String decryptValue(String encValue, String keyValue, String ivValue) {
		try {
			Security.setProperty("crypto.policy", "unlimited");
			if(keyValue != null && ivValue != null && !keyValue.trim().isEmpty() && !ivValue.trim().isEmpty()) {
				byte[] keyBytes = keyValue.getBytes();
				byte[] ivBytes = ivValue.getBytes();

				IvParameterSpec ivSpecURL = new IvParameterSpec(ivBytes);
				SecretKeySpec	keySpecURL = new SecretKeySpec(keyBytes, "AES");
				Cipher c = Cipher.getInstance(ALGORITHM);
				c.init(Cipher.DECRYPT_MODE, keySpecURL, ivSpecURL);
				byte[] decordedValue = Base64.decodeBase64(encValue);
				byte[] decValue = c.doFinal(decordedValue);
				return new String(decValue).trim();
			}else {
				return "";
			}
		}catch(BadPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException ex){
			LOGGER.error(ex.getMessage(), ex);
		}
		return "";
	}
/**
	 * This method is used to encrypt the plain text
	 * @param data : plain text which is to be encrypted
	 * @param keyValue : key value for encryption
	 * @param ivValue : iv value for encryption
	 * @return : encrypted text
	 * @return : null if key or iv is null
	 * @throws Exception
	 * @author : vrunda
	 */
	public static String encryptValue(String data, String keyValue, String ivValue ) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		if(keyValue != null && ivValue != null && !keyValue.trim().isEmpty() && !ivValue.trim().isEmpty()) {
			byte[] keyBytes = keyValue.getBytes();
			byte[] ivBytes = ivValue.getBytes();
			IvParameterSpec ivSpecURL = new IvParameterSpec(ivBytes);
			SecretKeySpec keySpecURL = new SecretKeySpec(keyBytes, "AES");
			Cipher c = Cipher.getInstance(ALGORITHM);
			c.init(Cipher.ENCRYPT_MODE, keySpecURL, ivSpecURL);
			byte[] encVal = c.doFinal(padString(data).getBytes());
			return org.apache.tomcat.util.codec.binary.Base64.encodeBase64String(encVal);
		}else {
			return null;
		}
	}

	/**
	 * This method is used to pad the string so that encryption is properly performed
	 * @param source : text to be padded
	 * @return : padded string
	 * @author : vrunda
	 */
	private static String padString(String source) {
		char paddingChar = ' ';
		int size = RANDOM_AND_SIZE_SIXTEEN;
		int x = source.length() % size;
		int padLength = size - x;

		for (int i = 0; i < padLength; i++) {
			source += paddingChar;
		}
		return source;
	}


	/**<code><b>genrateCsrfToken(HttpServletRequest request, HttpServletResponse response):</b></code>
	 * This function is use to generates new csrf token
	 * @param request   HttpServletRequest  request
	 * @param response  HttpServletResponse  request
	 *
	 */
	public static CsrfToken genrateCsrfToken(HttpServletRequest request, HttpServletResponse response) {
		// Generate and set CSRF token
		HttpSessionCsrfTokenRepository tokenRepository = new HttpSessionCsrfTokenRepository();
		tokenRepository.saveToken(tokenRepository.generateToken(request), request, response);
		return tokenRepository.loadToken(request);
		}



    public static String getRSAPubKey() {
    	String encodedPublicKey = "";


	    		SecurityHelper securityHelper = new SecurityHelper();
	    		 pair = securityHelper.generateRSAKeyPair();
				 pvtKey = pair.getPrivate();

	    		 pubKey = pair.getPublic();
	    		byte publicKeyBytes[] = pubKey.getEncoded();
	    		encodedPublicKey = new String(org.apache.tomcat.util.codec.binary.Base64.encodeBase64(publicKeyBytes));

    	return encodedPublicKey.trim();
    }
    public String[] getNewKey(String encKeyValue,String encIvValue,String usage ){

		String keyValue="";
		String ivValue="";
			try{

				SecurityHelper securityHelper = new SecurityHelper();
				Cipher cipher = Cipher.getInstance("RSA"); /// ECB/PKCS1Padding

				if(null  != cipher || null != pvtKey ){
						cipher.init(Cipher.DECRYPT_MODE, pvtKey);
						 keyValue = new String(cipher.doFinal(org.apache.tomcat.util.codec.binary.Base64.decodeBase64(encKeyValue)));
						 ivValue = new String(cipher.doFinal(org.apache.tomcat.util.codec.binary.Base64.decodeBase64(encIvValue)));

					}


			}catch(Exception ex1){
				ex1.printStackTrace();
			}
			String str[]=new String[2];
			str[0]=keyValue;
			str[1]=ivValue;
			return str ;
	}
public String getPlainUnamePWD(String str){
	String iv="";
	String key="";
	//String iv= !isSessionTimeout?String.valueOf(session.getAttribute("crypto_aesIv_loginDataEnc")):(String) session.getAttribute("crypto_aesIv_sessionTimeout");
	//String key=!isSessionTimeout?String.valueOf(session.getAttribute("crypto_aesKey_loginDataEnc")):(String) session.getAttribute("crypto_aesKey_sessionTimeout");
	/*String strUserName = request.getParameter("username");
	strUserName=(strUserName==null)?"":SecurityHelper.decryptValue(strUserName.trim(),key, iv);
	String password = request.getParameter("password");
	password=(password==null)?"":SecurityHelper.decryptValue(password.trim(),key, iv);
	*/
	return str=(str==null)?"":SecurityHelper.decryptValue(str.trim(),key, iv);
}
}
