/**
 * Created by Vrunda Patel
 * This file takes care of 
 * 1. Generating AES key and IV
 * 2. Setting Keys in session
 * 3. Encrypting data with AES key and IV
 */

/*This is only about get operation and its verified that we do not put sensitive data in sessionStorage
or localStorage. We will make sure that same principle is followed in future as well.*/
function jCryptionAuthenticate(usage,key,success,failure){
	var localKeyName = "jCryptionKey";
	if(usage && "" !== usage.trim()){
		usage = usage.trim();
		localKeyName =  localKeyName +"_"+usage;
	}

	var jCryptionKeyLocal = localStorage.getItem(localKeyName); //NOSONAR
	var encInstName = "encInstId_"+usage;

	if(jCryptionKeyLocal && jCryptionKeyLocal!=null && ""!== jCryptionKeyLocal){
		var sessionEncInstId = sessionStorage.getItem(encInstName); //NOSONAR
		var localEncInstId = localStorage.getItem(encInstName);

		if(sessionEncInstId == null || sessionEncInstId !== localEncInstId){
			localStorage.removeItem(localKeyName);
			var encInstId = generateGUID();
			sessionStorage.setItem(encInstName,encInstId);
			localStorage.setItem(encInstName,encInstId);
		}else {
			success(jCryptionKeyLocal);
			return;
		}
	}
	var hashObj = new jsSHA(generateGUID(), "ASCII");
	var key = (key) ? key : hashObj.getHash("SHA-512", "HEX");

	var gkp_url = "/mobiledoc/jsp/webemr/login/setEncVariables.jsp?gKP=true";
	if(usage && ""!== usage.trim()){
		gkp_url = gkp_url + "&usage="+usage;
	}

	var hs_url = "/mobiledoc/jsp/webemr/login/setEncVariables.jsp?hs=true";
	if(usage && ""!== usage.trim()){
		hs_url = hs_url + "&usage="+usage;
	}

	$.jCryption.authenticate(key,  gkp_url, hs_url,  function (AESKey) {
			localStorage.setItem(localKeyName,AESKey);
			var encInstId = generateGUID();
			sessionStorage.setItem(encInstName,encInstId);
			localStorage.setItem(encInstName,encInstId);
			success(AESKey);
		},function () {
			failure();
		}
	);
}
function getCryptoAesKey(usage,existingKey,existingIv,success,failure){

} 

function encryptDataWithAES(data,aesKey,aesIv){
	var aesEncrypted = "";
	var encValue = "";
	var keyValue="";
	var iv="";
	if(aesKey && aesIv){
		keyValue=CryptoJS.enc.Latin1.parse(aesKey);
		iv=CryptoJS.enc.Latin1.parse(aesIv);
		CryptoJS.pad.NoPadding = {pad: function(){}, unpad: function(){}};
		encValue = padString(data);
		aesEncrypted = CryptoJS.AES.encrypt(encValue, keyValue, { iv: iv, padding: CryptoJS.pad.NoPadding, mode: CryptoJS.mode.CBC});
	}
	return aesEncrypted;
}

function padString(source) {
    var paddingChar = ' ';
    var size = 16;
    var x = source.length % size;
    var padLength = size - x;
    
    for (var i = 0; i < padLength; i++) source += paddingChar;
    
    return source;
}

function setAesKeyInSession(strKeyValue, strIv, usage){
	var response = false;
	debugger;
	if(rsaPubKey){
		var csrfToken = $("meta[name='_csrf']").attr("content");
		var encrypt = new JSEncrypt();
		encrypt.setPublicKey(rsaPubKey);
		var encKeyValue = encrypt.encrypt(''+strKeyValue);
		var encIv = encrypt.encrypt(''+strIv);
		$.ajax({
			url: "/loginData/key",
	        type:'POST',
	        async:false,
	        headers: {
           	 "X-CSRF-Token":csrfToken
            }, 
	        data: {encKeyValue:encKeyValue, encIv:encIv, usage:usage} ,
	        success: function(result) {
				result = result.trim();
				var arr=result.split("***");
				// aesKey=arr[0];
			//	 aesIv=arr[1];
				isEncVariableAvailable=true;

            },
	        error: function(request, textStatus, errorThrown) {
	        	response = false;
	        }
	    });
	}	
	return response;
}
