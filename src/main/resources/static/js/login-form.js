var aesKey='';
var aesIv='';
var rsaPubKey='';
$(document).ready(function() {


    $('body').addClass('js');
    // Make the checkbox checked on load
    $('.login-form span').addClass('checked').children('input').attr('checked', true);
    localStorage.removeItem("aesKey");
    localStorage.removeItem("aesIv");
    localStorage.removeItem("rsaPubKey");
    if(localStorage.getItem("aesKey")==null) {
        $.ajax({
            url: "/loginData/pubKey",
            type: 'POST',
            data: {},
            success: function (result) {
                rsaPubKey = result.trim();
                aesKey = CryptoJS.enc.Hex.stringify(CryptoJS.lib.WordArray.random(128/16));
                aesIv = CryptoJS.enc.Hex.stringify(CryptoJS.lib.WordArray.random(128/16));
                localStorage.setItem("aesKey",aesKey);
                localStorage.setItem("aesIv",aesIv);
                localStorage.setItem("rsaPubKey",rsaPubKey);
            },
            error: function (request, textStatus, errorThrown) {
                response = false;
            }
        });
    }

});
function setLogin(){
    var encrypt = new JSEncrypt();
    encrypt.setPublicKey(localStorage.getItem("rsaPubKey"));

    var encKeyValue = encrypt.encrypt(''+localStorage.getItem("aesKey"));
    var encIv = encrypt.encrypt(''+localStorage.getItem("aesIv"));

    $('#doctorIDVal').val(encryptDataWithAES($('#doctorID').val(),localStorage.getItem("aesKey"),localStorage.getItem("aesIv")).toString());
    $('#password').val(encryptDataWithAES(hex_sha1(MD5($("#passwordField").val())),localStorage.getItem("aesKey"),localStorage.getItem("aesIv")).toString());
    $("#passwordField").val('');
    $("#doctorID").val('');
    $('#key').val(encKeyValue);
    $('#value').val(encIv);
    $("#loginForm").submit();

}
