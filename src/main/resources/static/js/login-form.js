var aesKey='';
var aesIv='';

var rsaPubKey='';

$(document).ready(function() {

    // Check if JavaScript is enabled
    $('body').addClass('js');

    // Make the checkbox checked on load
    $('.login-form span').addClass('checked').children('input').attr('checked', true);

    // Click function
    $('.login-form span').on('click', function() {



        if ($(this).children('input').attr('checked')) {
            $(this).children('input').attr('checked', false);
            $(this).removeClass('checked');
        } else {
            $(this).children('input').attr('checked', true);
            $(this).addClass('checked');
        }
    });
    var csrfToken = $("meta[name='_csrf']").attr("content");
    $.ajax({
        url: "/loginData/pubKey",
        type:'POST',
         data: {} ,
        success: function(result) {
            result = result.trim();
            rsaPubKey=result;
            //getCryptoAesKey('loginDataEnc','','',successAes,failureAes);
        },
        error: function(request, textStatus, errorThrown) {
            response = false;
        }
    });


});
function setLogin(){
    debugger;
    aesKey = CryptoJS.enc.Hex.stringify(CryptoJS.lib.WordArray.random(128/16));
    aesIv = CryptoJS.enc.Hex.stringify(CryptoJS.lib.WordArray.random(128/16));
    $('#doctorIDVal').val(encryptDataWithAES($('#doctorID').val(),aesKey,aesIv).toString());
    $('#password').val(encryptDataWithAES(hex_sha1(MD5($("#passwordField").val())),aesKey,aesIv).toString());
    $("#passwordField").val('');
    $("#doctorID").val('');
    $('#key').val(aesKey);
    $('#value').val(aesIv);
    $("#loginForm").submit();

}
