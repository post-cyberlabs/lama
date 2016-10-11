



function show_malware(id) {
    $('.malware').not('#malware_' + id).hide();
    $('#malware_' + id).show();
    $('.menu_malware').removeClass('active');
    $('#menu_malware_' + id).addClass('active');
}

function show_module_malware(malware_uid, module_id) {
    $('.module_malware_' + malware_uid).not('#module_malware_' + malware_uid + "_" + module_id).hide();
    $('#module_malware_' + malware_uid + "_" + module_id).show();
    $('.menu_module_malware_' + malware_uid).removeClass('active');
    $('#menu_module_malware_' + malware_uid + "_" + module_id).addClass('active');
}

$(document).ready(function() {
    var max_fields      = 20; //maximum input boxes allowed
    var wrapper         = $(".input_fields_wrap"); //Fields wrapper
    var wrapper_url     = $(".input_fields_wrap_url"); //Fields wrapper
    var add_button      = $(".add_field_button"); //Add button ID
    var add_button_url  = $(".add_field_button_url"); //Add button ID

    var x = 1; //initlal text box count
    $(add_button).click(function(e){ //on add input button click
        e.preventDefault();
        if(x < max_fields){ //max input box allowed
            x++; //text box increment

            $(wrapper).append('<div class="controls"><input type="file" id="fileInput" class="input-file" multiple name="file[]"><a href="#" class="remove_field"><span class="badge badge-important">X</span></a></div>'); //add input box
            // $(wrapper).append('<div><input type="text" name="mytext[]"/><a href="#" class="remove_field">Remove</a></div>'); //add input box
        }
    });

    $(add_button_url).click(function(e){ //on add input button click
        e.preventDefault();
        if(x < max_fields){ //max input box allowed
            x++; //text box increment

            $(wrapper_url).append('<div class="controls"><input id="urlInput" class="input-url" multiple name="url[]"><a href="#" class="remove_field_url"><span class="badge badge-important">X</span></a></div>'); //add input box
            // $(wrapper).append('<div><input type="text" name="mytext[]"/><a href="#" class="remove_field">Remove</a></div>'); //add input box
        }
    });

    $(wrapper).on("click",".remove_field", function(e){ //user click on remove text
        e.preventDefault(); $(this).parent('div').remove(); x--;
    })

    $(wrapper_url).on("click",".remove_field_url", function(e){ //user click on remove text
        e.preventDefault(); $(this).parent('div').remove(); x--;
    })

});

function delete_all_analysis(){
  var r = confirm("Are you sur ?");
  if (r == true) {
    var r = confirm("Realy sur ?");
    if (r == true) {
        $.ajax({type: "GET",
        url: "/api/analyze/flush/",
        success:function(result){
          location.reload();
        }});
    }
  }
}

function delete_analysis(analysis_uid){
  var r = confirm("Are you sur ?");
  if (r == true) {
      $.ajax({type: "GET",
      url: "/api/analyze/"+analysis_uid+"/delete",
      success:function(result){
        location.reload();
      }});
  }
}



$(document).ready(function () {

    $(window).scroll(function () {
        if ($(this).scrollTop() > 100) {
            $('.scrollup').fadeIn();
        } else {
            $('.scrollup').fadeOut();
        }
    });

    $('.scrollup').click(function () {
        $("html, body").animate({
            scrollTop: 0
        }, 600);
        return false;
    });

});

$(document).ready(function () {

  $('.cuckoo_vm ul').hide();
  $('.cuckoo_part .cuckoo_part_li').hide();

  $('.cuckoo_vm > .cuckoo_vm_li > h3').click(function() {
    $(this).parent().find('ul').slideToggle();
  });

  $('.cuckoo_part > h4').click(function() {
    $(this).next().slideToggle();
  });
});
