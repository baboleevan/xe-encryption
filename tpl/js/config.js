
jQuery(function() {
	
	var $ = jQuery;
	
	$("#encryption_aes_store_db,#encryption_aes_store_file").click(function() {
		if ($("#encryption_aes_store_db").is(":checked")) {
			$("#encryption_aes_store_filename").attr("disabled", "disabled");
		} else {
			$("#encryption_aes_store_filename").removeAttr("disabled");
		}
	});
	
	$("#encryption_rsa_store_db,#encryption_rsa_store_file").click(function() {
		if ($("#encryption_rsa_store_db").is(":checked")) {
			$("#encryption_rsa_store_filename").attr("disabled", "disabled");
		} else {
			$("#encryption_rsa_store_filename").removeAttr("disabled");
		}
	});
	
	if ($("#encryption_aes_keygen").size()) {
		$("#encryption_aes_key").hide();
	}
	
	if ($("#encryption_rsa_keygen").size()) {
		$("#encryption_rsa_privkey,#encryption_rsa_pubkey").hide();
	}
	
	$("#encryption_rsa_bits").change(function() {
		$("#encryption_rsa_bits_hidden").val($(this).val());
	});
	
	$("#encryption_aes_keygen").click(function(event) {
		event.preventDefault();
		$(this).attr("disabled", "disabled");
		$.exec_json(
			"encryption.getEncryptionAdminNewAESKey", { },
			function(response) {
				$("#encryption_aes_key").val(response.newkey).show();
				$("#encryption_aes_keygen").hide();
			},
			function(response) {
				alert("Keygen Error");
				$("#encryption_aes_keygen").removeAttr("disabled");
			}
		);
	});
	
	$("#encryption_rsa_keygen").click(function(event) {
		event.preventDefault();
		$(this).attr("disabled", "disabled");
		$.exec_json(
			"encryption.getEncryptionAdminNewRSAKey",
			{ key_size : $("#encryption_rsa_bits").val() },
			function(response) {
				$("#encryption_rsa_privkey").val(response.privkey).show();
				$("#encryption_rsa_pubkey").val(response.pubkey).show();
				$("#encryption_rsa_bits").attr("disabled", "disabled");
				$("#encryption_rsa_keygen").hide();
				$("#encryption_rsa_keygen_needed").hide();
			},
			function(response) {
				alert("Keygen Error");
				$("#encryption_rsa_keygen").removeAttr("disabled");
			}
		);
	});
	
	$("#encryption_delete_aes_key").click(function(event) {
		event.preventDefault();
		var yes = confirm($(this).data("confirm"));
		if (yes) {
			$("#encryption_aes_key").val("");
		}
	});
	
	$("#encryption_delete_rsa_key").click(function(event) {
		event.preventDefault();
		var yes = confirm($(this).data("confirm"));
		if (yes) {
			$("#encryption_rsa_privkey").val("");
			$("#encryption_rsa_pubkey").val("");
		}
	});
});
