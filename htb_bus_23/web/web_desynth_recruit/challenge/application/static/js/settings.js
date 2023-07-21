$(document).ready(function () {
	if ($('#bots').val() == 'None') return;

	let sBots = JSON.parse($('#bots').val().replaceAll("'", "\"") || '[]');
	$('.sBots').each(function () {
		if (sBots.includes($(this).val())) {
			$(this).prop('checked', true);
		}
	});
	$("#save-btn").on('click', saveSettings);

});

const check = (bots) => {
	if (
		!$('#full_name').val() ||
		!$('#issn').val() ||
		!$('#qualification').val() ||
		!$('#iexp').val() ||
		!$('#bio').val() ||
		!$('#meta_desc').val() ||
		!$('#meta_keywords').val() ||
		bots.length === 0
	) {
		return false
	}

	return true
}

const uploadIPC = async () => {
	if ($('#formFile').val() != null) {
		if ($('#formFile').val() != "") {
			var filedata = new FormData()
			filedata.append('file', $('#formFile')[0].files[0])

			fetch('/api/ipc_submit', {
				method: 'POST',
				body: filedata
			})
				.then(async (response) => {
					let resp = await response.json();

					if (response.status != 200) {
						let card = $("#resp-msg");
						card.text(resp.message);
					}
					else{
						location.reload()()
					}
				})
				.catch((error) => {
					card.text(error);
				});
		}
		else {
			return false
		}
	}
	else {
		return false
	}
}

const saveSettings = async () => {

	let card = $("#resp-msg");
	card.text('please wait...');
	card.show();

	let bots = [];
	$('.sBots:checked').each(function () {
		bots.push($(this).val());
	});

	validation = check(bots)

	if (!validation) {
		card.text('All fields are required!');
		return
	}

	const data = {
		full_name: $('#full_name').val(),
		issn: $('#issn').val(),
		qualification: $('#qualification').val(),
		iexp: $('#iexp').val(),
		bio: $('#bio').val(),
		bots,
		meta_desc: $('#meta_desc').val(),
		meta_keywords: $('#meta_keywords').val()
	};

	await fetch('/api/profile/me/update', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify(data),
	})
		.then(async (response) => {
			let resp = await response.json();
			card.text(resp.message);
			if (response.status == 200) {
				await uploadIPC().then((data)=>{
					if (data == false) {
						location.reload()
					}
				});
			}
		})
		.catch((error) => {
			card.text(error);
		});

	$("#submit-btn").prop("disabled", false);
}
