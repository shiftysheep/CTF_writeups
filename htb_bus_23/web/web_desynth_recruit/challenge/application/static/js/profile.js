window.onload = async () => {
    populateBots();
}

const populateBots = () => {
    let sBots = $('.exp-container').data('botExp');

    let botsHTML = `<div class="row justify-content-center">`;

    for(i=0; i < botsData.length; i++) {
        if (sBots.includes(botsData[i].name)) {
            botsHTML += `
            <div class='col-md-3 bots-col'>
                <img src='${botsData[i].src}' class='bots-img'>
            </div>`;
        }
    }

    botsHTML += `</div>`;

    $('.exp-container').html(botsHTML);
}

const reportUser = () => {
    if (!$('#report_id').val()) {
        return
    }

    fetch('/api/report', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({id: $('#report_id').val()}),
    })
    showToast('Profile reported successfully! Our moderators are reviewing the user');
}

const showToast = (msg, fixed=false) => {
    $('#globalToast').hide();
    $('#globalToast').show();
    $('#globalToastMsg').text(msg);
    if (!fixed) {
        setTimeout(() => {
            $('#globalToast').hide();
        }, 2500);
    }
}