$(document).ready(function () {
    // Init
    $('.loader').hide();
    $('#result').hide();

    // Predict
    $('#btn-predict').click(function () {
        var url_input = $('#url-input').val();

        // Show loading animation
        $(this).hide();
        $('.loader').show();

        // Make prediction by calling API /predict
        $.ajax({
            type: 'POST',
            url: '/predict',
            data: { url: url_input },
            success: function (data) {
                // Get and display the result
                $('.loader').hide();
                $('#result').fadeIn(600);
                $('#result').text('This website is ' + data.website_status + '.\n' + 'The malicious probability is ' + data.malicious_probability.toFixed(2) + '%.');
                console.log('Success!');
            },
            error: function (xhr, status, error) {
                // Handle errors
                $('.loader').hide();
                $('#result').text('Error: ' + error);
                $('#result').fadeIn(600);
                console.log('Error:', status, xhr.responseText);
            }
        });
    });
});
