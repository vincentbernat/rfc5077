var rfc = function() {

    var step = 0;
    function nextstep() {
	$(".step" + step)
	    .filter(".running")
	    .removeClass("current")
	    .hide();
	$(".step" + step)
	    .filter(".done").fadeIn();
	step = step + 1;
	$(".step" + step)
	    .filter(".running")
	    .addClass("current")
	    .fadeIn();
    }

    function checksessionid(port, cb) {
	/* Ask for /session several time and check that session ID are
	 * still the same */
	var tries = 4;
	var sessions = [];
	var dotry = function() {
	    $.ajax({
		url: "https://"
		    + location.hostname
		    + ":" + port
		    + "/session?callback=?",
		dataType: "jsonp",
		success: function(data) {
		    sessions.push(data.sessionid);
		    tries = tries - 1;
		    if (tries === 0) {
			/* Check if session ID are the same */
			/* Skip the first result. This may be empty or
			 * an old session. */
			for (var i=2; i < sessions.length; i++) {
			    if (sessions[i].sessionid != sessions[1].sessionid) {
				cb(false);
				return;
			    }
			}
			/* Maybe there is no session at all */
			cb(sessions[1].sessionid !== '');
		    } else dotry();
		}
	    });
	};
	dotry();
    }

    $(function() {
	/* Fill navigator name */
	$("#ua").text(navigator.userAgent);
	nextstep();

	/* Grab list of servers */
	$.ajax({
	    url: "servers?callback=?",
	    dataType: "jsonp",
	    success: function(data) {
		var ports = data.servers;
		for (var i = 0; i < ports.length; i++) {
		    var el = $("#ports")
		    if (i > 0) el.append(", ");
		    $("<a href='https://"
		      + location.hostname +":"
		      + ports[i] + "'>"
		      + ports[i] + "</a>").appendTo(el);
		}

		/* Setup the start button */
		$("#start").click(function() {
		    nextstep();
		    $.ajax({
			url: "session?callback=?",
			dataType: "jsonp",
			success: function(data) {
			    $("#cipher").text(data.cipher);
			    nextstep();
			    checksessionid(ports[1], function(same) {
				$("#resume1").text(same?"does":"does not");
				nextstep();
				checksessionid(ports[3], function(same) {
				    $("#resume2").text(same?"does":"does not");
				    nextstep();
				});
			    });
			}
		    });
		});

		/* Display it */
		nextstep();
	    }
	});
    });
}();
