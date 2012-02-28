var xmlhttp = null;
var latest = 0;
var waiting_for_events = false;

function refresh_xml(url, handle_response)
{
    if (xmlhttp == NULL) {
	    if (window.XMLHttpRequest) {
		    // code for IE7, Firefox, Mozilla, etc.
		    xmlhttp=new XMLHttpRequest();
	    } else if (window.ActiveXObject) {
		    // code for IE5, IE6
		    xmlhttp=new ActiveXObject("Microsoft.XMLHTTP");
	    }  
    }

	if (xmlhttp != null) {
		xmlhttp.onreadystatechange = handle_response;
		xmlhttp.open("GET",url,true);
		xmlhttp.send(null);
	}

}


function refresh()
{
    if (waiting_for_events == false) {
        waiting_for_events = true;
    	refresh_xml("getevents.xml?latest="+latest, handle_events);
    }
}


function handle_bssid_item()
{
	var update;
	var bases;

	// Wait until we get a reply back from the server		
	if(xmlhttp.readyState != 4) {
        waiting_for_events = false;
		return;
    }

	// Make sure the reply is "HTTP/1.1 200 OK"
	if(xmlhttp.status != 200)  {
        waiting_for_events = false;
		return;
    }

	//
	update = xmlhttp.responseXML.documentElement;
	if (!update) {
		alert("no XML document returned");
        waiting_for_events = false;
		return;
	}
	if (update.nodeName != "events") {
		alert("no EVENTS element");
        waiting_for_events = false;
		return; // corrupt XML contents
	}

	// Get the EVENTS information
	base = update.getElementsByTagName("events")[0];
	events = stationlist.getElementsByTagName("event");

	for (i=0; i<events.length; i++) {
		var e = events[i];
        var row;

        row = document.createElement("div");
        row.setAttribute("id", e.getAttribute("id"));
        row.innertHtml = '<div class="address">'
                        + e.getE

		rowId = sta.getAttribute("id");
		
		// See if the row exists
		table = document.getElementById("eventlist");
		if (!table) {
			alert("No event table");
		}



        if (!table.hasChildNodes()) {
            var item = document.createElement("div");
            item.setAttribute("id", "row_headers");
            item.innerHtml = '<div id="col_src">Source</div><div id="col_dst">Destination</div><div id="col_msg">Msg</div>';
            table.appendChild(item);
        }

        

		if (!table.rows[rowId]) {
			var row;
			var z = rowId;

			try {
			z = sta.getElementsByTagName("macaddr")[0].firstChild.nodeValue;

			table.insertRow(1);
			row = table.rows[1];
			row.innerHTML =
                    '<div id="'+rowId 
						  '<td id="station" class="station"><a href="/station/'+rowId+'.html">'+z+'</a></td>' +
						  '<td id="stamanuf" class="stamanuf"></td>' +
						  '<td id="power" class="power"></td>' +
						  '<td id="dataout" class="dataout"></td>' +
						  '<td id="datain"  class="datain" ></td>' +
						  '<td id="ctrlout" class="ctrlout"></td>' +
						  '<td id="ctrlin"  class="ctrlin" ></td>' +
						  '<td id="info" class="info"></td>'
							;
			} catch (er) {
				alert(er);
			}
			row.id = rowId;
		}

		var changes = 0;

		changes += xml_update_cell("stationlist", "stamanuf", sta);
		changes += xml_update_cell("stationlist", "power", sta);
		changes += xml_update_cell("stationlist", "dataout", sta);
		changes += xml_update_cell("stationlist", "datain", sta);
		changes += xml_update_cell("stationlist", "ctrlout", sta);
		changes += xml_update_cell("stationlist", "ctrlin", sta);
		changes += xml_update_cell("stationlist", "info", sta);
	}


}
