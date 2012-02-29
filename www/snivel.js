var xmlhttp = null;
var latest = 0;
var waiting_for_events = false;

function do_alert()
{
    alert("hello");
}

var t = setTimeout("do_alert()", 1000);

var foo = "bar";

function refresh_xml(url, handle_response)
{
    if (xmlhttp == null) {
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


function refresh_table()
{
    alert("refresh_table()");
    if (waiting_for_events == false) {
        waiting_for_events = true;
    	refresh_xml("getevents.xml?latest="+latest, handle_events);
    }
}

var elementlist = ["PRIORITY", "TIME", "IPSRC", "SPORT", "IPDST", "DPORT", "MSG", "CLASSIFICATION"];

function handle_events()
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
	if (update.nodeName != "EVENTS") {
		alert("no EVENTS element");
        waiting_for_events = false;
		return; // corrupt XML contents
	}

	// Get the EVENTS information
	events = update.getElementsByTagName("EVENT");

    table = document.getElementById("eventlist");

    if (events)
	for (i=0; i<events.length; i++) {
		var e = events[i];
        var row;
        var j;

        row = document.createElement("div");
        row.setAttribute("ID", e.getAttribute("ID"));
        row.setAttribute("class", "event");

        for (j=0; j < elementlist.length; j++) {
            var t = document.createTextNode(e.getElementsByTagName(elementlist[j])[0].firstChild.nodeValue);
            var col = document.createElement("div");
            col.appendChild(t);

            col.setAttribute("class", elementlist[j]);
            
            row.appendChild(col);
        }

        
        if (!table.hasChildNodes()) {
            var item = document.createElement("div");
            item.setAttribute("id", "row_headers");
            item.innerHtml = '<div id="col_src">Source</div><div id="col_dst">Destination</div><div id="col_msg">Msg</div>';
            table.appendChild(item);
            alert(table.length);
            table.appendChild(row);
        } else {
            alert(row.innerHtml);
            table.appendChild(row);
        }

	}

}
