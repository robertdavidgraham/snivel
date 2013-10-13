#include "snivel.h"
#include "unified2-format.h"
#include "mongoose.h"
#include "pixie.h"
#include <time.h>

#ifdef WIN32
#define strtoull _strtoui64
#endif

#ifndef countof
#define countof( array ) ( sizeof( array )/sizeof( array[0] ) )
#endif

/***************************************************************************
 ****************************************************************************/
static void
free_event_queue_item(struct EventQueue *q_item)
{
	unsigned i;

	if (q_item->e.u2_event) {
		free(q_item->e.u2_event);
		q_item->e.u2_event = 0;
	}

	for (i=0; i<sizeof(q_item->e.u2_extra)/sizeof(q_item->e.u2_extra[0]); i++) {
		if (q_item->e.u2_extra[i])
			free(q_item->e.u2_extra[i]);
		q_item->e.u2_extra[i] = 0;
	}
	for (i=0; i<sizeof(q_item->e.u2_packet)/sizeof(q_item->e.u2_packet[0]); i++) {
		if (q_item->e.u2_packet[i])
			free(q_item->e.u2_packet[i]);
		q_item->e.u2_packet[i] = 0;
	}
}

/***************************************************************************
 ****************************************************************************/
void httpd_store_event(struct Snivel *snivel, struct Unified2_Event *e)
{
	struct EventQueue *q_item;
	unsigned index;

	pixie_enter_critical_section(snivel->queue_cs);
	
	/* Grab the index of the next event in the queue. Since the 'head'
	 * index monotonically increases to infinitey, we must use the
	 * 'mod' operator to reduce it to point within the list */
	index = (snivel->queue_head) % snivel->queue_max;

	/* Grab the next queue item that we'll fill in with this event */
	q_item = snivel->queue + index;
	
	/* If the current item has already been used, free it */
	free_event_queue_item(q_item);

	/* Add the event to the current place in the list */
	q_item->e.u2_event = e;
	q_item->id = snivel->queue_head;

	/* Now increment the head index. Remember that the 'head' index 
	 * is endlessly monotonically increasing, and must be truncated
	 * with (queue_head%queue_max) to be used as an index. */
	snivel->queue_head++;

	pixie_leave_critical_section(snivel->queue_cs);
}

void httpd_store_extra(struct Snivel *snivel, struct Unified2_ExtraData *e)
{
	struct EventQueue *q_item;
	unsigned index;
	uint64_t h;
	unsigned i;

	pixie_enter_critical_section(snivel->queue_cs);

	/*
	 * Look backwards a few events in the event queue in order to
	 * see if we can found a matching event 
	 */
	for (h=0; h<16; h++) {
		index = (snivel->queue_head - h) % snivel->queue_max;
		q_item = &snivel->queue[index];

		/* don't go past the start of the list if there are fewer
		 * than 16 elements */
		if ((snivel->queue_head - h) == 0) {
			h = 16;
			break;
		}

		if (q_item->e.u2_event == NULL) {
			h = 16;
			break;
		}

		if (q_item->e.u2_event->sensor_id == e->event_id.sensor_id
			&& q_item->e.u2_event->event_number == e->event_id.event_number
			&& q_item->e.u2_event->event_second == e->event_id.event_second)
			break;
	}
	if (h >= 16) {
		/* not found */
		fprintf(stderr, "store_extra: matching event not found\n");
		free(e);
		goto end;
	}

	/*
	 * Now add this to the list
	 */
	for (i=0; i<countof(q_item->e.u2_extra); i++) {
		if (q_item->e.u2_extra[i] == NULL) {
			q_item->e.u2_extra[i] = e;
		}
	}
	if (i >= countof(q_item->e.u2_extra)) {
		fprintf(stderr, "store_extra: array full\n");
		free(e);
	}
end:
	pixie_leave_critical_section(snivel->queue_cs);
}

void httpd_store_packet(struct Snivel *snivel, struct Unified2_Packet *e)
{
	struct EventQueue *q_item;
	unsigned index;
	uint64_t h;
	unsigned i;

	pixie_enter_critical_section(snivel->queue_cs);
	
	/*
	 * Look backwards a few events in the event queue in order to
	 * see if we can found a matching event 
	 */
	for (h=0; h<16; h++) {
		index = (snivel->queue_head - h) % snivel->queue_max;
		q_item = &snivel->queue[index];

		/* don't go past the start of the list if there are fewer
		 * than 16 elements */
		if ((snivel->queue_head - h) == 0) {
			h = 16;
			break;
		}

		if (q_item->e.u2_event == NULL) {
			h = 16;
			break;
		}

		if (q_item->e.u2_event->sensor_id == e->event_id.sensor_id
			&& q_item->e.u2_event->event_number == e->event_id.event_number
			&& q_item->e.u2_event->event_second == e->event_id.event_second)
			break;
	}
	if (h >= 16) {
		/* not found */
		fprintf(stderr, "store_packet: matching event not found\n");
		free(e);
		goto end;
	}

	/*
	 * Now add this to the list
	 */
	for (i=0; i<countof(q_item->e.u2_packet); i++) {
		if (q_item->e.u2_packet[i] == NULL) {
			q_item->e.u2_packet[i] = e;
		}
	}
	if (i >= countof(q_item->e.u2_packet)) {
		fprintf(stderr, "store_packet: array full\n");
		free(e);
	}

end:
	pixie_leave_critical_section(snivel->queue_cs);
}


/***************************************************************************
 ****************************************************************************/
static void
xml_format_unified2_event(struct mg_connection *conn, struct Unified2_Event *e, uint64_t id, const struct Snivel *snivel)
{
	char buf[64];
	const char *msg;

	/* Format the 64-bit 'id' field ourselves rather than deal with the
	 * portability issues with 'sprintf()' */
	if (id == 0)
		strcpy(buf, "0");
	else {
		buf[0] = '\0';
		while (id) {
			memmove(buf+1, buf, strlen(buf)+1);
			buf[0] = (id%10) + '0';
			id /= 10;
		}
	}
	

	mg_printf(conn, "<EVENT ID=\"%s\">\r\n", buf);
    mg_printf(conn, " <SENSORID>%u</SENSORID>\r\n", e->sensor_id);
    mg_printf(conn, " <EVENTID>%u</EVENTID>\r\n", e->event_number);

	/* Format timestamp */
	{
		struct tm *mytm;
		time_t t = e->event_second;
		mytm = gmtime(&t);
		/* Mon, 25 Dec 1995 13:30:00 GMT */
		strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", mytm);
		snprintf(buf+strlen(buf), sizeof(buf)-strlen(buf), ".%06u", e->event_microsecond);
	    mg_printf(conn, " <TIME>%s</TIME>\r\n", buf);
	}

	msg = conf_sid_lookup_msg(snivel, e->generator_id, e->signature_id);
	if (msg == NULL) {
		msg = buf;
		snprintf(buf, sizeof(buf), "(%u:%u:%u)", e->generator_id, e->signature_id, e->signature_revision);
	}
    mg_printf(conn, " <MSG>%s</MSG>\r\n", msg);

    mg_printf(conn, " <SID>%u</SID>\r\n", e->signature_id);
    mg_printf(conn, " <GID>%u</GID>\r\n", e->generator_id);
    mg_printf(conn, " <REV>%u</REV>\r\n", e->signature_revision);
    mg_printf(conn, " <CLASSIFICATION>%u</CLASSIFICATION>\r\n", e->classification_id);
    mg_printf(conn, " <PRIORITY>%u</PRIORITY>\r\n", e->priority_id);
	if (e->ip_version == 4) {
		snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
			e->ip_source[0], e->ip_source[1], e->ip_source[2], e->ip_source[3]);
		mg_printf(conn, " <IPSRC>%s</IPSRC>\r\n", buf);
		snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
			e->ip_destination[0], e->ip_destination[1], e->ip_destination[2], e->ip_destination[3]);
		mg_printf(conn, " <IPDST>%s</IPDST>\r\n", buf);
	} else if (e->ip_version == 6) {
		format_ipv6_address(buf, sizeof(buf), e->ip_source);
		mg_printf(conn, " <IPSRC>%s</IPSRC>\r\n", buf);
		format_ipv6_address(buf, sizeof(buf), e->ip_destination);
		mg_printf(conn, " <IPDST>%s</IPDST>\r\n", buf);
	}
    mg_printf(conn, " <SPORT>%u</SPORT>\r\n", e->sport_itype);
    mg_printf(conn, " <DPORT>%u</DPORT>\r\n", e->dport_icode);
    mg_printf(conn, " <PROTO>%u</PROTO>\r\n", e->protocol);
	if (e->impact_flag)
		mg_printf(conn, " <impact_flag>%u</impact_flag>\r\n", e->impact_flag);
    mg_printf(conn, " <IMPACT>%u</IMPACT>\r\n", e->impact);
	if (e->blocked)
	    mg_printf(conn, " <blocked>%u</blocked>\r\n", e->blocked);
	if (e->mpls_label)
		mg_printf(conn, " <mpls_label>%u</mpls_label>\r\n", e->mpls_label);
	if (e->vlan_id)
		mg_printf(conn, " <vlan_id>%u</vlan_id>\r\n", e->vlan_id);
	if (e->pad)
		mg_printf(conn, " <pad>%u</pad>\r\n", e->pad);

	/*uint8_t		policy_uuid[16];
    uint32_t	user_id;
    uint32_t	web_application_id;
    uint32_t	client_application_id;
    uint32_t	application_protocol_id;
    uint32_t	policyengine_rule_id;
    uint8_t		policyengine_policy_uuid[16];
    uint8_t		interface_ingress_uuid[16];
    uint8_t		interface_egress_uuid[16];
    uint8_t		security_zone_ingress_uuid[16];
    uint8_t		security_zone_egress_uuid[16];*/

	mg_printf(conn, "</EVENT>\r\n");
}


/***************************************************************************
 ****************************************************************************/
#ifdef WIN32
__declspec(dllimport) void __stdcall Sleep(unsigned long dwMilliseconds);
void sleep_ms(unsigned ms)
{
	Sleep(ms);
}
#else
#include <unistd.h>
void sleep_ms(unsigned ms)
{
	usleep(ms*1000);
}
#endif

/***************************************************************************
 ****************************************************************************/
static void
get_events(struct mg_connection *conn, const struct mg_request_info *ri,
		void *user_data)
{
	struct Snivel *snivel = (struct Snivel*)user_data;
	uint64_t min;
	char *text;
	uint64_t max;
	uint64_t index;
	uint64_t latest_index;
	unsigned instance;

	mg_header_printf(conn,
			"HTTP/1.0 200 ok\r\n"
			"Content-Type: text/xml\r\n"
			"Server: snivel/0.1\r\n"
			"Refresh: 10\r\n"
			"\r\n");
	
	mg_printf(conn, "<?xml version=\"1.0\" ?>\r\n");
	//mg_printf(conn, "<?xml-stylesheet href=\"events.css\" title=\"Default style\"?>\r\n");
	mg_printf(conn, "<?xml-stylesheet type=\"text/xsl\" href=\"events.xsl\"?>\r\n");

	/*
	 * Do the 'instance' processing. This is so that the client can detect
	 * when the server restarts. If the client's instance is different than
	 * our instance, then we've restarted, and the client needs to reset
	 * it's index back to zero.
	 */
	text = mg_get_var(conn, "instance");
	if (text != NULL) {
		instance = strtoul(text,0,0);
		mg_free_var(text);

		/* Wrong instance, so return empty list. Client should take the
		 * hint and reset its instance ID */
		if (instance != snivel->httpd.instance) {
			mg_printf(conn, "<EVENTS instance=\"%u\">\r\n", snivel->httpd.instance);
			mg_printf(conn, "</EVENTS>\r\n");
		}
	}

	/*
	 * Do the 'latest' processing. If the client already has the latest
	 * data, then don't return immediately. Instead, hold the socket open
	 * for a while waiting for new events to arrive. This reduces latency to zero,
	 * because as soon as a new event arrives, we'll stop waiting, and the
	 * event will appear in the console. It also reduces network traffic: instead
	 * of querying for new data every second, the client only queries once every
	 * minute.
	 */
	text = mg_get_var(conn, "latest");
	if (text != NULL) {
		unsigned i;
		latest_index = strtoull(text,0,0);
		mg_free_var(text);

		/* Wait for up to 10 seconds */
		for (i=0; i<1000; i++) {
			if (latest_index <= snivel->queue_head)
				break;
			else
				sleep_ms(10); /* sleep for 10 milliseconds */
		}

		/* If no latest event, return an empty list */
		if (i >= 1000) {
			mg_printf(conn, "<EVENTS instance=\"%u\">\r\n", snivel->httpd.instance);
			mg_printf(conn, "</EVENTS>\r\n");
			return;
		}
	}


	/*
	 * If there are no events, then return an empty list 
	 */
	if (snivel->queue_head == 0) {
		mg_printf(conn, "<EVENTS instance=\"%u\">\r\n", snivel->httpd.instance);
		mg_printf(conn, "</EVENTS>\r\n");
		return;
	}

	/*
	 * MAX
	 */
	text = mg_get_var(conn, "max");
	if (text != NULL) {
		max = strtoull(text,0,0);
		if (max > snivel->queue_head)
			max = snivel->queue_head;
		mg_free_var(text);
	} else {
		max = snivel->queue_head;
	}

	/*
	 * MIN
	 */
	text = mg_get_var(conn, "max");
	if (text != NULL) {
		min = strtoull(text,0,0);
		if (min > max)
			min = max;
		else if (max > 64 && min < max - 64)
			min = max - 64;
		mg_free_var(text);
	} else {
		if (max > 64)
			min = max - 64;
		else
			min = 0;
	}


	mg_printf(conn, "<EVENTS instance=\"%u\">\r\n", snivel->httpd.instance);
	pixie_enter_critical_section(snivel->queue_cs);
	for (index=max; index>min; index--) {
		struct EventQueue *q_item;
		q_item = &snivel->queue[(index-1)%snivel->queue_max];

		if (q_item->e.u2_event) {
			xml_format_unified2_event(conn, q_item->e.u2_event, q_item->id, snivel);
		}
	}
	pixie_leave_critical_section(snivel->queue_cs);
	mg_printf(conn, "</EVENTS>\r\n");
}



/***************************************************************************
 ****************************************************************************/
void
httpd_init(struct Snivel *snivel)
{
	struct mg_context *mongoose_ctx;
	char listen_port[16];
	char listen_ip[64];

	/* Set up the mutex to protect structure from HTTPD threads */
	snivel->queue_cs = pixie_initialize_critical_section();

	/* Set the "instance" id on startup. The JavaScript client uses this
	 * in order to detect server restarts. We shouldn't restart the server
	 * within 1-second (since we use time(0)) or the client will get
	 * confused */
	snivel->httpd.instance = (unsigned)time(0);

	snivel->queue_max = 8192;
	snivel->queue = (struct EventQueue *)malloc(snivel->queue_max * sizeof(*snivel->queue));
	memset(snivel->queue, 0, snivel->queue_max * sizeof(*snivel->queue));
	snivel->queue_head = 0;
	

	snprintf(listen_port, sizeof(listen_port), "%u", snivel->httpd.port);
	snprintf(listen_ip, sizeof(listen_ip), "%u.%u.%u.%u", 
		(snivel->httpd.ip_address>>24)&0xFF,
		(snivel->httpd.ip_address>>16)&0xFF,
		(snivel->httpd.ip_address>> 8)&0xFF,
		(snivel->httpd.ip_address>> 0)&0xFF
		);


	/*
	 * Start the web server
	 */
	mongoose_ctx = mg_start();


	mg_set_option(mongoose_ctx, "ip", listen_ip);
	mg_set_option(mongoose_ctx, "ports", listen_port);

	mg_bind_to_uri(mongoose_ctx, "/events.xml", &get_events, snivel);
	

	{
		const char *val1 = mg_get_option(mongoose_ctx, "ip");
		const char *val2 = mg_get_option(mongoose_ctx, "ports");
		fprintf(stderr, "Snivel web server: http://%s:%s\n", val1, val2);
	}

}
