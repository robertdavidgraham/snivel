/***************************************************************************

	SNORT UNIFIED2 EVENT OUTPUT - SPEW FORMAT

	This output formats the Unified2 events in the same format as the
	"u2spew" tool that comes with the Snort distribution.


	Background:

	Snort is a popular open-source "intrusion detection system" (IDS) that
	eavesdros on network traffic looking for signs of hacker activity.
	When it triggers on something suspicious, Snort saves the "event" 
	into a file. The format of these files is known as "Unified2". Other
	tools, such as "Barnyard", read the events from these files and store
	them in a database, then provide Web 2.0 applications that allow
	security analysts to look at the data.

	This file is part of "Snivel", a tool like "Barnyard" that reads these
	files, but instead of doing something complex, Snivel just prints the
	live events the command-line.
 ****************************************************************************/
#include "snivel.h"
#include "unified2-format.h"


/***************************************************************************
 * Just a a normal hexdump, except that the 'spew' format wants 
 * decimal offset numbers rather than the normal hex.
 ****************************************************************************/
static void
hex_dump(FILE *fp, const unsigned char *px, unsigned length)
{
	unsigned i = 0;

	while (i < length) {
		unsigned j;

		fprintf(fp, "[%5u] ", i);

		/* Print hex area */
		for (j=0; j<16 && i+j<length; j++)
			fprintf(fp, "%02X ", px[i+j]);
		
		for ( ; j<16; j++)
			fprintf(fp, "   ");

		/* Print ASCII area */
		for (j=0; j<16 && i+j<length; j++) 
			fprintf(fp, "%c", isprint(px[i+j]) ? px[i+j] : '.');
		
		fprintf(fp, "\n");

		i += j;
	}
}

/****************************************************************************
 * Format an IPv6 address.
 * Example:
 *  3ffe:ffff:101::230:6eff:fe04:d9ff
 * 
 * NOTE: The symbol :: is a special syntax that can be used as a 
 * shorthand way of representing multiple 16-bit groups of 
 * contiguous 0’s (zeros). The :: can appear anywhere in the address; 
 * however it can only appear once in the address.
 *
 ****************************************************************************/
void
format_ipv6_address(char *buf, unsigned sizeof_buf, const void *v_addr)
{
    const unsigned char *px = (const unsigned char *)v_addr;
    unsigned has_elided = 0;
    unsigned buf_offset = 0;
    unsigned i;

    if (sizeof_buf < 41 || v_addr == NULL) {
        if (sizeof_buf > 4) {
            memcpy(buf, "err\0", 4);
        } else if (sizeof_buf > 1)
            buf[0] = '\0';
        else
            ;
        return;
    }


    for (i=0; i<16; i += 2) {
        unsigned num = px[i]<<8 | px[i+1];
        if (num == 0 && !has_elided) {
            buf[buf_offset++] = ':';

            while (i+2 < 16 && (px[i+2]<<8 | px[i+3]) == 0)
                i += 2;

            if (i == 16)
                buf[buf_offset++] = ':';

            has_elided = 1;
        } else {
            if (i != 0)
                buf[buf_offset++] = ':';
            buf[buf_offset++] = "0123456789abcdef"[(px[i+0]>>4)&0xF];
            buf[buf_offset++] = "0123456789abcdef"[(px[i+0]>>0)&0xF];
            buf[buf_offset++] = "0123456789abcdef"[(px[i+1]>>4)&0xF];
            buf[buf_offset++] = "0123456789abcdef"[(px[i+1]>>0)&0xF];
        }
    }
    buf[buf_offset] = '\0';

}

/***************************************************************************
 ****************************************************************************/
static void
format_uuid(const char* label, const uint8_t* data)
{
#ifdef HAVE_LIBUUID
    char buf[37];
    uuid_unparse(data, buf);
    printf("%s: %s\n", label, buf);
#else
    printf("%s: %.*s\n", label, 16, data);
#endif
}

/***************************************************************************
 ****************************************************************************/
void unified2_spew_event(const struct Snivel *snivel, const struct Unified2_Event *e)
{	
	char src[64];
	char dst[64];
	const char *msg;

	msg = conf_sid_lookup_msg(snivel, e->generator_id, e->signature_id);
	if (msg == NULL)
		msg = "";

	/*
	 * Format the addresses
	 */
	if (e->ip_version == 4) {
		_snprintf(dst, sizeof(dst), "%u.%u.%u.%u", 
			e->ip_destination[0], e->ip_destination[1], 
			e->ip_destination[2], e->ip_destination[3]); 
		_snprintf(src, sizeof(src), "%u.%u.%u.%u", 
			e->ip_source[0], e->ip_source[1], 
			e->ip_source[2], e->ip_source[3]);
	} else if (e->ip_version == 6) {
		format_ipv6_address(dst, sizeof(dst), e->ip_destination);
		format_ipv6_address(src, sizeof(src), e->ip_destination);
	} else {
		_snprintf(dst, sizeof(dst), "(err)");
		_snprintf(src, sizeof(src), "(err)");
	}

	/*
	 * Print the event type string
	 */
	switch (e->type) {
	case UNIFIED2_IPV4_EVENT1: printf("\n(Event) %s\n", msg); break;
	case UNIFIED2_IPV4_EVENT2: printf("\n(Event) %s\n", msg); break;
	case UNIFIED2_IPV4_EVENT3: printf("\n(Event NG) %s\n", msg); break;
	case UNIFIED2_IPV6_EVENT1: printf("\n(IPv6 Event) %s\n", msg); break;
	case UNIFIED2_IPV6_EVENT2: printf("\n(IPv6 Event) %s\n", msg); break;
	case UNIFIED2_IPV6_EVENT3: printf("\n(IPv6 NGFW Event)\n", msg); break;
	default: printf("\n(Unknown Event) %s\n", msg); break;
	}

	/* Print common event info */
    printf( "\tsensor id: %u\tevent id: %u\tevent second: %u\tevent microsecond: %u\n"
            "\tsig id: %u\tgen id: %u\trevision: %u\tclassification: %u\n"
            "\tpriority: %u\tip source: %s\tip destination: %s\n"
            "\tsrc port: %u\tdest port: %u\tprotocol: %u\timpact_flag: %u\tblocked: %u\n",
             e->sensor_id, e->event_number,
             e->event_second, e->event_microsecond,
             e->signature_id, e->generator_id,
             e->signature_revision, e->classification_id,
             e->priority_id, src,
             dst, e->sport_itype,
             e->dport_icode, e->protocol,
             e->impact_flag, e->blocked);

	if (e->event_version >= 2) {
		printf("\tmpls label: %u\tvland id: %u\tpolicy id: %u\n",
             e->mpls_label, e->vlan_id, e->pad);
	}

	if (e->event_version >= 3) {
		format_uuid("\tpolicy UUID", e->policy_uuid);

		printf("\tuser id: %u\t web application id: %u\n",
					e->user_id, e->web_application_id);
	    printf("\tclient application id: %u\tapplication protocol id%u\tpolicy engine rule id: %u\n",
            e->client_application_id, e->application_protocol_id, e->policyengine_rule_id);

		format_uuid("\tpolicy engine policy uuid", e->policyengine_policy_uuid);
		format_uuid("\tinterface ingress uuid", e->interface_ingress_uuid);
		format_uuid("\tinterface engress uuid", e->interface_egress_uuid);
	    format_uuid("\tsecurity zone ingress uuid", e->security_zone_ingress_uuid);
		format_uuid("\tsecurity zone egress uuid", e->security_zone_egress_uuid);
	}
}


/***************************************************************************
 ****************************************************************************/
void unified2_spew_packet(const struct Snivel *snivel, const struct Unified2_Packet *e)
{
    printf("\n(Packet)\n"
            "\tsensor id: %u\tevent id: %u\tevent second: %u\n"
            "\tpacket second: %u\tpacket microsecond: %u\n"
            "\tlinktype: %u\tpacket_length: %u\n",
            e->event_id.sensor_id, e->event_id.event_number, e->event_id.event_second,
            e->packet_second, e->packet_microsecond, e->linktype,
            e->packet_length);

    hex_dump(stdout, e->packet_data, e->packet_length);
}


/***************************************************************************
 ****************************************************************************/
static void print_text_buffer(const char *name, const unsigned char *px, unsigned length)
{
	unsigned j = (unsigned)strlen(name);
	unsigned i = 0;
	printf("%s", name);

	while (i<length) {

		for ( ; i<length && j<78; i++, j++) {
			if (px[i] == '\r') {
				printf("\\r");
				j++;
				continue;
			}
			if (px[i] == '\n') {
				printf("\\r");
				j++;
				continue;
			}
			if (px[i] == '\t') {
				printf(" ");
				j++;
				continue;
			}
			if (isprint(px[i]))
				printf("%c", px[i]);
			else
				printf(".");

		}
		j = 0;
		printf("\n");

		if (i<length) {
			printf("    ");
			j += 4;
		}
	}

	if (j != 0)
		printf("\n");
}

/***************************************************************************
 ****************************************************************************/
void unified2_spew_extra(const struct Snivel *snivel, const struct Unified2_ExtraData *e)
{
	const unsigned char *px = &e->blob_data[0];
	char buf[64];


    printf("\n(ExtraDataHdr)\n"
            "\tevent type: %u\tevent length: %u\n",
            e->event_type, e->event_length);

    printf("\n(ExtraData)\n"
            "\tsensor id: %u\tevent id: %u\tevent second: %u\n"
            "\ttype: %u\tdatatype: %u\tbloblength: %u\t",
             e->event_id.sensor_id,		e->event_id.event_number,
             e->event_id.event_second,	e->info_type,
             e->blob_type,				e->blob_length+8);


    switch(e->info_type) {
    case EVENT_INFO_XFF_IPV4:
        printf("Original Client IP: %u.%u.%u.%u\n", px[0], px[1], px[2], px[3]);
        break;

    case EVENT_INFO_XFF_IPV6:
		format_ipv6_address(buf, sizeof(buf), px);
		printf("Original Client IP: %s\n", buf);
        break;

    case EVENT_INFO_IPV6_SRC:
		format_ipv6_address(buf, sizeof(buf), px);
        printf("IPv6 Source Address: %s\n", buf);
        break;

    case EVENT_INFO_IPV6_DST:
		format_ipv6_address(buf, sizeof(buf), px);
        printf("IPv6 Destination Address: %s\n", buf);
        break;

    case EVENT_INFO_GZIP_DATA:
		print_text_buffer("GZIP Decompressed Data: ", px, e->blob_length);
        break;

    case EVENT_INFO_JSNORM_DATA:
		print_text_buffer("Normalized JavaScript Data: ", px, e->blob_length);
        break;

    case EVENT_INFO_SMTP_FILENAME:
		print_text_buffer("SMTP Attachment Filename: ", px, e->blob_length);
        break;

    case EVENT_INFO_SMTP_MAILFROM:
		print_text_buffer("SMTP MAIL FROM Addresses: ", px, e->blob_length);
        break;

    case EVENT_INFO_SMTP_RCPTTO:
		print_text_buffer("SMTP RCPT TO Addresses: ", px, e->blob_length);
        break;

    case EVENT_INFO_SMTP_EMAIL_HDRS:
		/* todo: should actually print the new-lines in the headers
		 * so that they are pretty */
		print_text_buffer("SMTP EMAIL HEADERS: ", px, e->blob_length);
        break;

    case EVENT_INFO_HTTP_URI:
		/* todo: should re-normalize the URL, decoding characters that shouldn't
		 * have the %xx encoding, and encoding binary characters */
		print_text_buffer("HTTP URI: ", px, e->blob_length);
        break;

    case EVENT_INFO_HTTP_HOSTNAME:
		print_text_buffer("HTTP Hostname: ", px, e->blob_length);
		break;
    default :
		print_text_buffer("(UNKNOWN DATA): ", px, e->blob_length);
		break;
    }


}
