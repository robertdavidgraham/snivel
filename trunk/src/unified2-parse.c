/***************************************************************************

	SNORT UNIFIED2 EVENT PARSER

	This module parses the external format of Snort Unified2 records
	into internal data structures.

	There are three data structures:
	1. events
	2. extra event data
	3. packets

	There are multiple (so far 6) external formats for event records,
	but the internal record used is a just a superset of them all. Some
	records use IPv4 addresses, others use IPv6. Some records have
	VLAN/MPLS info, some don't. Some records ahve NGFW policy info,
	some don't. We just use one big internal record to store all the
	info regardless of the external event record.




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
 * Extract a 32-bit file in "network byte order" and convert it into
 * internal order. If there is not enough data left to extract, this
 * will return zero. Moves the "offset" forward in the data stream.
 ****************************************************************************/
static unsigned
parse_uint32(const unsigned char *px, unsigned *r_offset, unsigned length)
{
	unsigned i = *r_offset;

	if (*r_offset + 3 >= length) {
		*r_offset = length+1;
		return 0;
	}
	*r_offset += 4;

	return px[i+0]<<24 | px[i+1]<<16 | px[i+2]<<8 | px[i+3];
}

/***************************************************************************
 * Sames as parse_uint32(), except for 16-bits
 ****************************************************************************/
static unsigned short
parse_uint16(const unsigned char *px, unsigned *r_offset, unsigned length)
{
	unsigned i = *r_offset;

	if (*r_offset + 1 >= length) {
		*r_offset = length+1;
		return 0;
	}
	*r_offset += 2;

	return px[i+0]<<8 | px[i+1];
}

/***************************************************************************
 * Sames as parse_uint32(), except for 8-bits
 ****************************************************************************/
unsigned char
parse_uint8(const unsigned char *px, unsigned *r_offset, unsigned length)
{
	unsigned i = *r_offset;

	if (*r_offset  >= length) {
		*r_offset = length+1;
		return 0;
	}
	*r_offset += 1;

	return px[i+0];
}

/***************************************************************************
 * Safely copies a buffer from an external source to an internal data
 * structure. This moves the "offset" forward the number of bytes
 * extracted.
 ****************************************************************************/
static void
parse_copy(void *dst, size_t sizeof_dst, unsigned bytes_to_copy, const unsigned char *px, unsigned *r_offset, unsigned length)
{
	unsigned i=0;

	while (i < bytes_to_copy && i < sizeof_dst && i+*r_offset < length) {
		unsigned char *dst2 = (unsigned char *)dst;
		dst2[i] = px[*r_offset + i];
		i++;
	}

	if (i < bytes_to_copy) {
		/* error. Signal the error by moving the offset past the maximum
		 * length */
		*r_offset = length+1;
	} else
		*r_offset += i;
}


/***************************************************************************
 * Parse all 6 Unified2 event formats, including those with/without
 * VLAN and NGFW data, regardless of IPv4 or IPv6.
 ****************************************************************************/
int
unified2_parse_event(struct Unified2_Event *e, unsigned type, const unsigned char *px, unsigned length)
{
	unsigned offset = 0;

	e->type = type;

	/* Find IP version */
	switch (type) {
	case UNIFIED2_IPV4_EVENT1:	/* type = 7 */
	case UNIFIED2_IPV4_EVENT2:	/* type = 104 */
	case UNIFIED2_IPV4_EVENT3:	/* type = 207 */
		e->ip_version = 4;
		break;
	case UNIFIED2_IPV6_EVENT1:	/* type = 72 */
	case UNIFIED2_IPV6_EVENT2:	/* type = 105 */
	case UNIFIED2_IPV6_EVENT3:	/* type = 208 */
		e->ip_version = 6;
		break;
	case UNIFIED2_PACKET:		/* type = 2 */
	case UNIFIED2_EXTRA_DATA:	/* type = 110 */
	default:
		e->ip_version = -1; /* error */
		break;
	}

	/* Find Event version */
	switch (type) {
	case UNIFIED2_IPV4_EVENT1:	/* type = 7 */
	case UNIFIED2_IPV6_EVENT1:	/* type = 72 */
		e->event_version = 1;
		break;
	case UNIFIED2_IPV4_EVENT2:	/* type = 104 */
	case UNIFIED2_IPV6_EVENT2:	/* type = 105 */
		e->event_version = 2;
		break;
	case UNIFIED2_IPV4_EVENT3:	/* type = 207 */
	case UNIFIED2_IPV6_EVENT3:	/* type = 208 */
		e->event_version = 3;
		break;
	case UNIFIED2_PACKET:		/* type = 2 */
	case UNIFIED2_EXTRA_DATA:	/* type = 110 */
	default:
		e->event_version = -1; /* error */
		break;
	}

    e->sensor_id			= parse_uint32(px, &offset, length);
    e->event_number			= parse_uint32(px, &offset, length);
    e->event_second			= parse_uint32(px, &offset, length);
    e->event_microsecond	= parse_uint32(px, &offset, length);
    e->signature_id			= parse_uint32(px, &offset, length);
    e->generator_id			= parse_uint32(px, &offset, length);
    e->signature_revision	= parse_uint32(px, &offset, length);
    e->classification_id	= parse_uint32(px, &offset, length);
    e->priority_id			= parse_uint32(px, &offset, length);

	if (e->ip_version == 4) {
		parse_copy(e->ip_source, sizeof(e->ip_source), 4, px, &offset, length);
		parse_copy(e->ip_destination, sizeof(e->ip_destination), 4, px, &offset, length);
	} else if (e->ip_version == 6) {
		parse_copy(e->ip_source, sizeof(e->ip_source), 4, px, &offset, length);
		parse_copy(e->ip_destination, sizeof(e->ip_destination), 4, px, &offset, length);
	}

    e->sport_itype			= parse_uint16(px, &offset, length);
    e->dport_icode			= parse_uint16(px, &offset, length);
    e->protocol				= parse_uint8(px, &offset, length);
    e->impact_flag			= parse_uint8(px, &offset, length);
    e->impact				= parse_uint8(px, &offset, length);
    e->blocked				= parse_uint8(px, &offset, length);

	if (e->event_version >= 2) {
		e->mpls_label			= parse_uint32(px, &offset, length);
		e->vlan_id				= parse_uint16(px, &offset, length);
		e->pad					= parse_uint16(px, &offset, length);
	}

	if (e->event_version >= 3) {
		parse_copy(e->policy_uuid,              sizeof(e->policy_uuid),               16, px, &offset, length);
		e->user_id					= parse_uint32(px, &offset, length);
		e->web_application_id		= parse_uint32(px, &offset, length);
		e->client_application_id	= parse_uint32(px, &offset, length);
		e->application_protocol_id	= parse_uint32(px, &offset, length);
		e->policyengine_rule_id		= parse_uint32(px, &offset, length);
		parse_copy(e->policyengine_policy_uuid,  sizeof(e->policyengine_policy_uuid),  16, px, &offset, length);
		parse_copy(e->interface_ingress_uuid,    sizeof(e->interface_ingress_uuid),    16, px, &offset, length);
		parse_copy(e->interface_egress_uuid,     sizeof(e->interface_egress_uuid),     16, px, &offset, length);
		parse_copy(e->security_zone_ingress_uuid,sizeof(e->security_zone_ingress_uuid),16, px, &offset, length);
		parse_copy(e->security_zone_egress_uuid, sizeof(e->security_zone_egress_uuid), 16, px, &offset, length);
	}
	return offset <= length;
}

/***************************************************************************
 * Parse a record structure holdinga packet.
 ****************************************************************************/
int
unified2_parse_packet(struct Unified2_Packet *e, unsigned type, const unsigned char *px, unsigned length)
{
	unsigned offset = 0;

    e->event_id.sensor_id		= parse_uint32(px, &offset, length);
    e->event_id.event_number	= parse_uint32(px, &offset, length);
    e->event_id.event_second	= parse_uint32(px, &offset, length);
    e->packet_second			= parse_uint32(px, &offset, length);
    e->packet_microsecond		= parse_uint32(px, &offset, length);
    e->linktype					= parse_uint32(px, &offset, length);
    e->packet_length			= parse_uint32(px, &offset, length);

	/* Prevent buffer-overflow from an invalid length field */
	if (e->packet_length > length-offset) {
		fprintf(stderr, "parse_event_packet: invalid length\n");
		e->packet_length = length-offset;
	}

	memcpy(e->packet_data, px+offset, e->packet_length);
	
	return offset <= length;
}

/***************************************************************************
 * Parse an extra data record and its associated blob of data
 ****************************************************************************/
int
unified2_parse_extra(struct Unified2_ExtraData *e, unsigned type, const unsigned char *px, unsigned length)
{
	unsigned offset = 0;

	e->event_type				= parse_uint32(px, &offset, length);
	e->event_length				= parse_uint32(px, &offset, length);
	if (e->event_length != length) {
		fprintf(stderr, "invalid extra event_length, saw [%u], expected [%u]\n", e->event_length, length);
		return 0;
	}

    e->event_id.sensor_id		= parse_uint32(px, &offset, length);
    e->event_id.event_number	= parse_uint32(px, &offset, length);
    e->event_id.event_second	= parse_uint32(px, &offset, length);
    

    e->info_type				= parse_uint32(px, &offset, length);
    e->blob_type				= parse_uint32(px, &offset, length);
    e->blob_length				= parse_uint32(px, &offset, length);
	if (e->blob_length < 8) {
		fprintf(stderr, "invalid extra blob_length, saw [%u], expected at least [8]\n", e->blob_length);
		return 0;
	} else
		e->blob_length -= 8;

	if (e->blob_length > length-offset) {
		fprintf(stderr, "invalid extra blob_length, saw [%u], expected nore more than [%u]\n", e->blob_length, length-offset);
		e->blob_length = length-offset;
	}

	memcpy(e->blob_data, px+offset, e->blob_length);
	return offset <= length;
}
