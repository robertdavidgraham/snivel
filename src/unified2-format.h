#ifndef UNIFIED2_FORMAT_H
#define UNIFIED2_FORMAT_H
#include <stdint.h>
/*
	Unified2

	RECORD HEADER

	The file consists of a series of TLV encoded records. Each record starts
	with a "type" (Unified2_RecordType) followed by a "length" of the remainder
	of the data within the record.

	If the "type" of the record is unknown, readers SHOULD skip the record
	and continue reading the next record.  Readers MAY output a warning 
	message indicating that the "type" is unknown.

	EVENT ID

	An event can generate multiple records. There will be one record for the 
	event itself, anotehr for the packets associated with the event, and
	additional "extra" data events containing such things as URLs or e-mail
	addresses.

	All records assocated with an event will have the same "event ID"
	consisting of:
	1. The unique ID of the sensor. If the user has only one sensor, this
	will usually be '0'.
	2. The event number, a monotonically increasing 32-bit number. After
	4-billion events, this number will wrap.
	3. A timestamp, in seconds. It is assumed that the sensor cannot produce
	more than 4-billion events-per-second.

	The reader SHOULD expect that such events can appear in any order. The
	reader SHOULD expect that events can be interleaved, that additional records
	with the same event_id can appear many seconds later in the file.

	For example, the sensor may trigger on an event within the URL, but
	only many seconds later (after other events have appeared in the file)
	will the full headers be avaible and included in the event.

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


*/


/***************************************************************************
 ****************************************************************************/
enum Unified2_RecordType {
	UNIFIED2_PACKET					= 2,
	UNIFIED2_IPV4_EVENT1			= 7,
	UNIFIED2_IPV6_EVENT1			= 72,
	UNIFIED2_IPV4_EVENT2			= 104,
	UNIFIED2_IPV6_EVENT2			= 105,
	UNIFIED2_EXTRA_DATA				= 110,
	UNIFIED2_IPV4_EVENT3			= 207, /* NGFW */
	UNIFIED2_IPV6_EVENT3			= 208, /* NGFW */
};
struct Unified2_Header
{
    enum Unified2_RecordType	type;
    uint32_t					length;
};

/***************************************************************************
 ****************************************************************************/
struct Unified2_EventID
{
    uint32_t	sensor_id;
    uint32_t	event_number;
    uint32_t	event_second;
};


/***************************************************************************
 ****************************************************************************/


/* type = 7 (UNIFIED2_IPV4_EVENT1) */
struct Unified2_IPv4_Event1
{
	struct Unified2_EventID event_id;

    uint32_t	event_microsecond;
    uint32_t	signature_id;
    uint32_t	generator_id;
    uint32_t	signature_revision;
    uint32_t	classification_id;
    uint32_t	priority_id;
    uint8_t		ip_source[4];
    uint8_t		ip_destination[4];
    uint16_t	sport_itype;
    uint16_t	dport_icode;
    uint8_t		protocol;
    uint8_t		impact_flag;
    uint8_t		impact;
    uint8_t		blocked;
};


/* type = 104 (UNIFIED2_IPV4_EVENT2) */
struct Unified2_IPv4_Event2
{
	struct Unified2_IPv4_Event1 event1;

    uint32_t mpls_label;
    uint16_t vlan_id;
    uint16_t pad;
};

/* type = 207 (UNIFIED2_IPV4_EVENT3) */
struct Unified2_IPv4_Event3
{
	struct Unified2_IPv4_Event2 uevent2;

    uint8_t		policy_uuid[16];
    uint32_t	user_id;
    uint32_t	web_application_id;
    uint32_t	client_application_id;
    uint32_t	application_protocol_id;
    uint32_t	policyengine_rule_id;
    uint8_t		policyengine_policy_uuid[16];
    uint8_t		interface_ingress_uuid[16];
    uint8_t		interface_egress_uuid[16];
    uint8_t		security_zone_ingress_uuid[16];
    uint8_t		security_zone_egress_uuid[16];
};

/* type = 72 (UNIFIED2_IPV6_EVENT1) */
struct Unified2_IPv6_Event1
{
	struct Unified2_EventID event_id;

    uint32_t	event_microsecond;
    uint32_t	signature_id;
    uint32_t	generator_id;
    uint32_t	signature_revision;
    uint32_t	classification_id;
    uint32_t	priority_id;
    uint8_t		ip_source[16];
    uint8_t		ip_destination[16];
    uint16_t	sport_itype;
    uint16_t	dport_icode;
    uint8_t		protocol;
    uint8_t		impact_flag;
    uint8_t		impact;
    uint8_t		blocked;
};

/* type = 105 (UNIFIED2_IPV6_EVENT2) */
struct Unified2_IPv6_Event2
{
	struct Unified2_IPv6_Event1 event1;

    uint32_t	mpls_label;
    uint16_t	vlan_id;
    uint16_t	pad;
};

/* type = 208 (UNIFIED2_IPV6_EVENT3) */
struct Unified2_IPv6_Event3
{
	struct Unified2_IPv6_Event2 event2;

    uint8_t		policy_uuid[16];
    uint32_t	user_id;
    uint32_t	web_application_id;
    uint32_t	client_application_id;
    uint32_t	application_protocol_id;
    uint32_t	policyengine_rule_id;
    uint8_t		policyengine_policy_uuid[16];
    uint8_t		interface_ingress_uuid[16];
    uint8_t		interface_egress_uuid[16];
    uint8_t		security_zone_ingress_uuid[16];
    uint8_t		security_zone_egress_uuid[16];
};




/***************************************************************************
 ****************************************************************************/
/* type = 2 (UNIFIED2_PACKET) */
struct Unified2_Packet
{
	struct Unified2_EventID event_id;

    uint32_t	packet_second;
    uint32_t	packet_microsecond;
    uint32_t	linktype;
    uint32_t	packet_length;
    uint8_t		packet_data[1]; /*length = packet_length */
};


/***************************************************************************
 ****************************************************************************/
/*
http://blog.snort.org/2011/09/snort-291-http-and-smtp-logging.html
Type 1: True-Client-IP/XFF IPv4 address
Type 2: True-Client-IP/XFF IPv6 address
Type 4: HTTP Gzip decompressed data
Type 5: SMTP filename
Type 6: SMTP MAIL FROM addresses
Type 7: SMTP RCPT TO addresses
Type 8: SMTP Email headers
Type 9: HTTP Request URI
Type 10: HTTP Request Hostname
Type 11: Packet's IPv6 Source IP Address
Type 12: Packet's IPv6 Destination IP Address
*/
enum Unified2_InfoType
{
    EVENT_INFO_XFF_IPV4			= 1, /* blob size = 4 */
    EVENT_INFO_XFF_IPV6			= 2, /* blob size = 16 */
    EVENT_INFO_REVIEWED_BY		= 3,
    EVENT_INFO_GZIP_DATA		= 4,
    EVENT_INFO_SMTP_FILENAME	= 5,
    EVENT_INFO_SMTP_MAILFROM	= 6,
    EVENT_INFO_SMTP_RCPTTO		= 7,
    EVENT_INFO_SMTP_EMAIL_HDRS	= 8,
    EVENT_INFO_HTTP_URI			= 9,
    EVENT_INFO_HTTP_HOSTNAME	= 10, /* blob size < 256 */
    EVENT_INFO_IPV6_SRC			= 11, /* blob size = 16 */
    EVENT_INFO_IPV6_DST			= 12, /* blog size = 16 */
    EVENT_INFO_JSNORM_DATA		= 13, /* http://blog.snort.org/2012/01/snort-2920-javascript-normalization.html */
};

enum Unified2_BlobType
{
    EVENT_DATA_TYPE_BLOB		= 1,
};

enum Unified2_ExtraType {
	EVENT_TYPE_EXTRA_DATA		= 4,
};

/* type  = 110 (UNIFIED2_EXTRA_DATA) */
struct Unified2_ExtraData
{
    enum Unified2_ExtraType			event_type;
    uint32_t						event_length;		/* Length of remainder + 8, or the same value as the record header */

	struct Unified2_EventID			event_id;

	enum Unified2_InfoType			info_type;
	enum Unified2_BlobType			blob_type;
    uint32_t						blob_length;		/* Length of the data + 8*/
	uint8_t							blob_data[1];		/* length = blob_length - 8, or event_length - 32 */
};


/***************************************************************************
 The following structure is a useful "internal" superset of the other
 event data structures. This is not an "external" structure found
 in Unified2 files.
 ****************************************************************************/
struct Unified2_Event
{
	uint32_t	type;
	uint16_t	ip_version; /* 4 or 6 */
	uint16_t	event_version; /* 1, 2, 3 */

    uint32_t	sensor_id;
    uint32_t	event_number;
    uint32_t	event_second;

	/* version 1 of the event structure */
    uint32_t	event_microsecond;
    uint32_t	signature_id;
    uint32_t	generator_id;
    uint32_t	signature_revision;
    uint32_t	classification_id;
    uint32_t	priority_id;
    uint8_t		ip_source[16];
    uint8_t		ip_destination[16];
    uint16_t	sport_itype;
    uint16_t	dport_icode;
    uint8_t		protocol;
    uint8_t		impact_flag;
    uint8_t		impact;
    uint8_t		blocked;

	/* added in version 2 "VLAN"*/
    uint32_t	mpls_label;
    uint16_t	vlan_id;
    uint16_t	pad;

	/* added in version 3 "NGFW" */
    uint8_t		policy_uuid[16];
    uint32_t	user_id;
    uint32_t	web_application_id;
    uint32_t	client_application_id;
    uint32_t	application_protocol_id;
    uint32_t	policyengine_rule_id;
    uint8_t		policyengine_policy_uuid[16];
    uint8_t		interface_ingress_uuid[16];
    uint8_t		interface_egress_uuid[16];
    uint8_t		security_zone_ingress_uuid[16];
    uint8_t		security_zone_egress_uuid[16];
};


#endif


