/***************************************************************************
	SNIVEL - a live viewer for snort events

	Snivel processes Snort Unified2 files and prints the events to the
	command-line.

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
#ifndef SNIVEL_H
#define SNIVEL_H
#ifdef __cplusplus
extern "C" {
#endif
#ifdef WIN32
#define _CRT_SECURE_NO_WARNINGS 1
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <stdint.h>


/***************************************************************************
 * REFERENCES and CLASSIFICATIONS
 * 
 * Stores records from "classification.config":
 *		config classification: not-suspicious,Not Suspicious Traffic,3
 *		config classification: unknown,Unknown Traffic,3
 *		config classification: bad-unknown,Potentially Bad Traffic, 2
 *		...
 *
 * Stores records from "reference.config":
 *		config reference: bugtraq   http://www.securityfocus.com/bid/ 
 *		config reference: cve       http://cve.mitre.org/cgi-bin/cvename.cgi?name=
 *		config reference: arachNIDS http://www.whitehats.com/info/IDS
 *		...
 ****************************************************************************/
struct NameValue
{
	char *name;
	char *value;
	unsigned num;
};
struct NameValues
{
	struct NameValue *elements;
	unsigned count;
	unsigned max;
};


/***************************************************************************
 * SID-MSG-MAP
 * 
 * Stores records from the "sid-msg.map" file:
 *		...
 *		4984 || SQL sa brute force failed login unicode attempt || bugtraq,4797 || cve,2000-1209 || nessus,10673
 *		4985 || WEB-MISC Twiki rdiff rev command injection attempt || bugtraq,14834 || cve,2005-2877
 *		4986 || WEB-MISC Twiki view rev command injection attempt || bugtraq,14834 || cve,2005-2877
 *		...
 * In addition, these records are also found by parsing the ".rules" files. 
 ****************************************************************************/
struct MapElement
{
	unsigned gid;
	unsigned sid;
	char *msg;
};

struct MsgMap
{
	struct MapElement *elements;
	unsigned count;
	unsigned max;
};

/***************************************************************************
 ****************************************************************************/
struct Logfile {
	int type;
	char *filename;
	unsigned limit;
	unsigned nostamp:1;
	unsigned mpls_event_types:1;
	unsigned vlan_event_types:1;
};


/***************************************************************************
 * The full 'event', including associated packets and extra data. We limit
 * this to 8 addition 'extra data' structures and 8 additional 'packet'
 * structures.
 ****************************************************************************/
struct EventQEvent 
{
	struct Unified2_Event *u2_event;
	struct Unified2_ExtraData *u2_extra[7];
	struct Unified2_Packet *u2_packet[8];
};

/***************************************************************************
 ****************************************************************************/
struct EventQueue
{
	/** An internal identifier that monotonically increases each time
	 * time that an event is added to the list. This is used by the 
	 * web JavaScript client so that it knows how to ask for the 
	 * "last 10 events" 
	 */
	uint64_t id;

	struct EventQEvent e;
};


/***************************************************************************
 ****************************************************************************/
struct Snivel
{
	/**
	 * A list of logfiles that we are monitoring
	 */
	struct Logfile log[16];
	unsigned log_count;

	/** Whether we are running live in 'tail -f' mode */
	unsigned is_tail:1;

	/** Whether we found the merged.log by reading /etc/snort/snort.conf */
	unsigned is_snort_conf:1;


	/*
	 * When printing events, where to print them. This will be <stdout>
	 * when printing events to the command-line.
	 */
	FILE *out_fp;

	struct NameValues refs;
	struct NameValues classifications;
	struct NameValues vars;

	struct MsgMap msg_map;

	/**
	 * The name of the directory where logging information is stored
	 */
	char *logdir;

	/**
	 * [OPTIONAL] Starts an internal web server to retrieve the events
	 * via XML
	 */
	struct {
		unsigned ip_address;
		unsigned port;
		unsigned instance; /* so the client can detect restarts */
		unsigned is_enabled:1;
		void *mongoose_ctx;
	} httpd;

	struct EventQueue *queue;
	unsigned queue_max;
	uint64_t queue_head;
	void *queue_cs;

};


/**
 * Configure which file we are reading.
 */
void conf_set_logfilename(struct Snivel *snivel, const char *filename, size_t filename_length);

/**
 * Read a "snort.conf" file. This ignores any options that aren't needed for
 * Unified2 parsing. Mostly, all this does is find the location of the the
 * "marged.log" file, and determines whether it's a single file or a 
 * directory that we are reading
 */
void conf_read_file(struct Snivel *snivel, const char *filename);

/**
 * Set the default logdir relative to the conf file directory. This is for 
 * Windows, so that if you read "C:\snort\etc\snort.conf", then the 
 * logging directory becomes "C:\snort\etc\..\log\"
 */
void conf_set_relative_logdir(struct Snivel *snivel, const char *filename);

void conf_set_logdir(struct Snivel *snivel, const char *filename, unsigned filename_lenth);

/** 
 * Given a sid/gid from a Unified2 event, lookup the "msg" for the event
 */
const char *conf_sid_lookup_msg(const struct Snivel *snivel, unsigned gid, unsigned sid);

/***************************************************************************
 ****************************************************************************/
int unified2_parse_event(struct Unified2_Event *e, unsigned type, const unsigned char *px, unsigned length);
int unified2_parse_extra(struct Unified2_ExtraData *e, unsigned type, const unsigned char *px, unsigned length);
int unified2_parse_packet(struct Unified2_Packet *e, unsigned type, const unsigned char *px, unsigned length);


/***************************************************************************
 ****************************************************************************/
void unified2_spew_event(const struct Snivel *snivel, const struct Unified2_Event *e);
void unified2_spew_packet(const struct Snivel *snivel, const struct Unified2_Packet *e);
void unified2_spew_extra(const struct Snivel *snivel, const struct Unified2_ExtraData *e);


/***************************************************************************
 ****************************************************************************/
char *find_latest_filename(char *dirname, char *filename);

/***************************************************************************
 * Combines a directory name and filename together.
 * Example:
 *		combine_filename("/var/log/snort", "merged.log");
 * produces:
 *		"/var/log/snort/merged.log"
 * More importantly, it parses the filenames, hadnling things like ".."
 * internally:
 *		combine_filename("c:\snort\etc\..\rules", "web-misc.rules");
 * produces:
 *		"c:/snort/rules/web-misc.rules"
 * Windows handows forward-slashes fine, so all back-slashes are converted
 * to forward slashes.
 ****************************************************************************/
char *combine_filename(const char *dirname, const char *filename);


/***************************************************************************
 * Start a web server that we can use to retrieve events from.
 ****************************************************************************/
void httpd_init(struct Snivel *snivel);


/***************************************************************************
 ****************************************************************************/
void httpd_store_event(struct Snivel *snivel, struct Unified2_Event *e);
void httpd_store_extra(struct Snivel *snivel, struct Unified2_ExtraData *e);
void httpd_store_packet(struct Snivel *snivel, struct Unified2_Packet *e);


/***************************************************************************
 ****************************************************************************/
void format_ipv6_address(char *buf, unsigned sizeof_buf, const void *v_addr);

#ifdef __cplusplus
}
#endif
#endif
