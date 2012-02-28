/*
	SNIVEL - Snort Live Event Viewer

	Snivel monitors Snort Unified2 files, printing events live as they are 
	generated.

	The current version of Snivel is functionally the same as the tool
	"u2spew", except for 2 primary differences.

	1. It also acts live from files (like "tail -f")
	2. The code is a lot clearer about the Unified2 format


	USAGE #1: decode a Unified2 file like "u2spew"
	Example:
		snivel -r /var/log/snort/merged.log

	This is functionally the same as using "u2spew". It reads the named
	file and dumps it to the command-line, using the same format as 
	"u2spew".

	USAGE #2: tail a Unified2 file (live)	
	Example:
		snivel -f -r /var/log/snort/merged.log

	This is the same as the usage example above, except rather than dumping
	the file and quitting the program continues to monitor the file. As new
	events are appended to the file, Snivel will print them to the screen.
	You must use <ctrl-C> in order to exit this mode, because it'll 
	continue to monitor the file forever.


	USAGE #3: read from snort.conf	
	Example:
		snivel -f -c /etc/snort/snort.conf

	Instead of specifying the file to read from, this reads in the Snort
	configuration file. 

	

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
#include <sys/stat.h>




/***************************************************************************
 ****************************************************************************/
struct Record {
    unsigned type;
    unsigned length;
	unsigned max;
    unsigned char *value;
};



/***************************************************************************
 ****************************************************************************/
int 
read_next_record(FILE *fp, struct Record *record)
{
	unsigned char buf[8];
    unsigned bytes_read;

    if (fp == NULL)
		return -1;

    /* check if the log was rotated */
    if (feof(fp)) {
        /* Get next timestamped file? */
        puts("Hit the EOF .. and this is not being handled yet.");
        return -1;
    }

	/*
	 * Read the record header
	 */
    bytes_read = fread(buf, 1, 8, fp);
	if (bytes_read <= 0)
		return -1; /* end of file */
	if (bytes_read != 8) {
        fprintf(stderr, "get_record: (1) Failed to read all of record.");
        fprintf(stderr, "\tRead %u of %u bytes\n", bytes_read, 8);
		return -1;
	}
    record->type = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
    record->length = buf[4]<<24 | buf[5]<<16 | buf[6]<<8 | buf[7];


	if (record->max == 0)
		record->value = (unsigned char *)malloc(record->length);
	else if (record->length > record->max) {
	    record->value = (unsigned char *)realloc(record->value, record->length);
		record->max = record->length;
	}

	/*
	 * Read in the raw record
	 */
    bytes_read = fread(record->value, 1, record->length, fp);
    if (bytes_read != record->length) {
        fprintf(stderr, "get_record: (2) Failed to read all of record data.");
        fprintf(stderr, "\tRead %u of %u bytes\n", bytes_read, record->length);
        return -1;
    }

    return 0;
}




/***************************************************************************
 ****************************************************************************/
#ifdef WIN32
__declspec(dllimport) void __stdcall Sleep(unsigned long dwMilliseconds);
void sleep(unsigned seconds)
{
	Sleep(seconds * 1000);
}
#endif


/***************************************************************************
 * See if there is a newer file than the one that we are processing, when
 * snort is marking log files with timestamps.
 ****************************************************************************/
static int
is_later_file(const struct Snivel *snivel, const char *filename)
{
	const char *filename_number;
	unsigned old_time;
	unsigned new_time;
	char *latest;
	const char *latest_number;

	/* If there aren't file timestamps, then no later file */
	if (snivel->log[0].nostamp)
		return 0;

	/* look for last '.' in "merged.log.00000" */
	filename_number = strrchr(filename, '.');
	if (filename_number == NULL)
		return 0;
	filename_number++;
	if (!isdigit(*filename_number & 0xFF))
		return 0;
	old_time = strtoul(filename_number, 0, 0);

	/* Grab a later filename */
	latest = find_latest_filename(snivel->logdir, snivel->log[0].filename);
	if (latest == NULL)
		return 0;
	latest_number = strrchr(latest, '.');
	if (latest_number == NULL || !isdigit(latest_number[1]&0xFF)) {
		free(latest);
		return 0;
	} else
		latest_number++;
	new_time = strtoul(latest_number, 0, 0);
	free(latest);

	/*
	 * Now return the result
	 */
	return new_time > old_time;
}

/***************************************************************************
 ****************************************************************************/
int
snivel_decode_file(struct Snivel *snivel, const char *filename)
{
    struct Record record;
	FILE *fp;
	int fd;
	unsigned seconds_since_last_event = 0;
	unsigned event_count = 0;

	/*
	 * Open the file. We need both a file pointer for "fprintf()", and a
	 * file descriptor for the setpos functions. The setpos functions
	 * support 64-bit offsets more portably, allowing us to support files
	 * larger than 4-gigabytes.
	 */
    fp = fopen(filename, "rb");
	if (fp == NULL) {
		perror(filename);
		return -1;
	}
	fd = _fileno(fp);

	/*
	 * Initialize the 'record' structure that we read records into
	 */
    memset(&record, 0, sizeof(record));

	/*
	 * Read all records from the  file
	 */
	for (;;) {
		int x;
		fpos_t position;
		struct __stat64 s;

		/*
		 * First, see where we are in the file. If we get a partial record, then
		 * we have the backtrack to this point.
		 */
		x = fgetpos(fp, &position);
		if (x != 0) {
			perror(filename);
			break;
		}

		/*
		 * Now discover if we are behind the maximum
		 */
		x = _fstati64(fd, &s);
		if (x != 0) {
			perror(filename);
			break;
		}

		/*
		 * If we have caught up with the end of the file, the one of several things
		 * needs to happen.
		 * 1. If we are processing a single file, then simply stop processing
		 * 2. If we are tailing a "merged.log", then pause before continuing
		 * 3. If we are tailing multiple "merged.log.0000" (with timestamps on the
		 *    on the end), then occasionally go look to see if the current file
		 *    was closed and a new one was created. If so, then exit out of this
		 *	  loop. The caller will close this file, and then call us again
		 *    with the new file.
		 */
		if (position >= s.st_size) {
			if (snivel->is_tail) {
				sleep(1);
				if (seconds_since_last_event++ > 5) {
					if (is_later_file(snivel, filename))
						break;
				}
				continue;
			} else {
				break;
			}
		}

		/*
		 * Get the next record
		 */
		x = read_next_record(fp, &record);
		if (x != 0) {
			/* we might've gotten a partial record, so try again */
			fsetpos(fp, &position);
			sleep(1);
			continue;
		}
		seconds_since_last_event = 0;
		event_count++;

		/*
		 * Read in the next record, then pring it
		 */
		switch (record.type) {
		case UNIFIED2_IPV4_EVENT1:	/* type = 7 */
		case UNIFIED2_IPV4_EVENT2:	/* type = 104 */
		case UNIFIED2_IPV4_EVENT3:	/* type = 207 */
		case UNIFIED2_IPV6_EVENT1:	/* type = 72 */
		case UNIFIED2_IPV6_EVENT2:	/* type = 105 */
		case UNIFIED2_IPV6_EVENT3:	/* type = 208 */
			{
				struct Unified2_Event *e;
				e = (struct Unified2_Event *)malloc(sizeof(*e));
				unified2_parse_event(e, record.type, record.value, record.length);
				unified2_spew_event(snivel, e);
				if (snivel->httpd.is_enabled)
					httpd_store_event(snivel, e);
				else
					free(e);
			}
			break;
		case UNIFIED2_EXTRA_DATA:
			{
				struct Unified2_ExtraData *e;
				e = (struct Unified2_ExtraData *)malloc(record.length);
				unified2_parse_extra(e, record.type, record.value, record.length);
				//unified2_spew_extra(snivel, e);
				if (snivel->httpd.is_enabled)
					httpd_store_extra(snivel, e);
				else
					free(e);
			}
			break;
		case UNIFIED2_PACKET:
			{
				struct Unified2_Packet *e;
				e = (struct Unified2_Packet *)malloc(record.length);
				unified2_parse_packet(e, record.type, record.value, record.length);
				//unified2_spew_packet(snivel, e);
				if (snivel->httpd.is_enabled)
					httpd_store_packet(snivel, e);
				else
					free(e);
			}
			break;
		default:
			fprintf(stderr, "******************* unknown record type=%u length=%u *************\n",
				record.type, record.length);
			break;
		}

    }

	if (record.value) {
		free(record.value);
	}
	fclose(fp);

    return 0;
}

/****************************************************************************
 * Attempts to parse an IPv4 address out of the input stream.
 * If successful, it returns 'true', moves the 'offset' forward to the next
 * character after the address, and fills in the 'ip' structure.
 * If unsuccessful, it returns 'false', does not change 'offset', but
 * may or may not change some fields in 'ip'.
 ****************************************************************************/
static int
parse_ipv4_address(const char *px, unsigned *offset, unsigned length, unsigned char *address)
{
	unsigned prefix_length = 0;
    unsigned i;
    unsigned j;

	if (offset)
		i = *offset;
	else
		i = 0;

	/* Parse the 4 numbers in an IPv4 address */
    for (j=0; j<4; j++) {
        unsigned num = 0;
        unsigned k;

        /* Each of the 4 numbers must start with a digit */
        if (i>=length || !isdigit(px[i]))
            return 0;

        /* Parse the number */
        for (k=0; k<3 && i+k < length && isdigit(px[i+k]); k++)
            num = num * 10 + (px[i+k]-'0');
        i += k;
        if (num > 255)
            return 0;
        address[j] = (unsigned char)num;
        
        /* Make sure the next character is a dot */
        if (j<3) {
			if (i<length && px[i] == '/') {
				/* Allow truncated addresses, like "10/8" or "192.168/16" */
				while (j<3)
					address[++j] = 0;
			} else if (i>=length || px[i] != '.') {
	            return 0;
			} else
	            i++;
        }
    }

    /* Check for optional CIDR field */
    if (i<length && px[i] == '/') {
        unsigned n = 0;
        
        i++;

        if (i>=length || !isdigit(px[i]))
            return 0;

        n = px[i] - '0';
        i++;

        if (i<length && isdigit(px[i])) {
            n = n * 10 + px[i] - '0';
            i++;
        }

        if (n > 32)
            return 0;
        else
            prefix_length = (unsigned char)n;
    }

	if (offset)
	    *offset = i;
    return 1;
}


/***************************************************************************
 ****************************************************************************/
void
set_httpd(struct Snivel *snivel, const char *arg)
{
	unsigned port = 3333;
	unsigned ipv4_address = 0x7f000001;
	unsigned char addr_buf[4];
	const char *str_port_number;
	const char *str_ip_address = arg;
	unsigned str_ip_length;

	if (strchr(arg, ':')) {
		str_port_number = strchr(arg, ':') + 1;
		str_ip_address = arg;
		str_ip_length = strchr(arg, ':') - arg;
	} else {
		str_port_number = "3333";
		str_ip_address = arg;
		str_ip_length = strlen(arg);
	}

	if (str_ip_length == 0) {
		str_ip_address = "127.0.0.1";
		str_ip_length = strlen(str_ip_address);
	}


	port = strtoul(strchr(arg, ':')+1, 0, 0);
	if (port > 65535) {
		fprintf(stderr, "bad port number: %s\n", str_port_number);
		exit(1);
		return; 
	}
	if (!parse_ipv4_address(str_ip_address, 0, str_ip_length, addr_buf)) {
		fprintf(stderr, "bad httpd IPvr address: %.*s\n", str_ip_length, str_ip_address);
	}
	
	snivel->httpd.ip_address = addr_buf[0]<<24 | addr_buf[1]<<16 | addr_buf[2]<<8 | addr_buf[3];
	snivel->httpd.port = port;
	snivel->httpd.is_enabled = 1;
}


/***************************************************************************
 ****************************************************************************/
int 
main(int argc, char **argv)
{
	int i;
	struct Snivel snivel[1];

    if(argc <= 1) {
        fprintf(stderr, "usage:\n");
		fprintf(stderr, " snivel -r <unified2.log>\n");
        fprintf(stderr, " snivel -f -c <snort.conf>\n");
        return 1;
    }

	/*
	 * Initialize Snivel
	 */
	memset(snivel, 0, sizeof(snivel[0]));
	snivel->out_fp = stdout;


	/*
	 * Parse command-line
	 */
	for (i=1; i<argc; i++) {
		unsigned offset;

		if (argv[i][0] == '-')
		switch (argv[i][1]) {
		case 'c': /* read 'snort.conf' */
			if (argv[i][2] == '\0') {
				i++;
				offset = 0;
			} else
				offset = 2;
#if WIN32
			/* On Linux, the default log-directory is /var/log/snort. On Windows, it
			 * is relative to the location of the snort.conf file, namely
			 * "snort.conf/../log" */
			conf_set_relative_logdir(snivel, argv[i] + offset);
#endif
			/* Read in the snort.conf file, pulling out the locations of the
			 * merged.log file, as well as event names */
			conf_read_file(snivel, argv[i] + offset);
			snivel->is_snort_conf = 1;
			break;
		case 'f': /* Whether to monitor file like "tail -f" */
			snivel->is_tail = 1;
			break;
		case 'H': /* httpd web server */
			if (argv[i][2] == '\0') {
				i++;
				offset = 0;
			} else
				offset = 2;
			set_httpd(snivel, argv[i] + offset);
			break;
		case 'l': /* set 'logdir', like Snort command-line */
			if (argv[i][2] == '\0') {
				i++;
				offset = 0;
			} else
				offset = 2;
			conf_set_logdir(snivel, argv[i] + offset, (unsigned)strlen(argv[i]+offset));
			break;
		case 'r': /* Read specific filename */
			if (argv[i][2] == '\0') {
				i++;
				offset = 0;
			} else
				offset = 2;
			conf_set_logfilename(snivel, argv[i]+offset, strlen(argv[i]+offset));
			break;
		default:
			fprintf(stderr, "%s: unknown configuration option\n", argv[i]);
			break;
		}
	}

	/*
	 * If we have a web server, start it no
	 */
	if (snivel->httpd.is_enabled) {
		httpd_init(snivel);
	}

	/*
	 * Ok, we are done reading in the configuration. Now lets do the actual
	 * work of reading in the Unified2 files and printout out the contents.
	 */
	if (snivel->is_snort_conf && snivel->log[0].nostamp == 0) {
		char last_latest[256] = "";
		unsigned last_repeats = 0;

		/*
		 * Each time that a "merged.log.00000" is closed and a new one opened,
		 * we'll loop again here and start over with the next file in the directory
		 */
		for (;;) {
			/* Deal with timestamped files, which means processing the directory
			 * looking for the latest file */
			char *latest;
			unsigned i=0;
			char *filename;

			/*
			 * Find the actual filename
			 */
			again:
			latest = find_latest_filename(snivel->logdir, snivel->log[0].filename);
			if (latest == NULL) {
				/* directory or file not found. Try a few more times, in case the
				 * snort service is slow coming up */
				sleep(1);
				if (i++ > 5) {
					fprintf(stderr, "Unified2 file '%s.0000000' not found in directory '%s'\n", snivel->log[0].filename, snivel->logdir);
					exit(1);
				}
				goto again;
			}

			if (strcmp(latest, last_latest) == 0) {
				free(latest);
				if (last_repeats++ > 5) {
					fprintf(stderr, "%s: done with no new files\n", last_latest);
					exit(1);
				}
				sleep(1);
				continue;
			} else {
				last_repeats = 0;
				strcpy(last_latest, latest);
			}

			/*
			 * Now that we have found the file, let's run it
			 */
			filename = combine_filename(snivel->logdir, latest);
			snivel_decode_file(snivel, filename);
			free(filename);
			free(latest);

			/*
			 * If not monitoring files live, the exit now. Otherwise, we'll loop again
			 * expecting a later file.
			 */
			if (!snivel->is_tail)
				break;
		}

	} else {
		/* deal with a single file */
		char *filename;

		filename = combine_filename(snivel->logdir, snivel->log[0].filename);
		
		snivel_decode_file(snivel, filename);

		free(filename);
	}

	return 1;
}

