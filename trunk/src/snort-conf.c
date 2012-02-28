/***************************************************************************
	
	SNORT.CONF PARSER FOR SNIVEL

	One of Snivel's modes is simply:
		snivel -c /etc/snort/snort.conf -f
	In this mode, Snivel looks for lines like "config logdir" and 
	"output unified2" in order to find the Unified2 files. It also
	reads all the 'sid' and 'msg' fields from the rules, so that it
	doesn't have to rely upon the map files in order to know the name
	of an event.

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
#include <sys/stat.h>
#include "keyword.h"

/* use these macros, because functions like isspace() produce undefined
 * results for sign-extended characters */
#define my_isspace(c) isspace((c)&0xFF)
#define my_isalpha(c) isalpha((c)&0xFF)

/***************************************************************************
 ****************************************************************************/
void
combine_elements(char *result, unsigned *result_offset, unsigned result_max,
				 unsigned prefix_length,
				 const char *filename, unsigned filename_max)
{
	unsigned filename_offset[1] = {0};
	static const struct Keyword slash = {"/", 1};

	while (*filename_offset < filename_max) {
		struct Keyword element;

		/* skip duplicate //// characters */
		if (filename[*filename_offset] == '\\') {
			(*filename_offset)++;
			continue;
		}
		if (filename[*filename_offset] == '/') {
			(*filename_offset)++;
			continue;
		}
		
		/* Grab element from input filename */
		element = keyword_next_path_element(filename, filename_offset, filename_max);

		/* ignore "." */
		if (keyword_is_equal(&element, ".")) {
			continue;
		}

		/* traverse "..". Keep track of the path prefix (like "c:\") and don't go
		 * past the root even if there are too many ".." symbols */
		if (keyword_is_equal(&element, "..")) {

			/* go backwards until "/" */
			while (*result_offset > prefix_length && result[(*result_offset)-1] != '/' && result[(*result_offset)-1] != '\\')
				(*result_offset)--;

			/* go backwards past the "/" */ 
			while ((*result_offset) > prefix_length && (result[(*result_offset)-1] == '/' || result[(*result_offset)-1] == '\\'))
				(*result_offset)--;
			
			/* terminate string at this point */
			result[*result_offset] = '\0';
			continue;
		}

		/* else,
		 *	append the right-hand element onto the left-hand element
		 */
		if (*result_offset && result[(*result_offset) - 1] != '/')
			keyword_append(result, result_offset, result_max, slash);
		keyword_append(result, result_offset, result_max, element);
	}
}

/***************************************************************************
 ****************************************************************************/
char *
combine_filename(const char *dirname, const char *filename)
{
	char *result;
	unsigned dirname_length;
	unsigned filename_length;
	unsigned dirname_offset = 0;
	unsigned filename__offset = 0;
	unsigned result_offset = 0;
	unsigned result_max;
	static const struct Keyword slash = {"/", 1};
	struct Keyword prefix;
	unsigned prefix_length;

	/* Deal with empty strings*/
	filename_length = (unsigned)strlen(filename);
	if (dirname == NULL || dirname[0] == '\0') {
		result = (char*)malloc(filename_length+1);
		memcpy(result, filename, filename_length+1);
		return result;
	}
	dirname_length = (unsigned)strlen(dirname);


	/* Remove leading '/' on the filename */
	while (filename_length && (filename[0] == '/' || filename[0] == '\\')) {
		filename_length--;
		filename++;
	}

	/* Remove trailing '/' on directory name */
	while (dirname_length && (dirname[dirname_length-1] == '/' || filename[0] == '\\'))
		dirname_length--;

	/* Allocate space for the result */
	result_max = dirname_length + filename_length + 2;
	result = (char*)malloc(result_max + 1);

	/*
	 * Get the prefix, which is something like "C:\" on Windows,
	 * or "\\" or "//" also on Windows, or "/" on Unix 
	 */
	prefix = keyword_get_file_prefix(dirname, &dirname_offset, dirname_length);
	keyword_append(result, &result_offset, result_max, prefix);
	if (result_offset && result[result_offset - 1] != '/' && result[result_offset - 1] != '\\')
		keyword_append(result, &result_offset, result_max, slash);
	prefix_length = result_offset;

	/* Combine elements */
	combine_elements(result, &result_offset, result_max, prefix_length, dirname, dirname_length);
	combine_elements(result, &result_offset, result_max, prefix_length, filename, filename_length);


	return result;
}



/***************************************************************************
 * Whetherh the first string ends with the second.
 *    true == ends_with("xyzpdq", "pdq")
 ****************************************************************************/
static int
ends_with(const char *line, const char *ending)
{
	size_t line_length = strlen(line);
	size_t ending_length = strlen(ending);

	if (line_length < ending_length)
		return 0;
	else
		return memcmp(line+line_length-ending_length, ending, ending_length+1) == 0;

}


/***************************************************************************
 * When the line returned by 'fgets()' is longer than the allocated buffer,
 * the grow the length of the buffer. This is especially important for lines
 * that use the \ operator to split across multiple lines.
 ****************************************************************************/
char *
fgets_autogrow(char **line, size_t *line_length, FILE *fp, size_t offset)
{
	char *p;
	size_t bytes_read = 0;

	/* Do the initial read into the buffer */
	p = fgets(*line+offset, *line_length-offset, fp);
	if (p == NULL)
		return p;

	/* If the line doesn't end with a '\n', we've either read the last 
	 * line in the file, or we've filled our buffer and have an incomplete
	 * line */
	while (!ends_with(*line, "\n")) {
		size_t old_length = strlen(*line);
		size_t new_length = (*line_length * 2) + 1;
		char *new_line;

		/* In some files, the last line isn't terminated by a '\n'. In that
		 * case, simply return the line immediately */
		if (strlen(*line) < (*line_length - 1)) {
			/* at file end */
			return p;
		}

		/*
		 * Expand line
		 */
		new_line = (char*)malloc(new_length+1);
		memcpy(new_line, *line, old_length+1);
		free(*line);
		*line = new_line;
		*line_length = new_length;

		/*
		 * Continue reading line
		 */
		p = fgets(*line + old_length, *line_length - old_length, fp);
		if (p == NULL)
			return p;
	}

	return p;
}

/***************************************************************************
 * Whether this line ends with \
 * ...which means to continue onto the next line
 ****************************************************************************/
static int
has_continuation(const char *line)
{
	size_t line_length = strlen(line);

	/* ignore trailing whitespace. In other words, lines can end 
	 * with "\    \r\n", with all the space after the \ being ignored */
	while (line_length && my_isspace(line[line_length-1]))
		line_length--;

	/* Now test the line */
	if (line_length && line[line_length-1] == '\\')
		return 1;
	else
		return 0;
}

/***************************************************************************
 * Remove the \ operator from the end of the line, so that the next line
 * can be combined with this line. Note that we still retain the '\n' 
 * character in the line. That's for printing error messages, so that we
 * can correctly identify the corresponding line the file when printing
 * error messages.
 ****************************************************************************/
static int
remove_continuation(char *line)
{
	size_t line_length = strlen(line);
	while (line_length && my_isspace(line[line_length-1]))
		line_length--;
	if (line_length && line[line_length-1] == '\\') {
		line_length--;
		line[line_length] = '\n';
		line[line_length+1] = '\0';
		return 1;
	} else
		return 0;
}





/***************************************************************************
 * Whether two strings are equal.
 ****************************************************************************/
static int
str_is_equal(const char *lhs, size_t lhs_length, const char *rhs, size_t rhs_length)
{
	if (lhs_length != rhs_length)
		return 0;
	return memcmp(lhs, rhs, rhs_length) == 0;
}

/***************************************************************************
 ****************************************************************************/
static const char *
namevalue_lookup(const struct NameValues *refs, const char *name, unsigned name_length)
{
	unsigned i;

	/*
	 * See if the reference is already there
	 */
	for (i=0; i<refs->count; i++) {
		if (str_is_equal(refs->elements[i].name, strlen(refs->elements[i].name), name, name_length)) {
			return refs->elements[i].value;
		}
	}

	return 0;
}

/***************************************************************************
 * For adding 'reference' and 'classification' items to the arrays.
 ****************************************************************************/
static void
namevalue_add(struct NameValues *refs, const char *name, unsigned name_length, const char *value, unsigned value_length, unsigned num)
{
	unsigned i;

	/*
	 * See if the reference is already there
	 */
	for (i=0; i<refs->count; i++) {
		if (str_is_equal(refs->elements[i].name, strlen(refs->elements[i].name), name, name_length)) {
			fprintf(stderr, "duplicate reference: %.*s = %.*s\n", name_length, name, value_length, value);
			return;
		}
	}

	/*
	 * Make sure there is enough room
	 */
	if (refs->count + 1 >= refs->max) {
		unsigned new_max = refs->max*2 + 1;
		struct NameValue *new_elements = (struct NameValue *)malloc(new_max * sizeof(*new_elements));

		memcpy(new_elements, refs->elements, refs->count * sizeof(*new_elements));
		if (refs->elements)
			free(refs->elements);
		refs->elements = new_elements;
		refs->max = new_max;
	}

	/*
	 * Fill in the reference element
	 */
	{
		char *new_name = (char*)malloc(name_length+1);
		char *new_value = (char*)malloc(value_length+1);
		memcpy(new_name, name, name_length);
		new_name[name_length] = '\0';
		memcpy(new_value, value, value_length);
		new_value[value_length] = '\0';

		refs->elements[refs->count].name = new_name;
		refs->elements[refs->count].value = new_value;
		refs->elements[refs->count].num = num;
		refs->count++;
	}
}

void
conf_add_reference(struct Snivel *snivel, const char *name, unsigned name_length, const char *value, unsigned value_length)
{
	namevalue_add(&snivel->refs, name, name_length, value, value_length, 0);
}
void
conf_add_classification(struct Snivel *snivel, const char *name, unsigned name_length, const char *value, unsigned value_length, unsigned priority)
{
	namevalue_add(&snivel->classifications, name, name_length, value, value_length, priority);
}


/***************************************************************************
 * Add a <sid=msg> map to our list. This will be used later when printing
 * alerts, so that we can include the 'msg' along with the 'sid'.
 ****************************************************************************/
const char *
conf_sid_lookup_msg(const struct Snivel *snivel, unsigned gid, unsigned sid)
{
	const struct MsgMap *map = &snivel->msg_map;
	unsigned i;

	/*
	 * See if the reference is already there
	 */
	for (i=0; i<map->count; i++) {
		if (map->elements[i].gid == gid && map->elements[i].sid == sid)
			return map->elements[i].msg;
	}

	return 0;
}

/***************************************************************************
 * Add a <sid=msg> map to our list. This will be used later when printing
 * alerts, so that we can include the 'msg' along with the 'sid'.
 ****************************************************************************/
void
conf_add_sid_msg(struct Snivel *snivel, unsigned gid, unsigned sid, const char *msg, unsigned msg_length)
{
	struct MsgMap *map = &snivel->msg_map;
	unsigned i;

	/*
	 * See if the reference is already there
	 */
	for (i=0; i<map->count; i++) {
		if (map->elements[i].gid == gid && map->elements[i].sid == sid) {
			if (!str_is_equal(map->elements[i].msg, strlen(map->elements[i].msg), msg, msg_length)) {
				fprintf(stderr, "duplicate msg map: [gid=%u,sid=%u], \"%.*s\" vs \"%s\" \n",
					gid, sid,  msg_length, msg, map->elements[i].msg);
				return;
			}
		}
	}

	/*
	 * Make sure there is enough room
	 */
	if (map->count + 1 >= map->max) {
		unsigned new_max = map->max*2 + 1;
		struct MapElement *new_elements = (struct MapElement *)malloc(new_max * sizeof(*new_elements));

		memcpy(new_elements, map->elements, map->count * sizeof(*new_elements));
		if (map->elements)
			free(map->elements);
		map->elements = new_elements;
		map->max = new_max;
	}

	/*
	 * Fill in the reference element
	 */
	{
		char *new_msg = (char*)malloc(msg_length+1);
		memcpy(new_msg, msg, msg_length);
		new_msg[msg_length] = '\0';
		
		map->elements[map->count].msg = new_msg;
		map->elements[map->count].gid = gid;
		map->elements[map->count].sid = sid;
		map->count++;
	}
}


/***************************************************************************
 * Parse a snort "rule" looking for the "sid" field and "msg" field.
 ****************************************************************************/
static void
conf_process_rule(struct Snivel *snivel, const char *line, unsigned line_length)
{
	unsigned offset;
	struct Keyword msg = {"(unknown)",9};
	struct Keyword gid = {"1",1};
	struct Keyword sid = {"0",1};
	unsigned gid_value;
	unsigned sid_value;

	for (offset=0; offset<line_length; offset++) {
		if (line[offset] == '(')
			break;
	}

	if (offset >= line_length || line[offset] != '(')
		return;
	else
		offset++;

	while (offset < line_length) {
		struct Keyword name;
		struct Keyword value;

		/* strip whitespace */
		while (offset < line_length && my_isspace(line[offset]))
			offset++;

		/* See if we have come to the end */
		if (offset >= line_length || line[offset] == ')')
			break;

		/* Grab the <name=value> */
		name = keyword_next_opt_name(line, &offset, line_length);
		value = keyword_next_opt_value(line, &offset, line_length);

		/* Look for the values we want */
		if (keyword_is_equal(&name, "msg")) {
			memcpy(&msg, &value, sizeof(msg));
		} else if (keyword_is_equal(&name, "gid")) {
			memcpy(&gid, &value, sizeof(gid));
		} else if (keyword_is_equal(&name, "sid")) {
			memcpy(&sid, &value, sizeof(sid));
		}

		/* strip whitespace */
		while (offset < line_length && my_isspace(line[offset]))
			offset++;
		if (offset < line_length && line[offset] == ';')
			line++;
		while (offset < line_length && my_isspace(line[offset]))
			offset++;
	}

	if (!keyword_to_unsigned(&sid, &sid_value))
		return;
	if (!keyword_to_unsigned(&gid, &gid_value))
		return;

	if (msg.length && msg.str[0] == '\"') {
		msg.str++;
		msg.length--;

		while (msg.length && my_isspace(msg.str[0])) {
			msg.str++;
			msg.length--;
		}

		if (msg.length && msg.str[msg.length-1] == '\"') {
			msg.length--;
			while (msg.length && my_isspace(msg.str[msg.length-1]))
				msg.length--;
		}
	}

	conf_add_sid_msg(snivel, gid_value, sid_value, msg.str, msg.length);

}



/***************************************************************************
 ****************************************************************************/
void
conf_set_logdir(struct Snivel *snivel, const char *filename, unsigned filename_length)
{
	char *p;
	unsigned p_offset = 0;
	struct Keyword prefix;
	struct Keyword slash = {"/", 1};
	unsigned filename_offset = 0;
	unsigned p_max = filename_length;
	unsigned prefix_length;

	p = (char*)malloc(p_max + 1);
	if (p == NULL) {
		fprintf(stderr, "out of mem\n");
		return;
	}

	/*
	 * Get the prefix, which is something like "C:\" on Windows,
	 * or "\\" or "//" also on Windows, or "/" on Unix 
	 */
	prefix = keyword_get_file_prefix(filename, &filename_offset, filename_length);
	keyword_append(p, &p_offset, p_max, prefix);
	if (p_offset && p[p_offset - 1] != '/')
		keyword_append(p, &p_offset, p_max, slash);
	prefix_length = p_offset;

	/*
	 * Now go through all the file elements and append them
	 * to the string
	 */
	while (filename_offset < filename_length) {
		struct Keyword element;

		if (filename[filename_offset] == '/') {
			filename_offset++;
			continue;
		}

		element = keyword_next_path_element(filename, &filename_offset, filename_length);


		if (keyword_is_equal(&element, ".")) {
			continue;
		}
		if (keyword_is_equal(&element, "..")) {
			while (p_offset > prefix_length && p[p_offset-1] != '/')
				p_offset--;
			if (p_offset > prefix_length && p[p_offset-1] == '/')
				p_offset--;
			p[p_offset] = '\0';
			continue;
		}


		if (p_offset && p[p_offset - 1] != '/')
			keyword_append(p, &p_offset, p_max, slash);
		keyword_append(p, &p_offset, p_max, element);
	}

	/*
	 * Now set the logging directory
	 */
	if (snivel->logdir)
		free(snivel->logdir);
	snivel->logdir = p;

	/*
	 * Check logging dir
	 */
	{
		struct _stat s;

		if (_stat(snivel->logdir, &s) != 0) {
			fprintf(stderr, "logdir: directory invalid\n");
			perror(snivel->logdir);
			exit(1);
		} else if (!(s.st_mode & S_IFDIR)) {
			fprintf(stderr, "logdir: filename not a valid directory: %s\n", snivel->logdir);
			exit(1);
		}
	}
}

/***************************************************************************
 * Example:
 * output unified2: filename merged.log, limit 128, nostamp, mpls_event_types, vlan_event_types
 *                  ^
 *
 ****************************************************************************/
void
conf_read_unified2(struct Snivel *snivel, const char *line, unsigned offset, unsigned line_length, unsigned line_number, const char *filename)
{
	struct Keyword logfilename = {0, 0};
	unsigned limit = 0;
	unsigned nostamp = 0;
	unsigned mpls_event_types = 0;
	unsigned vlan_event_types = 0;
	struct Logfile *log;


	/*
	 * Parse the <name=value> pairs
	 */
	while (offset < line_length) {
		struct Keyword field;
		struct Keyword name;
		struct Keyword value;

		field = keyword_next_to_comma(line, &offset, line_length);
		keyword_to_name_value(&field, &name, &value);

		if (keyword_is_equal(&name, "filename")) {
			memcpy(&logfilename, &value, sizeof(logfilename));
		} else if (keyword_is_equal(&name, "limit")) {
			if (!keyword_to_unsigned(&value, &limit)) {
				fprintf(stderr, "%s:%u:%u: invalid value for unified2 limit: \"%.*s\"\n", 
					filename, line_number, offset-value.length,
					value.length, value.str);
				limit = 0;
			}
		} else if (keyword_is_equal(&name, "nostamp")) {
			nostamp = 1;
		} else if (keyword_is_equal(&name, "mpls_event_types")) {
			mpls_event_types = 1;
		} else if (keyword_is_equal(&name, "vlan_event_types")) {
			vlan_event_types = 1;
		} else {
			fprintf(stderr, "%s:%u:%u: unknown unified2 parameter: \"%.*s\"\n", 
				filename, line_number, offset-name.length,
				name.length, name.str);
		}
	}

	if (logfilename.str == 0 || logfilename.length == 0) {
		fprintf(stderr, "%s:%u:%u: missing log filename\n", 
			filename, line_number, 1);
		return;
	}
	if (snivel->log_count >= sizeof(snivel->log)/sizeof(snivel->log[0])) {
		fprintf(stderr, "%s:%u:%u: unknown unified2 parameter: \"%.*s\"\n", 
				filename, line_number, 1,
				logfilename.length, logfilename.str);
		return;
	}

	log = &snivel->log[snivel->log_count++];
	log->filename = (char*)malloc(logfilename.length+1);
	memcpy(log->filename, logfilename.str, logfilename.length+1);
	log->filename[logfilename.length] = '\0';
	log->limit = limit;
	log->nostamp = nostamp;
	log->mpls_event_types = mpls_event_types;
	log->vlan_event_types = vlan_event_types;

}

/***************************************************************************
 ****************************************************************************/
static is_variable_char(const char c)
{
	if (isalnum(c&0xFF))
		return 1;
	if (c == '-')
		return 1;
	if (c == '_')
		return 1;
	return 0;
}

/***************************************************************************
 ****************************************************************************/
char *
replace_vars(const struct Snivel *snivel, const char *rhs)
{
	unsigned i;
	char *result;
	size_t result_length = strlen(rhs);
	unsigned result_offset = 0;
	
	result = (char*)malloc(result_length+1);

	for (i=0; rhs[i]; i++) {
		if (rhs[i] == '$') {
			const char *name = rhs+1;
			const char *value;
			unsigned name_length=0;
			while (is_variable_char(name[name_length]))
				name_length++;

			value = namevalue_lookup(&snivel->vars, name, name_length);
			if (value) {
				size_t value_length = strlen(value);

				result_length += value_length;
				result = realloc(result, result_length+1);
				memcpy(result+result_offset, value, value_length+1);

				result_offset += value_length;
				i += name_length;
				continue;
			}
		}
		result[result_offset++] = rhs[i];
	}

	result[result_offset] = '\0';

	return result;
}


/***************************************************************************
 * Process a single line (that has been read in from snort.conf). The line
 * has been reassembled if it crossed lines with the \ operator.
 ****************************************************************************/
void
conf_read_line(struct Snivel *snivel, const char *line, unsigned line_length, unsigned line_number, const char *filename)
{
	unsigned offset = 0;
	struct Keyword keyword;

	keyword = keyword_next(line, &offset, line_length);

	if (keyword_is_equal(&keyword, "include")) {
		char *p1 = combine_filename(filename, "..");
		char *p2 = replace_vars(snivel, line+offset);
		char *p3 = combine_filename(p1, p2);
		conf_read_file(snivel, p3);
		free(p1);
		free(p2);
		free(p3);
	} else if (keyword_is_equal(&keyword, "output")) {
		struct Keyword type;
		type = keyword_next(line, &offset, line_length);
		if (keyword_is_equal(&type, "unified2:")) {
			conf_read_unified2(snivel, line, offset, line_length, line_number, filename);
		} else if (keyword_is_equal(&type, "alert_unified2:")) {
			conf_read_unified2(snivel, line, offset, line_length, line_number, filename);
		} else if (keyword_is_equal(&type, "log_unified2:")) {
			conf_read_unified2(snivel, line, offset, line_length, line_number, filename);
		} else {
			fprintf(stderr, "%s:%u:%u: output \"%.*s\" unknown format\n", 
				filename, line_number, offset-type.length,
				type.length, type.str);
		}
	} else if (keyword_is_equal(&keyword, "alert")) {
		conf_process_rule(snivel, line, line_length);
	} else if (keyword_is_equal(&keyword, "var")) {
		struct Keyword name;
		struct Keyword value;
		name = keyword_next(line, &offset, line_length);
		value = keyword_next(line, &offset, line_length);
		namevalue_add(&snivel->vars, name.str, name.length, value.str, value.length, 0);
	} else if (keyword_is_equal(&keyword, "config")) {
		struct Keyword config;
		config = keyword_next(line, &offset, line_length);
		if (keyword_is_equal(&config, "classification:")) {
			struct Keyword classname;
			struct Keyword classdesc;
			struct Keyword prioritystr;
			unsigned priority;

			classname = keyword_next_to_comma(line, &offset, line_length);
			classdesc = keyword_next_to_comma(line, &offset, line_length);
			prioritystr = keyword_next_to_comma(line, &offset, line_length);
			keyword_to_unsigned(&prioritystr, &priority);

			conf_add_classification(snivel, classname.str, classname.length, classdesc.str, classdesc.length, priority);

		} else if (keyword_is_equal(&config, "reference:")) {
			struct Keyword ref;
			ref = keyword_next(line, &offset, line_length);
			conf_add_reference(snivel, ref.str, ref.length, line+offset, line_length-offset);
		} else if (keyword_is_equal(&config, "logdir:")) {
			unsigned new_length = line_length - offset;
			char *new_line = (char*)malloc(new_length + 1);
			unsigned j;
			memcpy(new_line, line+offset, new_length+1);
			new_line[new_length] = '\0';
			for (j=0; j<new_length; j++) {
				if (new_line[j] == '\\')
					new_line[j] = '/'; /* convert \ to / */
			}
			conf_set_logdir(snivel, new_line, new_length);
			free(new_line);
		} else {
			/* some other configuration we don't care about */
			;
		}
	} else {
		/* some other keyword we don't care about */
		;
	}

}


/***************************************************************************
 ****************************************************************************/
void
conf_read_file(struct Snivel *snivel, const char *filename)
{
	unsigned line_number = 0;
	FILE *fp;
	char *line;
	size_t line_length = 10; /* start with a small number, then auto-grow */

	/*
	 * Initial allocation for the line, which will grow as we encounter
	 * longer lines
	 */
	line = (char*)malloc(line_length+1);
	if (line == NULL) {
		fprintf(stderr, "read conf: memory allocation error\n");
		return;
	}

	/*
	 * open 'snort.conf'
	 */
	fp = fopen(filename, "rt");
	if (fp == NULL) {
		perror(filename);
		fprintf(stderr, "%s: cannot read Snort conf file\n", filename);
		return;
	}

	/*
	 * Read all lines from the configuration file
	 */
	for (;;) {
		char *p;
		unsigned this_linenumber;

		line_number++;
		this_linenumber = line_number;

		/*
		 * Read the next line
		 */
		p = fgets_autogrow(&line, &line_length, fp, 0);
		if (p == NULL)
			break;

		/*
		 * See if we need to combine lines
		 */
		while (has_continuation(line)) {
			remove_continuation(line);
			line_number++;
			p = fgets_autogrow(&line, &line_length, fp, strlen(line));
		}

		/*
		 * strip whitespace from end
		 */
		while (line[0] && my_isspace(line[strlen(line)-1]))
			line[strlen(line)-1] = '\0';

		/*
		 * strip whitespace from beginning
		 */
		while (line[0] && my_isspace(line[0]))
			memmove(line, line+1, strlen(line));

		/*
		 * Skip comments
		 */
		if (line[0] == '#' || line[0] == '\0')
			continue;

		/*
		 * Handle the line
		 */
		conf_read_line(snivel, line, strlen(line), line_number, filename);
	}


	free(line);
	fclose(fp);
}

/***************************************************************************
 ****************************************************************************/
void
conf_set_logfilename(struct Snivel *snivel, const char *filename, size_t filename_length)
{
	struct Logfile *file;

	if (snivel->log_count >= sizeof(snivel->log)/sizeof(snivel->log[0])) {
		fprintf(stderr, "set log filename: too many names, ignoring %.*s\n", filename_length, filename);
		return;
	} else 
		file = &snivel->log[snivel->log_count++];

	file->filename = (char*)malloc(filename_length + 1);
	memcpy(file->filename, filename, filename_length);
	file->filename[filename_length] = '\0';
}

/***************************************************************************
 * Set the default logdir relative to the conf file directory. This is for 
 * Windows, so that if you read "C:\snort\etc\snort.conf", then the 
 * logging directory becomes "C:\snort\etc\..\log\"
 ****************************************************************************/
void conf_set_relative_logdir(struct Snivel *snivel, const char *filename)
{
	char *p;
	char *slash;
	unsigned i;

	p = (char*)malloc(strlen(filename) + strlen("/../log/") + 1);
	memcpy(p, filename, strlen(filename)+1);

	/* change backslashes to forward slashes */
	for (i=0; p[i]; i++)
		if (p[i] == '\\')
			p[i] = '/';

	
	slash = strrchr(p, '/');
	if (slash == NULL || strrchr(p, '\\') > slash)
		slash = strrchr(p, '\\');
	if (slash == NULL)
		slash = p;
	strcpy(slash, "/../log/");

	conf_set_logdir(snivel, p, strlen(p));

	free(p);
}
