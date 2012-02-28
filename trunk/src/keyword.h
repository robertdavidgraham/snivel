/***************************************************************************
	
	KEYWORD TOKENIZER FOR READING SNORT.CONF FILES

	This module is used when parsing "snort.conf" files. Snivel parses
	Snort's configuration files in order to find the location of
	the Unified2 output files, as well as to parse the "msg", "sid",
	and "gen_id" from the rules.

	The parsing is done via "tokenizing". Each of the parsing functions
	grabs a smaller token from the larger token.


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
#ifndef KEYWORD_H
#define KEYWORD_H

struct Keyword
{
	const char *str;
	unsigned length;
};

struct Keyword keyword_next(const char *line, unsigned *r_offset, unsigned max);
struct Keyword keyword_next_to_comma(const char *line, unsigned *r_offset, unsigned max);
struct Keyword keyword_next_opt_name(const char *line, unsigned *r_offset, unsigned max);
struct Keyword keyword_next_opt_value(const char *line, unsigned *r_offset, unsigned max);
struct Keyword keyword_next_path_element(const char *line, unsigned *r_offset, unsigned max);

int keyword_is_equal(const struct Keyword *lhs, const char *rhs);
struct Keyword keyword_get_file_prefix(const char *filename, unsigned *r_offset, unsigned length);
void keyword_append(char *p, unsigned *r_offset, unsigned max, struct Keyword element);

void keyword_to_name_value(const struct Keyword *field, struct Keyword *name, struct Keyword *value);
int keyword_to_unsigned(struct Keyword *key, unsigned *r_result);


#endif
