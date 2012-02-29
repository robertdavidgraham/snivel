/***************************************************************************
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
#define _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#ifndef WIN32
#include <unistd.h>
#include <dirent.h>
#include <dlfcn.h>
#endif


#ifdef WIN32
#include <Windows.h>
struct dirent {
	char	d_name[FILENAME_MAX];
};
typedef struct DIR {
	HANDLE			handle;
	WIN32_FIND_DATAA	info;
	struct dirent		result;
} DIR;

static DIR *
opendir(const char *name)
{
	DIR	*dir = NULL;
	char	path[FILENAME_MAX];

	if (name == NULL || name[0] == '\0') {
		errno = EINVAL;
	} else if ((dir = (DIR *) malloc(sizeof(*dir))) == NULL) {
		errno = ENOMEM;
	} else {
		_snprintf(path, sizeof(path), "%s/*", name);
		dir->handle = FindFirstFileA(path, &dir->info);

		if (dir->handle != INVALID_HANDLE_VALUE) {
			dir->result.d_name[0] = '\0';
		} else {
			free(dir);
			dir = NULL;
		}
	}

	return (dir);
}

static int
closedir(DIR *dir)
{
	int result = -1;

	if (dir != NULL) {
		if (dir->handle != INVALID_HANDLE_VALUE)
			result = FindClose(dir->handle) ? 0 : -1;

		free(dir);
	}

	if (result == -1)
		errno = EBADF;

	return (result);
}

struct dirent *
readdir(DIR *dir)
{
	struct dirent *result = 0;

	if (dir && dir->handle != INVALID_HANDLE_VALUE) {
		if(!dir->result.d_name ||
		    FindNextFileA(dir->handle, &dir->info)) {
			result = &dir->result;
			strcpy(result->d_name, dir->info.cFileName);
		}
	} else {
		errno = EBADF;
	}

	return (result);
}

#endif

/***************************************************************************
 * This finds the newest Unified filename that matches the spec.
 * Example:
 * Consider a directory that looks like the following:
 *		 Volume in drive C is BOOTCAMP
 *		 Volume Serial Number is EC80-DA0E
 *
 *	Directory of C:\Snort\log
 *
 *	02/23/2012  01:37 PM    <DIR>          .
 *	02/23/2012  01:37 PM    <DIR>          ..
 *	02/16/2012  03:49 PM             8,492 merged.log.1329424960
 *	02/23/2012  01:36 PM           593,304 merged.log.1330017813
 *	02/23/2012  01:37 PM                 0 merged.log.1330022228 <--this
 *	02/08/2012  05:02 PM           491,760 merged.old.log
 *	02/23/2012  01:37 PM                 0 snort.alert
 *	02/23/2012  01:37 PM                 0 snort.log
 *				   6 File(s)      1,093,556 bytes
 *				   2 Dir(s)   1,264,742,400 bytes free
 *
 * This function will be called with:
 *		dirname = "C:\Snort\log"
 *		filename = "merged.log"
 * and will return:
 *		result = "merged.log.1330022228"
 *
 * On Unix, we use the opendir() APIs. On Windows, we emulate those APIs.
 ****************************************************************************/
char *
find_latest_filename(char *dirname, char *filename)
{
	static DIR *directory;
	char *result;
	unsigned largest_number = 0;

	/*
	 * Open a handle to the directory in order to start listing
	 * all the directory entries
	 */
	directory = opendir(dirname);
	if (directory == NULL) {
		fprintf(stderr, "%s: couldn't list directory\n", dirname);
		return NULL;
	}

	/*
	 * Allocate space to hold the result. Nul terminate it to
	 * mark the fact that we haven't found a matching file yet
	 */
	result = (char*)malloc(256);
	result[0] = '\0';


	/*
	 * 'for all directory entries'
	 *   'look for matching file '
	 */
	for (;;) {
		struct dirent *entry;
		const char *entry_name;
		unsigned n;

		/* Read the next file */
		entry = readdir(directory);
		if (entry == NULL)
			break;
		entry_name = entry->d_name;

		/* See if it matches the filename */
		if (strlen(entry_name) <= strlen(filename))
			continue;
		if (memcmp(entry_name, filename, strlen(filename)) != 0)
			continue;
		entry_name += strlen(filename);
		while (ispunct(*entry_name & 0xFF))
			entry_name++;
		if (!isdigit(*entry_name&0xFF))
			continue;

		/* Now test the number */
		n = strtoul(entry_name, 0, 0);
		if (n > largest_number) {
			n = largest_number;
			strcpy(result, entry->d_name);
		}
	}

	closedir(directory);

	if (*result == '\0') {
		/* not found */
		free(result);
		return 0;
	} else
		return result;
}