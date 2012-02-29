#define _CRT_SECURE_NO_WARNINGS 1
/*
 * Copyright (c) 2004-2009 Sergey Lyubka
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * $Id: mongoose.c 200 2009-01-04 15:13:14Z valenok $
 */

#ifndef _WIN32_WCE /* Some ANSI #includes are not available on Windows CE */
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#endif /* _WIN32_WCE */

#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>


#if defined(_WIN32)		/* Windows specific	*/
#pragma comment(lib,"wsock32.lib")

#pragma warning(disable:4115)
#include <windows.h>

#ifndef _WIN32_WCE
#include <process.h>
#include <direct.h>
#include <io.h>
#else /* _WIN32_WCE */
/* Windows CE-specific definitions */
#define NO_CGI	/* WinCE has no pipes */
#define NO_GUI	/* temporarily until it is fixed */
/* WinCE has both Unicode and ANSI versions of GetProcAddress */
#undef GetProcAddress
#define GetProcAddress GetProcAddressA
#endif /* _WIN32_WCE */

/*
 * Do not allow holes in data structures!
 * This is needed so when Mongoose DLL is loaded, other languages that
 * describe struct mg_request_info from mongoose.h, agree with C code.
 */
#pragma pack(1)

#if _MSC_VER<=1200
#define	__FUNCTION__		""
#endif
#define	__func__		__FUNCTION__
#define	ERRNO			GetLastError()
#define	NO_SOCKLEN_T
#define	SSL_LIB			"ssleay32.dll"
#define	DIRSEP			'\\'
#define	IS_DIRSEP_CHAR(c)	((c) == '/' || (c) == '\\')
#define	O_NONBLOCK		0
#undef EWOULDBLOCK
#define	EWOULDBLOCK		WSAEWOULDBLOCK
#define	dlopen(x,y)		LoadLibraryA(x)
#define	dlsym(x,y)		GetProcAddress((HINSTANCE) (x), (y))
#define	_POSIX_

#if !defined(R_OK)
#define	R_OK			04 /* for _access() */
#endif /* !R_OK  MINGW #defines R_OK */

#define	SHUT_WR			1
#define	snprintf		_snprintf
#define	vsnprintf		_vsnprintf
#define	popen(x, y)		_popen(x, y)
#define	pclose(x)		_pclose(x)
#define	access(x, y)		_access(x, y)
#define	getcwd(x, y)		_getcwd(x, y)

#ifdef HAVE_STRTOUI64
#define	strtoull(x, y, z)	_strtoui64(x, y, z)
#else
#define	strtoull(x, y, z)	strtoul(x, y, z)
#endif /* HAVE_STRTOUI64 */

#define	write(x, y, z)		_write(x, y, (unsigned) z)
#define	read(x, y, z)		_read(x, y, (unsigned) z)
#define	open(x, y, z)		_open(x, y, z)
#define	lseek(x, y, z)		_lseek(x, y, z)
#define	close(x)		_close(x)

#if !defined(fileno)
#define	fileno(x)		_fileno(x)
#endif /* !fileno MINGW #defines fileno */

typedef HANDLE pthread_mutex_t;

#if !defined(S_ISDIR)
#define S_ISDIR(x)		((x) & _S_IFDIR)
#endif /* S_ISDIR */

#if defined(HAVE_STDINT)
#include <stdint.h>
#else
typedef unsigned int		uint32_t;
typedef unsigned short		uint16_t;
typedef unsigned __int64	uint64_t;
#endif /* HAVE_STDINT */

/*
 * POSIX dirent interface
 */
struct dirent {
	char	d_name[FILENAME_MAX];
};

typedef struct DIR {
	HANDLE			handle;
	WIN32_FIND_DATAW	info;
	struct dirent		result;
} DIR;

#else				/* UNIX  specific	*/
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <pwd.h>
#include <unistd.h>
#include <dirent.h>
#include <dlfcn.h>
#include <pthread.h>
#define	SSL_LIB			"libssl.so"
#define	DIRSEP			'/'
#define	IS_DIRSEP_CHAR(c)	((c) == '/')
#define	O_BINARY		0
#define	closesocket(a)		close(a)
#define	mg_mkdir(x, y)		mkdir(x, y)
#define	mg_open(x, y, z)	open(x, y, z)
#define	mg_remove(x)		remove(x)
#define	mg_stat(x, y)		stat(x, y)
#define	ERRNO			errno
#define	INVALID_SOCKET		(-1)
typedef int SOCKET;

#endif /* End of Windows and UNIX specific includes */

#include "mongoose.h"

#define	MONGOOSE_VERSION	"2.3"
#define	PASSWORDS_FILE_NAME	".htpasswd"
#define	CGI_ENVIRONMENT_SIZE	4096
#define	MAX_CGI_ENVIR_VARS	64
#define	MAX_REQUEST_SIZE	16384
#define	MAX_LISTENING_SOCKETS	10
#define	MAX_CALLBACKS		20
#define	ARRAY_SIZE(array)	(sizeof(array) / sizeof(array[0]))

#if defined(_MSC_VER) && _MSC_VER <= 1200
#define MAX64 0xffffffffffffffffui64
#else
#define MAX64 ((uint64_t) ~0ULL)
#endif
#define	UNKNOWN_CONTENT_LENGTH	MAX64

#if defined(_MSC_VER) && _MSC_VER <= 1200
#define	__FUNCTION__		""
#define U64 "%I64u"
#else
#define U64 "%llu"
#endif

/*
 * Darwin prior to 7.0 and Win32 do not have socklen_t
 */
#ifdef NO_SOCKLEN_T
typedef int socklen_t;
#endif /* NO_SOCKLEN_T */

#if !defined(FALSE)
enum {FALSE, TRUE};
#endif /* !FALSE */

typedef int bool_t;
typedef void * (*mg_thread_func_t)(void *);
static void cry(const char *, ...);

static int tz_offset;
static const char *http_500_error = "Internal Server Error";
static FILE *error_log;

/*
 * Snatched from OpenSSL includes. I put the prototypes here to be independent
 * from the OpenSSL source installation. Having this, mongoose + SSL can be
 * built on any system with binary SSL libraries installed.
 */
typedef struct ssl_st SSL;
typedef struct ssl_method_st SSL_METHOD;
typedef struct ssl_ctx_st SSL_CTX;

#define	SSL_ERROR_WANT_READ	2
#define	SSL_ERROR_WANT_WRITE	3
#define SSL_FILETYPE_PEM	1

/*
 * Dynamically loaded SSL functionality
 */
struct ssl_func {
	const char	*name;		/* SSL function name	*/
	void		(*ptr)(void);	/* Function pointer	*/
};

#define	FUNC(x)	ssl_sw[x].ptr

#define	SSL_free(x)	(* (void (*)(SSL *)) FUNC(0))(x)
#define	SSL_accept(x)	(* (int (*)(SSL *)) FUNC(1))(x)
#define	SSL_connect(x)	(* (int (*)(SSL *)) FUNC(2))(x)
#define	SSL_read(x,y,z)	(* (int (*)(SSL *, void *, int)) FUNC(3))((x),(y),(z))
#define	SSL_write(x,y,z) \
	(* (int (*)(SSL *, const void *,int)) FUNC(4))((x), (y), (z))
#define	SSL_get_error(x,y)(* (int (*)(SSL *, int)) FUNC(5))((x), (y))
#define	SSL_set_fd(x,y)	(* (int (*)(SSL *, SOCKET)) FUNC(6))((x), (y))
#define	SSL_new(x)	(* (SSL * (*)(SSL_CTX *)) FUNC(7))(x)
#define	SSL_CTX_new(x)	(* (SSL_CTX * (*)(SSL_METHOD *)) FUNC(8))(x)
#define	SSLv23_server_method()	(* (SSL_METHOD * (*)(void)) FUNC(9))()
#define	SSL_library_init() (* (int (*)(void)) FUNC(10))()
#define	SSL_CTX_use_PrivateKey_file(x,y,z)	(* (int (*)(SSL_CTX *, \
		const char *, int)) FUNC(11))((x), (y), (z))
#define	SSL_CTX_use_certificate_file(x,y,z)	(* (int (*)(SSL_CTX *, \
		const char *, int)) FUNC(12))((x), (y), (z))
#define SSL_CTX_set_default_passwd_cb(x,y) \
	(* (void (*)(SSL_CTX *, mg_spcb_t))FUNC(13))((x),(y))

static struct ssl_func	ssl_sw[] = {
	{"SSL_free",			NULL},
	{"SSL_accept",			NULL},
	{"SSL_connect",			NULL},
	{"SSL_read",			NULL},
	{"SSL_write",			NULL},
	{"SSL_get_error",		NULL},
	{"SSL_set_fd",			NULL},
	{"SSL_new",			NULL},
	{"SSL_CTX_new",			NULL},
	{"SSLv23_server_method",	NULL},
	{"SSL_library_init",		NULL},
	{"SSL_CTX_use_PrivateKey_file",	NULL},
	{"SSL_CTX_use_certificate_file",NULL},
	{"SSL_CTX_set_default_passwd_cb",NULL},
	{NULL,				NULL}
};

struct usa {
	socklen_t len;
	union {
		struct sockaddr	sa;
		struct sockaddr_in sin;
	} u;
};

/*
 * Numeric indexes for the option values in context, ctx->options
 */
enum mg_option_index {
	OPT_ROOT, OPT_INDEX_FILES, OPT_PORTS, OPT_DIR_LIST, OPT_CGI_EXTENSIONS,
	OPT_CGI_INTERPRETER, OPT_SSI_EXTENSIONS, OPT_AUTH_DOMAIN,
	OPT_AUTH_GPASSWD, OPT_AUTH_PUT, OPT_ACCESS_LOG, OPT_ERROR_LOG,
	OPT_SSL_CERTIFICATE, OPT_ALIASES, OPT_ACL, OPT_UID,
	OPT_PROTECT, OPT_SERVICE, OPT_HIDE, OPT_ADMIN_URI,
	OPT_IP,
	NUM_OPTIONS
};

struct listener {
	SOCKET	sock;		/* Listening socket		*/
	int	is_ssl;		/* Should be SSL-ed		*/
};

/*
 * Callback function, and where it is bound to
 */
struct callback {
	char		*uri_regex;	/* URI regex to handle		*/
	mg_callback_t	func;		/* user callback		*/
	bool_t		is_auth;	/* func is auth checker		*/
	int		status_code;	/* error code to handle		*/
	void		*user_data;	/* opaque user data		*/
};

/*
 * Mongoose context
 */
struct mg_context {
	int		stop_flag;	/* Should we stop event loop	*/
	SSL_CTX		*ssl_ctx;	/* SSL context			*/

	FILE		*access_log;	/* Opened access log		*/
	FILE		*error_log;	/* Opened error log		*/

	struct listener	listeners[MAX_LISTENING_SOCKETS];
	int		num_listeners;

	struct callback	callbacks[MAX_CALLBACKS];
	int		num_callbacks;

	char	*options[NUM_OPTIONS];	/* Configured opions		*/
	pthread_mutex_t	mutex;		/* Option setter/getter guard	*/

	mg_spcb_t	ssl_password_callback;
};

struct mg_connection {
	struct mg_request_info	request_info;
	struct mg_context *ctx;		/* Mongoose context we belong to*/
	SSL		*ssl;		/* SSL descriptor		*/
	SOCKET		sock;		/* Connected socket		*/
	struct usa	rsa;		/* Remote socket address	*/
	struct usa	lsa;		/* Local socket address		*/
	time_t		birth_time;	/* Time connection was accepted	*/
	bool_t		free_post_data;	/* post_data was malloc-ed	*/
	bool_t		keep_alive;	/* Keep-Alive flag		*/
	uint64_t	num_bytes_sent;	/* Total bytes sent to client	*/
	
	/* ROB: allow construction of headers without doing sends 
	 * across the socket */
	char		response_header[16384];
	unsigned	response_header_length;
};

/*
 * In Mongoose, list of values are represented as comma separated
 * string. For example, list of CGI extensions can be represented as
 * ".cgi,.php,.pl", FOR_EACH_WORD_IN_LIST macro allows to
 * loop through the individual values in that list.
 *
 * A "const char *" and "int" variables must be passed to the macro.
 *
 * In every iteration of the loop, "s" points to the current value, and
 * "len" specifies its length. Code inside loop must not change "s" and "len".
 */
#define	FOR_EACH_WORD_IN_LIST(s, len)					\
	for (; s != NULL && (len = strcspn(s, ",")) != 0;		\
			s += len, s+= strspn(s, ","))

/*
 * Print error message to the opened error log stream.
 */
static void
cry(const char *fmt, ...)
{
	FILE	*fp;
	va_list	ap;

	fp = error_log == NULL ? stderr : error_log;
	va_start(ap, fmt);
	(void) vfprintf(fp, fmt, ap);
	va_end(ap);

	fputc('\n', fp);
}

const char *
mg_version(void)
{
	return (MONGOOSE_VERSION);
}

static void
mg_strlcpy(register char *dst, register const char *src, size_t n)
{
	for (; *src != '\0' && n > 1; n--)
		*dst++ = *src++;
	*dst = '\0';
}

static int
mg_strncasecmp(const char *str1, const char *str2, size_t len)
{
	const unsigned char	*s1, *s2, *end;

	s1 = (unsigned char *) str1;
	s2 = (unsigned char *) str2;
	end = s1 + len - 1;

	while (s1 < end && *s1 && *s2 && tolower(*s1) == tolower(*s2)) {
		s1++;
		s2++;
	}

	return (tolower(*s1) - tolower(*s2));
}

static int
mg_strcasecmp(const char *str1, const char *str2)
{
	return (mg_strncasecmp(str1, str2, strlen(str1)));
}

static char *
mg_strndup(const char *ptr, size_t len)
{
	char	*p;

	if ((p = (char *) malloc(len + 1)) != NULL)
		mg_strlcpy(p, ptr, len + 1);

	return (p);

}

static char *
mg_strdup(const char *str)
{
	return (mg_strndup(str, strlen(str)));
}

/*
 * Like snprintf(), but never returns negative value, or the value
 * that is larger than a supplied buffer.
 * Thanks to Adam Zeldis to pointing snprintf()-caused vulnerability
 * in his audit report.
 */
static int
mg_vsnprintf(char *buf, size_t buflen, const char *fmt, va_list ap)
{
	int	n;

	if (buflen == 0)
		return (0);

	n = vsnprintf(buf, buflen, fmt, ap);

	if (n < 0) {
		cry("vsnprintf error");
		n = 0;
	} else if (n >= (int) buflen) {
		cry("truncating vsnprintf buffer");
		n = (int) buflen - 1;
	}
	buf[n] = '\0';

	return (n);
}

static int
mg_snprintf(char *buf, size_t buflen, const char *fmt, ...)
{
	va_list	ap;
	int	n;

	va_start(ap, fmt);
	n = mg_vsnprintf(buf, buflen, fmt, ap);
	va_end(ap);

	return (n);
}

/*
 * Convert string representing a boolean value to a boolean value
 */
static bool_t
is_true(const char *str)
{
	static const char *trues[] = {"1", "yes", "true", "jawohl", NULL};
	const char	**p;

	for (p = trues; *p != NULL; p++)
		if (str && !mg_strcasecmp(str, *p))
			return (TRUE);

	return (FALSE);
}

/*
 * Skip the characters until one of the delimiters characters found.
 * 0-terminate resulting word. Skip the rest of the delimiters if any.
 * Advance pointer to buffer to the next word. Return found 0-terminated word.
 */
static char *
skip(char **buf, const char *delimiters)
{
	char	*p, *begin_word, *end_word, *end_delimiters;

	begin_word = *buf;
	end_word = begin_word + strcspn(begin_word, delimiters);
	end_delimiters = end_word + strspn(end_word, delimiters);

	for (p = end_word; p < end_delimiters; p++)
		*p = '\0';

	*buf = end_delimiters;

	return (begin_word);
}

/*
 * Return HTTP header value, or NULL if not found.
 */
static const char *
get_header(const struct mg_request_info *ri, const char *name)
{
	int	i;

	for (i = 0; i < ri->num_headers; i++)
		if (!mg_strcasecmp(name, ri->http_headers[i].name))
			return (ri->http_headers[i].value);

	return (NULL);
}

const char *
mg_get_header(const struct mg_connection *conn, const char *name)
{
	return (get_header(&conn->request_info, name));
}

#if !(defined(NO_CGI) && defined(NO_SSI))
/*
 * Verify that given file has certain extension
 */
static bool_t
match_extension(const char *path, const char *ext_list)
{
	size_t		len, path_len;

	path_len = strlen(path);

	FOR_EACH_WORD_IN_LIST(ext_list, len)
		if (len < path_len && path[path_len - (len + 1)] == '.' &&
		    !mg_strncasecmp(path + path_len - len, ext_list, len))
			return (TRUE);

	return (FALSE);
}
#endif /* !(NO_CGI && NO_SSI) */

static bool_t
match_regex(const char *uri, const char *regexp)
{
	if (*regexp == '\0')
		return (*uri == '\0');

	if (*regexp == '*')
		do {
			if (match_regex(uri, regexp + 1))
				return (TRUE);
		} while (*uri++ != '\0');

	if (*uri != '\0' && *regexp == *uri)
		return (match_regex(uri + 1, regexp + 1));

	return (FALSE);
}

static const struct callback *
find_callback(const struct mg_context *ctx, bool_t is_auth,
		const char *uri, int status_code)
{
	const struct callback	*cb;
	int			i;

	for (i = 0; i < ctx->num_callbacks; i++) {
		cb = ctx->callbacks + i;
		if ((uri != NULL && cb->uri_regex != NULL &&
		    ((is_auth && cb->is_auth) || (!is_auth && !cb->is_auth)) &&
		    match_regex(uri, cb->uri_regex)) || (uri == NULL &&
		     (cb->status_code == 0 || cb->status_code == status_code)))
		    return (cb);
	}

	return (NULL);
}

/*
 * Send error message back to a client.
 */
static void
send_error(struct mg_connection *conn, int status, const char *reason,
		const char *fmt, ...)
{
	const struct callback	*cb;
	char		buf[BUFSIZ];
	va_list		ap;
	int		len;

	conn->request_info.status_code = status;

	/* If error handler is set, call it. Otherwise, send error message */
	if ((cb = find_callback(conn->ctx, FALSE, NULL, status)) != NULL) {
		cb->func(conn, &conn->request_info, cb->user_data);
	} else {
		(void) mg_printf(conn,
		    "HTTP/1.1 %d %s\r\n"
		    "Content-Type: text/plain\r\n"
		    "Connection: close\r\n"
		    "\r\n", status, reason);

		/* Errors 1xx, 204 and 304 MUST NOT send a body */
		if (status > 199 && status != 204 && status != 304) {
			conn->num_bytes_sent = mg_printf(conn,
			    "Error %d: %s\n", status, reason);

			va_start(ap, fmt);
			len = mg_vsnprintf(buf, sizeof(buf), fmt, ap);
			va_end(ap);
			conn->num_bytes_sent += mg_write(conn, buf, len);
		}
	}
}

#ifdef _WIN32
static int
pthread_mutex_init(pthread_mutex_t *mutex, void *unused) {
	unused = NULL;
	*mutex = CreateMutex(NULL, FALSE, NULL);
	return (*mutex == NULL ? -1 : 0);
}

static int
pthread_mutex_destroy(pthread_mutex_t *mutex) {
	CloseHandle(*mutex);
	return (0);
}

static int
pthread_mutex_lock(pthread_mutex_t *mutex) {
	return (WaitForSingleObject(*mutex, INFINITE) == WAIT_OBJECT_0? 0 : -1);
}

static int
pthread_mutex_unlock(pthread_mutex_t *mutex) {
	return (ReleaseMutex(*mutex) == 0 ? -1 : 0);
}

static void
fix_directory_separators(char *path)
{
	for (; *path != '\0'; path++) {
		if (*path == '/')
			*path = '\\';
		if (*path == '\\')
			while (path[1] == '\\' || path[1] == '/')
				(void) memmove(path + 1,
				    path + 2, strlen(path + 2) + 1);
	}
}

static void
to_unicode(const char *path, wchar_t *wbuf, size_t wbuf_len)
{
	char	buf[FILENAME_MAX], *p;

	mg_strlcpy(buf, path, sizeof(buf));
	fix_directory_separators(buf);

	/* Point p to the end of the file name */
	p = buf + strlen(buf) - 1;

	/* Trim trailing backslash character */
	while (p > buf && *p == '\\' && p[-1] != ':')
		*p-- = '\0';

	/*
	 * Protect from CGI code disclosure.
	 * This is very nasty hole. Windows happily opens files with
	 * some garbage in the end of file name. So fopen("a.cgi    ", "r")
	 * actually opens "a.cgi", and does not return an error!
	 */
	if (*p == 0x20 || *p == 0x2e || *p == 0x2b || (*p & ~0x7f)) {
		cry("Rejecting suspicious path: [%s]", buf);
		buf[0] = '\0';
	}

	MultiByteToWideChar(CP_UTF8, 0, buf, -1, wbuf, (int) wbuf_len);
}

static int
mg_open(const char *path, int flags, int mode)
{
	wchar_t	wbuf[FILENAME_MAX];

	to_unicode(path, wbuf, ARRAY_SIZE(wbuf));

	return (_wopen(wbuf, flags, mode));
}

static int
mg_stat(const char *path, struct stat *stp)
{
	wchar_t	wbuf[FILENAME_MAX];

	to_unicode(path, wbuf, ARRAY_SIZE(wbuf));

	return (_wstat(wbuf, (struct _stat *) stp));
}

static int
mg_remove(const char *path)
{
	wchar_t	wbuf[FILENAME_MAX];

	to_unicode(path, wbuf, ARRAY_SIZE(wbuf));

	return (_wremove(wbuf));
}

static DIR *
opendir(const char *name)
{
	DIR	*dir = NULL;
	char	path[FILENAME_MAX];
	wchar_t	wpath[FILENAME_MAX];

	if (name == NULL || name[0] == '\0') {
		errno = EINVAL;
	} else if ((dir = (DIR *) malloc(sizeof(*dir))) == NULL) {
		errno = ENOMEM;
	} else {
		mg_snprintf(path, sizeof(path), "%s/*", name);
		to_unicode(path, wpath, ARRAY_SIZE(wpath));
		dir->handle = FindFirstFileW(wpath, &dir->info);

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

static struct dirent *
readdir(DIR *dir)
{
	struct dirent *result = 0;

	if (dir && dir->handle != INVALID_HANDLE_VALUE) {
		if(!dir->result.d_name ||
		    FindNextFileW(dir->handle, &dir->info)) {
			result = &dir->result;

			WideCharToMultiByte(CP_UTF8, 0, dir->info.cFileName,
			    -1, result->d_name,
			    sizeof(result->d_name), NULL, NULL);
		}
	} else {
		errno = EBADF;
	}

	return (result);
}

#define	set_close_on_exec(fd)	/* No FD_CLOEXEC on Windows */

static int
start_thread(void * (*func)(void *), void *param)
{
#ifdef _MT
	return (_beginthread((void (__cdecl *)( void *))func, 0, param) == 0);
#else
	return -1;
#endif
}

static bool_t
spawn_process(struct mg_connection *conn, const char *prog, char *envblk,
		char *envp[], int fd_stdin, int fd_stdout, const char *dir)
{
	HANDLE	me;
	char	*p, *interp, cmdline[FILENAME_MAX], line[FILENAME_MAX];
	FILE	*fp;
	bool_t	retval;
	STARTUPINFOA		si;
	PROCESS_INFORMATION	pi;

	envp = NULL; /* Unused */

	(void) memset(&si, 0, sizeof(si));
	(void) memset(&pi, 0, sizeof(pi));

	/* XXX redirect CGI errors to the error log file */
	si.cb		= sizeof(si);
	si.dwFlags	= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow	= SW_HIDE;

	me = GetCurrentProcess();
	DuplicateHandle(me, (HANDLE) _get_osfhandle(fd_stdin), me,
	    &si.hStdInput, 0, TRUE, DUPLICATE_SAME_ACCESS);
	DuplicateHandle(me, (HANDLE) _get_osfhandle(fd_stdout), me,
	    &si.hStdOutput, 0, TRUE, DUPLICATE_SAME_ACCESS);

	/* If CGI file is a script, try to read the interpreter line */
	interp = conn->ctx->options[OPT_CGI_INTERPRETER];
	if (interp == NULL) {
		line[2] = '\0';
		(void) mg_snprintf(cmdline, sizeof(cmdline), "%s%c%s",
		    dir, DIRSEP, prog);
		if ((fp = fopen(cmdline, "r")) != NULL) {
			(void) fgets(line, sizeof(line), fp);
			if (memcmp(line, "#!", 2) != 0)
				line[2] = '\0';
			/* Trim whitespaces from interpreter name */
			for (p = &line[strlen(line) - 1]; p > line &&
			    isspace(*p); p--)
				*p = '\0';
			(void) fclose(fp);
		}
		interp = line + 2;
		(void) mg_snprintf(cmdline, sizeof(cmdline), "%s%s%s",
		    line + 2, line[2] == '\0' ? "" : " ", prog);
	}

	if ((p = (char *) strrchr(prog, '/')) != NULL)
		prog = p + 1;

	(void) mg_snprintf(cmdline, sizeof(cmdline), "%s %s", interp, prog);
	(void) mg_snprintf(line, sizeof(line), "%s", dir);
	fix_directory_separators(line);
	fix_directory_separators(cmdline);

	if (CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
	    CREATE_NEW_PROCESS_GROUP, envblk, line, &si, &pi) == 0) {
		cry("%s: CreateProcess(%s): %d", __func__, cmdline, ERRNO);
		retval = FALSE;
	} else {
		close(fd_stdin);
		close(fd_stdout);
		retval = TRUE;
	}

	CloseHandle(si.hStdOutput);
	CloseHandle(si.hStdInput);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return (retval);
}

static int
pipe(int *fds)
{
	return (_pipe(fds, BUFSIZ, _O_BINARY));
}

static int
mg_mkdir(const char *path, int mode)
{
	char	buf[FILENAME_MAX];
	wchar_t	wbuf[FILENAME_MAX];

	mode = 0; /* Unused */
	mg_strlcpy(buf, path, sizeof(buf));
	fix_directory_separators(buf);

	MultiByteToWideChar(CP_UTF8, 0, buf, -1, wbuf, sizeof(wbuf));

	return (_wmkdir(wbuf));
}

#else

static void
set_close_on_exec(int fd)
{
	(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
}

static int
start_thread(void * (*func)(void *), void *param)
{
	pthread_t	thread_id;
	pthread_attr_t	attr;
	int		retval;

	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	if ((retval = pthread_create(&thread_id, &attr, func, param)) != 0)
		cry("%s: %s", __func__, strerror(retval));

	return (retval);
}

#ifndef NO_CGI
static bool_t
spawn_process(struct mg_connection *conn, const char *prog, char *envblk,
		char *envp[], int fd_stdin, int fd_stdout, const char *dir)
{
	int		ret;
	pid_t		pid;
	const char	*interp;

	envblk = NULL;	/* unused */
	ret = FALSE;

	if ((pid = fork()) == -1) {
		/* Parent */
		ret = -1;
		send_error(conn, 500, http_500_error,
		    "fork(): %s", strerror(ERRNO));
	} else if (pid == 0) {
		/* Child */
		if (chdir(dir) != 0) {
			cry("chdir(%s): %s", dir, strerror(ERRNO));
		} else if (dup2(fd_stdin, 0) == -1) {
			cry("dup2(stdin, %d): %s", fd_stdin, strerror(ERRNO));
		} else if (dup2(fd_stdout, 1) == -1) {
			cry("dup2(stdout, %d): %s", fd_stdout, strerror(ERRNO));
		} else {
			/* If error file is specified, send errors there */
			if (error_log != NULL)
				(void) dup2(fileno(error_log), 2);

			(void) close(fd_stdin);
			(void) close(fd_stdout);

			/* Execute CGI program */
			interp = conn->ctx->options[OPT_CGI_INTERPRETER];
			if (interp == NULL) {
				(void) execle(prog, prog, NULL, envp);
				cry("execle(%s): %s", prog, strerror(ERRNO));
			} else {
				(void) execle(interp, interp, prog, NULL, envp);
				cry("execle(%s %s): %s",
				    interp, prog, strerror(ERRNO));
			}
		}
		exit(EXIT_FAILURE);
	} else {
		/* Parent. Suspended until child does execle() */
		(void) close(fd_stdin);
		(void) close(fd_stdout);
		ret = TRUE;
	}

	return (ret);
}
#endif /* !NO_CGI */
#endif /* _WIN32 */

static void
mg_lock(struct mg_context *ctx)
{
	if (pthread_mutex_lock(&ctx->mutex) != 0)
		cry("pthread_mutex_lock: %s", strerror(ERRNO));
}

static void
mg_unlock(struct mg_context *ctx)
{
	if (pthread_mutex_unlock(&ctx->mutex) != 0)
		cry("pthread_mutex_unlock: %s", strerror(ERRNO));
}

/*
 * Write data to the IO channel - opened file descriptor, socket or SSL
 * descriptor. Return number of bytes written.
 */
static uint64_t
push(int fd, SOCKET sock, SSL *ssl, const char *buf, uint64_t len)
{
	uint64_t	sent;
	int		n, k;

	sent = 0;
	while (sent < len) {

		/* How many bytes we send in this iteration */
		k = len - sent > INT_MAX ? INT_MAX : (int) (len - sent);

		if (ssl != NULL) {
			n = SSL_write(ssl, buf + sent, k);
		} else if (fd != -1) {
			n = write(fd, buf + sent, k);
		} else {
#ifdef __GNUC__
			n = send(sock, buf + sent, k, MSG_NOSIGNAL);
#else
			n = send(sock, buf + sent, k, 0);
#endif
		}

		if (n < 0) {
			cry("%s: %s", __func__, strerror(ERRNO));
			break;
		} else {
			sent += n;
		}
	}

	return (sent);
}

/*
 * Read from IO channel - opened file descriptor, socket, or SSL descriptor.
 * Return number of bytes read.
 */
static int
pull(int fd, SOCKET sock, SSL *ssl, char *buf, int len)
{
	int	nread;

	if (ssl != NULL) {
		nread = SSL_read(ssl, buf, len);
	} else if (fd != -1) {
		nread = read(fd, buf, (size_t) len);
	} else {
		nread = recv(sock, buf, (size_t) len, 0);
	}

	if (nread < 0)
		cry("%s failed: %s", "recv", strerror(ERRNO));

	return (nread);
}

int
mg_write(struct mg_connection *conn, const void *buf, int len)
{
	int first_result = 0;
	int second_result = 0;
	assert(len >= 0);

	/*ROB: if there is a response header, then first add this to
	 * the response header */
	if (conn->response_header_length) {
		int append_length;

		append_length = sizeof(conn->response_header) - conn->response_header_length;
		if (append_length > len)
			append_length = len;
		memcpy(	conn->response_header + conn->response_header_length,
				buf,
				append_length);
		buf = (unsigned char*)buf + append_length;
		len -= append_length;
		conn->response_header_length += append_length;

		first_result = (int) push(-1, conn->sock, conn->ssl, (const char *)conn->response_header, (uint64_t) conn->response_header_length);
		conn->response_header_length = 0;
		if (first_result <= 0 || len == 0)
			return first_result;
	}

	second_result = ((int) push(-1, conn->sock, conn->ssl,
				(const char *) buf, (uint64_t) len));
	if (second_result < 0)
		return second_result;
	return first_result + second_result;
}


int
mg_header_printf(struct mg_connection *conn, const char *fmt, ...)
{
	char *buf = conn->response_header + conn->response_header_length;
	unsigned sizeof_buf = sizeof(conn->response_header) - conn->response_header_length;
	int	len;
	va_list	ap;

	va_start(ap, fmt);
	len = mg_vsnprintf(buf, sizeof_buf, fmt, ap);
	va_end(ap);

	if (len > 0)
		conn->response_header_length += len;

	return len;
}

int mg_headers_ok(struct mg_connection *conn, const char *content_type)
{
	static const char *fmt = "%a, %d %b %Y %H:%M:%S GMT";
	time_t timestamp;
	char field_date[64];

	timestamp = time(0); /* current time, "now" */	
	strftime(field_date, sizeof(field_date), fmt, gmtime(&timestamp));


	mg_header_printf(conn, "HTTP/1.0 200 OK\r\n");
	mg_header_printf(conn, "Date: %s\r\n",			field_date);
	mg_header_printf(conn, "Server: %s\r\n",		"leapcrack/1.0");
	mg_header_printf(conn, "Content-Type: %s\r\n",	content_type);

	return 0;
}

int
mg_printf(struct mg_connection *conn, const char *fmt, ...)
{
	char	buf[MAX_REQUEST_SIZE];
	int	len;
	va_list	ap;

	va_start(ap, fmt);
	len = mg_vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	return (mg_write(conn, buf, len));
}

/*
 * Return content length of the request, or UNKNOWN_CONTENT_LENGTH constant if
 * Content-Length header is not set.
 */
static uint64_t
get_content_length(const struct mg_connection *conn)
{
	const char *cl = mg_get_header(conn, "Content-Length");
	return (cl == NULL ? UNKNOWN_CONTENT_LENGTH : strtoull(cl, NULL, 10));
}

/*
 * URL-decode input buffer into destination buffer.
 * 0-terminate the destination buffer. Return the length of decoded data.
 * form-url-encoded data differs from URI encoding in a way that it
 * uses '+' as character for space, see RFC 1866 section 8.2.1
 * http://ftp.ics.uci.edu/pub/ietf/html/rfc1866.txt
 */
static size_t
url_decode(const char *src, size_t src_len, char *dst, size_t dst_len,
		bool_t is_form_url_encoded)
{
	size_t	i, j;
	int	a, b;
#define	HEXTOI(x)  (isdigit(x) ? x - '0' : x - 'W')

	for (i = j = 0; i < src_len && j < dst_len - 1; i++, j++) {
		if (src[i] == '%' &&
		    isxdigit(* (unsigned char *) (src + i + 1)) &&
		    isxdigit(* (unsigned char *) (src + i + 2))) {
			a = tolower(* (unsigned char *) (src + i + 1));
			b = tolower(* (unsigned char *) (src + i + 2));
			dst[j] = (char)(((HEXTOI(a) << 4) | HEXTOI(b)) & 0xff);
			i += 2;
		} else if (is_form_url_encoded && src[i] == '+') {
			dst[j] = ' ';
		} else {
			dst[j] = src[i];
		}
	}

	dst[j] = '\0';	/* Null-terminate the destination */

	return (j);
}

/*
 * Search for a form variable in a given buffer.
 * Semantic is the same as for mg_get_var().
 */
static char *
get_var(const char *name, const char *buf, size_t buf_len)
{
	const char	*p, *e, *s;
	char		tmp[BUFSIZ];
	size_t		var_len;

	var_len = strlen(name);
	e = buf + buf_len;

	/* buf is "var1=val1&var2=val2...". Find variable first */
	for (p = buf; p + var_len < e; p++)
		if ((p == buf || p[-1] == '&') && p[var_len] == '=' &&
		    !mg_strncasecmp(name, p, var_len)) {

			/* Point p to variable value */
			p += var_len + 1;

			/* Point s to the end of the value */
			s = (const char *) memchr(p, '&', e - p);
			if (s == NULL)
				s = e;

			/* URL-decode value. Return result length */
			(void) url_decode(p, s - p, tmp, sizeof(tmp), TRUE);
			return (mg_strdup(tmp));
		}

	return (NULL);
}

void
mg_free_var(char *value)
{
	if (value)
		free(value);
}

/*
 * Return form data variable.
 * It can be specified in query string, or in the POST data.
 * Return NULL if the variable not found, or allocated 0-terminated value.
 * It is caller's responsibility to free the returned value.
 */
char *
mg_get_var(const struct mg_connection *conn, const char *name)
{
	const struct mg_request_info	*ri = &conn->request_info;
	char				*v1, *v2;

	v1 = v2 = NULL;

	/* Look in both query_string and POST data */
	if (ri->query_string != NULL)
		v1 = get_var(name, ri->query_string, strlen(ri->query_string));
	if (ri->post_data_len > 0)
		v2 = get_var(name, ri->post_data, ri->post_data_len);

	/* If they both have queried variable, POST data wins */
	if (v1 != NULL && v2 != NULL)
		free(v1);

	return (v2 == NULL ? v1 : v2);
}

/*
 * Transform URI to the file name.
 */
static void
make_path(struct mg_context *ctx, const char *uri, char *buf, size_t buf_len)
{
	char	*p, *s;
	size_t	len;

	mg_snprintf(buf, buf_len, "%s%s", ctx->options[OPT_ROOT], uri);

	/* If requested URI has aliased prefix, use alternate root */
	mg_lock(ctx);
       	s = ctx->options[OPT_ALIASES];
	FOR_EACH_WORD_IN_LIST(s, len) {

		p = (char *) memchr(s, '=', len);
		if (p == NULL || p >= s + len || p == s)
			continue;

		if (memcmp(uri, s, p - s) == 0) {
			(void) mg_snprintf(buf, buf_len, "%.*s%s",
			    (s + len) - p - 1, p + 1, uri + (p - s));
			break;
		}
	}
	mg_unlock(ctx);

	/* Remove trailing '/' characters, if directory is requested */
	for (p = buf + strlen(buf) - 1; p > buf && *p == '/'; p--)
		*p = '\0';

#ifdef _WIN32
	for (p = buf; *p != '\0'; p++)
		if (*p == '/')
			*p = '\\';
#endif /* _WIN32 */
}

/*
 * Setup listening socket on given port, return socket
 */
static SOCKET
mg_open_listening_port(int ip_address, int port)
{
	SOCKET		sock;
	int		on = 1;
	struct usa	sa;

printf("DEBUG: mg_open_listening_port(%d)\n", port);
	sa.len				= sizeof(sa.u.sin);
	sa.u.sin.sin_family		= AF_INET;
	sa.u.sin.sin_port		= htons((uint16_t) port);
	sa.u.sin.sin_addr.s_addr	= htonl(ip_address);

	if ((sock = socket(PF_INET, SOCK_STREAM, 6)) != INVALID_SOCKET &&
	    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
	    (char *) &on, sizeof(on)) == 0 &&
	    bind(sock, &sa.u.sa, sa.len) == 0 &&
	    listen(sock, 128) == 0) {
		/* Success */
		set_close_on_exec(sock);
		fprintf(stderr, "Proxy: listening on %u.%u.%u.%u:%u\n",
			((ip_address>>24)&0xFF),
			((ip_address>>16)&0xFF),
			((ip_address>> 8)&0xFF),
			((ip_address>> 0)&0xFF),
			port);

	} else {
		/* Error */
		fprintf(stderr, "listen(%u,%d): %s", ip_address, port, strerror(errno));
		cry("open_listening_port(%d): %s", port, strerror(errno));
		if (sock != INVALID_SOCKET)
			(void) closesocket(sock);
		sock = INVALID_SOCKET;
	}

	return (sock);
}

/*
 * Check whether full request is buffered Return headers length, or 0
 */
static int
get_request_len(const char *buf, size_t buflen)
{
	const char	*s, *e;
	int		len = 0;

	for (s = buf, e = s + buflen - 1; len <= 0 && s < e; s++)
		/* Control characters are not allowed but >=128 is. */
		if (!isprint(* (unsigned char *) s) && *s != '\r' &&
		    *s != '\n' && * (unsigned char *) s < 128)
			len = -1;
		else if (s[0] == '\n' && s[1] == '\n')
			len = (int) (s - buf) + 2;
		else if (s[0] == '\n' && &s[1] < e &&
		    s[1] == '\r' && s[2] == '\n')
			len = (int) (s - buf) + 3;

	return (len);
}

/*
 * Convert month to the month number. Return -1 on error, or month number
 */
static int
montoi(const char *s)
{
	static const char *month_names[] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	};
	size_t	i;

	for (i = 0; i < sizeof(month_names) / sizeof(month_names[0]); i++)
		if (!strcmp(s, month_names[i]))
			return ((int) i);

	return (-1);
}

/*
 * Parse date-time string, and return the corresponding time_t value
 */
static time_t
date_to_epoch(const char *s)
{
	struct tm	tm, *tmp;
	time_t		current_time;
	char		mon[32];
	int		sec, min, hour, mday, month, year;

	(void) memset(&tm, 0, sizeof(tm));
	sec = min = hour = mday = month = year = 0;

	if (((sscanf(s, "%d/%3s/%d %d:%d:%d",
	    &mday, mon, &year, &hour, &min, &sec) == 6) ||
	    (sscanf(s, "%d %3s %d %d:%d:%d",
	    &mday, mon, &year, &hour, &min, &sec) == 6) ||
	    (sscanf(s, "%*3s, %d %3s %d %d:%d:%d",
	    &mday, mon, &year, &hour, &min, &sec) == 6) ||
	    (sscanf(s, "%d-%3s-%d %d:%d:%d",
	    &mday, mon, &year, &hour, &min, &sec) == 6)) &&
	    (month = montoi(mon)) != -1) {
		tm.tm_mday	= mday;
		tm.tm_mon	= month;
		tm.tm_year	= year;
		tm.tm_hour	= hour;
		tm.tm_min	= min;
		tm.tm_sec	= sec;
	}

	if (tm.tm_year > 1900)
		tm.tm_year -= 1900;
	else if (tm.tm_year < 70)
		tm.tm_year += 100;

	/* Set Daylight Saving Time field */
	current_time = time(NULL);
	tmp = localtime(&current_time);
	tm.tm_isdst = tmp->tm_isdst;

	return (mktime(&tm));
}

static void
remove_double_dots(char *s)
{
	char	*p = s;

	while (*s != '\0') {
		*p++ = *s++;
		if (s[-1] == '/' || s[-1] == '\\')
			while (*s == '.' || *s == '/' || *s == '\\')
				s++;
	}
	*p = '\0';
}

static const struct {
	const char	*extension;
	const char	*mime_type;
} mime_types[] = {
	{"html",	"text/html"			},
	{"htm",		"text/html"			},
	{"shtm",	"text/html"			},
	{"shtml",	"text/html"			},
	{"css",		"text/css"			},
	{"xsl",		"text/xsl"			},
	{"js",		"application/x-javascript"	},
	{"ico",		"image/x-icon"			},
	{"gif",		"image/gif"			},
	{"jpg",		"image/jpeg"			},
	{"jpeg",	"image/jpeg"			},
	{"png",		"image/png"			},
	{"svg",		"image/svg+xml"			},
	{"torrent",	"application/x-bittorrent"	},
	{"wav",		"audio/x-wav"			},
	{"mp3",		"audio/x-mp3"			},
	{"mid",		"audio/mid"			},
	{"m3u",		"audio/x-mpegurl"		},
	{"ram",		"audio/x-pn-realaudio"		},
	{"ra",		"audio/x-pn-realaudio"		},
	{"doc",		"application/msword",		},
	{"exe",		"application/octet-stream"	},
	{"zip",		"application/x-zip-compressed"	},
	{"xls",		"application/excel"		},
	{"tgz",		"application/x-tar-gz"		},
	{"tar.gz",	"application/x-tar-gz"		},
	{"tar",		"application/x-tar"		},
	{"gz",		"application/x-gunzip"		},
	{"arj",		"application/x-arj-compressed"	},
	{"rar",		"application/x-arj-compressed"	},
	{"rtf",		"application/rtf"		},
	{"pdf",		"application/pdf"		},
	{"swf",		"application/x-shockwave-flash"	},
	{"mpg",		"video/mpeg"			},
	{"mpeg",	"video/mpeg"			},
	{"asf",		"video/x-ms-asf"		},
	{"avi",		"video/x-msvideo"		},
	{"bmp",		"image/bmp"			},
	{NULL,		NULL				}
};

static const char *
get_mime_type(const char *path)
{
	const char	*extension;
	size_t		i, ext_len;

	if ((extension = strrchr(path, '.')) != NULL) {

		extension++;
		ext_len = strlen(extension);

		/* If no luck, try built-in mime types */
		for (i = 0; mime_types[i].extension != NULL; i++)
			if (!mg_strcasecmp(extension,
			    mime_types[i].extension))
				return (mime_types[i].mime_type);
	}

	return ("text/plain");
}

#if !defined(NO_AUTH)
#ifndef HAVE_MD5
typedef struct MD5Context {
	uint32_t	buf[4];
	uint32_t	bits[2];
	unsigned char	in[64];
} MD5_CTX;

#if __BYTE_ORDER == 1234
#define byteReverse(buf, len)	/* Nothing */
#else
/*
 * Note: this code is harmless on little-endian machines.
 */
static void
byteReverse(unsigned char *buf, unsigned longs)
{
	uint32_t t;
	do {
		t = (uint32_t) ((unsigned) buf[3] << 8 | buf[2]) << 16 |
			((unsigned) buf[1] << 8 | buf[0]);
		*(uint32_t *) buf = t;
		buf += 4;
	} while (--longs);
}
#endif /* __BYTE_ORDER */

/* The four core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#define MD5STEP(f, w, x, y, z, data, s) \
( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
static void
MD5Init(MD5_CTX *ctx)
{
	ctx->buf[0] = 0x67452301;
	ctx->buf[1] = 0xefcdab89;
	ctx->buf[2] = 0x98badcfe;
	ctx->buf[3] = 0x10325476;

	ctx->bits[0] = 0;
	ctx->bits[1] = 0;
}

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */
static void
MD5Transform(uint32_t buf[4], uint32_t const in[16])
{
	register uint32_t a, b, c, d;

	a = buf[0];
	b = buf[1];
	c = buf[2];
	d = buf[3];

	MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
	MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
	MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
	MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
	MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
	MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
	MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
	MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
	MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
	MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
	MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
	MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
	MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
	MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
	MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
	MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

	MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
	MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
	MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
	MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
	MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
	MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
	MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
	MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
	MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
	MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
	MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
	MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
	MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
	MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
	MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
	MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

	MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
	MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
	MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
	MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
	MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
	MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
	MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
	MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
	MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
	MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
	MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
	MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
	MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
	MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
	MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
	MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

	MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
	MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
	MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
	MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
	MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
	MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
	MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
	MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
	MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
	MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
	MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
	MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
	MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
	MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
	MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
	MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

	buf[0] += a;
	buf[1] += b;
	buf[2] += c;
	buf[3] += d;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
static void
MD5Update(MD5_CTX *ctx, unsigned char const *buf, unsigned len)
{
	uint32_t t;

	/* Update bitcount */

	t = ctx->bits[0];
	if ((ctx->bits[0] = t + ((uint32_t) len << 3)) < t)
		ctx->bits[1]++;		/* Carry from low to high */
	ctx->bits[1] += len >> 29;

	t = (t >> 3) & 0x3f;	/* Bytes already in shsInfo->data */

	/* Handle any leading odd-sized chunks */

	if (t) {
		unsigned char *p = (unsigned char *) ctx->in + t;

		t = 64 - t;
		if (len < t) {
			memcpy(p, buf, len);
			return;
		}
		memcpy(p, buf, t);
		byteReverse(ctx->in, 16);
		MD5Transform(ctx->buf, (uint32_t *) ctx->in);
		buf += t;
		len -= t;
	}
	/* Process data in 64-byte chunks */

	while (len >= 64) {
		memcpy(ctx->in, buf, 64);
		byteReverse(ctx->in, 16);
		MD5Transform(ctx->buf, (uint32_t *) ctx->in);
		buf += 64;
		len -= 64;
	}

	/* Handle any remaining bytes of data. */

	memcpy(ctx->in, buf, len);
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
static void
MD5Final(unsigned char digest[16], MD5_CTX *ctx)
{
	unsigned count;
	unsigned char *p;

	/* Compute number of bytes mod 64 */
	count = (ctx->bits[0] >> 3) & 0x3F;

	/* Set the first char of padding to 0x80.  This is safe since there is
	   always at least one byte free */
	p = ctx->in + count;
	*p++ = 0x80;

	/* Bytes of padding needed to make 64 bytes */
	count = 64 - 1 - count;

	/* Pad out to 56 mod 64 */
	if (count < 8) {
		/* Two lots of padding:  Pad the first block to 64 bytes */
		memset(p, 0, count);
		byteReverse(ctx->in, 16);
		MD5Transform(ctx->buf, (uint32_t *) ctx->in);

		/* Now fill the next block with 56 bytes */
		memset(ctx->in, 0, 56);
	} else {
		/* Pad block to 56 bytes */
		memset(p, 0, count - 8);
	}
	byteReverse(ctx->in, 14);

	/* Append length in bits and transform */
	((uint32_t *) ctx->in)[14] = ctx->bits[0];
	((uint32_t *) ctx->in)[15] = ctx->bits[1];

	MD5Transform(ctx->buf, (uint32_t *) ctx->in);
	byteReverse((unsigned char *) ctx->buf, 4);
	memcpy(digest, ctx->buf, 16);
	memset((char *) ctx, 0, sizeof(ctx));	/* In case it's sensitive */
}
#endif /* !HAVE_MD5 */

/*
 * Stringify binary data. Output buffer must be twice as big as input,
 * because each byte takes 2 bytes in string representation
 */
static void
bin2str(char *to, const unsigned char *p, size_t len)
{
	static const char *hex = "0123456789abcdef";

	for (; len--; p++) {
		*to++ = hex[p[0] >> 4];
		*to++ = hex[p[0] & 0x0f];
	}
	*to = '\0';
}

/*
 * Return stringified MD5 hash for list of vectors.
 * buf must point to 33-bytes long buffer
 */
void
mg_md5(char *buf, ...)
{
	unsigned char	hash[16];
	const char	*p;
	va_list		ap;
	MD5_CTX		ctx;

	MD5Init(&ctx);

	va_start(ap, buf);
	while ((p = va_arg(ap, const char *)) != NULL)
		MD5Update(&ctx, (unsigned char *) p, (int) strlen(p));
	va_end(ap);

	MD5Final(hash, &ctx);
	bin2str(buf, hash, sizeof(hash));
}

/*
 * Check the user's password, return 1 if OK
 */
static bool_t
check_password(const char *method, const char *ha1, const char *uri,
		const char *nonce, const char *nc, const char *cnonce,
		const char *qop, const char *response)
{
	char	ha2[32 + 1], expected_response[32 + 1];

	/* XXX  Due to a bug in MSIE, we do not compare the URI	 */
	/* Also, we do not check for authentication timeout */
	if (/*strcmp(dig->uri, c->ouri) != 0 || */
	    strlen(response) != 32 /*||
	    now - strtoul(dig->nonce, NULL, 10) > 3600 */)
		return (FALSE);

	mg_md5(ha2, method, ":", uri, NULL);
	mg_md5(expected_response, ha1, ":", nonce, ":", nc,
	    ":", cnonce, ":", qop, ":", ha2, NULL);

	return (!mg_strcasecmp(response, expected_response));
}

/*
 * Use the global passwords file, if specified by auth_gpass option,
 * or search for .htpasswd in the requested directory.
 */
static FILE *
open_auth_file(struct mg_context *ctx, const char *path)
{
	char 		name[FILENAME_MAX];
	const char	*p, *e;
	struct stat	st;
	FILE		*fp;

	if (ctx->options[OPT_AUTH_GPASSWD] != NULL) {
		/* Use global passwords file */
		if ((fp = fopen(ctx->options[OPT_AUTH_GPASSWD], "r")) == NULL)
			cry("fopen(%s): %s",
			    ctx->options[OPT_AUTH_GPASSWD], strerror(ERRNO));
	} else if (!mg_stat(path, &st) && S_ISDIR(st.st_mode)) {
		(void) mg_snprintf(name, sizeof(name), "%s%c%s",
		    path, DIRSEP, PASSWORDS_FILE_NAME);
		fp = fopen(name, "r");
	} else {
		/*
		 * Try to find .htpasswd in requested directory.
		 * Given the path, create the path to .htpasswd file
		 * in the same directory. Find the right-most
		 * directory separator character first. That would be the
		 * directory name. If directory separator character is not
		 * found, 'e' will point to 'p'.
		 */
		for (p = path, e = p + strlen(p) - 1; e > p; e--)
			if (IS_DIRSEP_CHAR(*e))
				break;

		/*
		 * Make up the path by concatenating directory name and
		 * .htpasswd file name.
		 */
		(void) mg_snprintf(name, sizeof(name), "%.*s%c%s",
		    (int) (e - p), p, DIRSEP, PASSWORDS_FILE_NAME);
		fp = fopen(name, "r");
	}

	return (fp);
}

struct ah {
	char	*user, *uri, *cnonce, *response, *qop, *nc, *nonce;
};

static bool_t
parse_auth_header(struct mg_connection *conn, char *buf, size_t buf_size,
		struct ah *ah)
{
	char		*name, *value, *s;
	const char	*auth_header;

	if ((auth_header = mg_get_header(conn, "Authorization")) == NULL ||
	    mg_strncasecmp(auth_header, "Digest ", 7) != 0)
		return (FALSE);

	/* Make modifiable copy of the auth header */
	(void) mg_strlcpy(buf, auth_header + 7, buf_size);

	s = buf;
	(void) memset(ah, 0, sizeof(*ah));

	/* Gobble initial spaces */
	while (isspace(* (unsigned char *) s))
		s++;

	/* Parse authorization header */
	for (;;) {
		name = skip(&s, "=");
		value = skip(&s, ", ");

		if (*value == '"') {
			value++;
			value[strlen(value) - 1] = '\0';
		} else if (*value == '\0') {
			break;
		}

		if (!strcmp(name, "username")) {
			ah->user = value;
		} else if (!strcmp(name, "cnonce")) {
			ah->cnonce = value;
		} else if (!strcmp(name, "response")) {
			ah->response = value;
		} else if (!strcmp(name, "uri")) {
			ah->uri = value;
		} else if (!strcmp(name, "qop")) {
			ah->qop = value;
		} else if (!strcmp(name, "nc")) {
			ah->nc = value;
		} else if (!strcmp(name, "nonce")) {
			ah->nonce = value;
		}
	}

	/* CGI needs it as REMOTE_USER */
	if (ah->user != NULL)
		conn->request_info.remote_user = mg_strdup(ah->user);

	return (TRUE);
}

/*
 * Authorize against the opened passwords file. Return 1 if authorized.
 */
static bool_t
authorize(struct mg_connection *conn, FILE *fp)
{
	struct ah	ah;
	char		line[256], f_user[256], domain[256], ha1[256],
			buf[MAX_REQUEST_SIZE];

	if (!parse_auth_header(conn, buf, sizeof(buf), &ah))
		return (FALSE);

	/* Loop over passwords file */
	while (fgets(line, sizeof(line), fp) != NULL) {

		if (sscanf(line, "%[^:]:%[^:]:%s", f_user, domain, ha1) != 3)
			continue;

		if (!strcmp(ah.user, f_user) &&
		    !strcmp(domain, conn->ctx->options[OPT_AUTH_DOMAIN]))
			return (check_password(
			    conn->request_info.request_method, ha1,
			    ah.uri, ah.nonce, ah.nc, ah.cnonce,
			    ah.qop, ah.response));
	}

	return (FALSE);
}

/*
 * Return TRUE if request is authorised, FALSE otherwise.
 */
static bool_t
check_authorization(struct mg_connection *conn, const char *path)
{
	FILE		*fp;
	size_t		len, n;
	char		protected_path[FILENAME_MAX];
	const char	*p, *s;
	const struct callback *cb;
	bool_t		authorized;

	fp = NULL;
	authorized = TRUE;

	mg_lock(conn->ctx);
	s = conn->ctx->options[OPT_PROTECT];
	FOR_EACH_WORD_IN_LIST(s, len) {

		p = (const char *) memchr(s, '=', len);
		if (p == NULL || p >= s + len || p == s)
			continue;

		if (!memcmp(conn->request_info.uri, s, p - s)) {

			n = (size_t) (s + len - p);
			if (n > sizeof(protected_path) - 1)
				n = sizeof(protected_path) - 1;

			mg_strlcpy(protected_path, p + 1, n);

			if ((fp = fopen(protected_path, "r")) == NULL)
				cry("check_auth: cannot open %s: %s",
				    protected_path, strerror(errno));
			break;
		}
	}
	mg_unlock(conn->ctx);

	if (fp == NULL)
		fp = open_auth_file(conn->ctx, path);

	if (fp != NULL) {
		authorized = authorize(conn, fp);
		(void) fclose(fp);
	}

	if ((cb = find_callback(conn->ctx, TRUE,
	    conn->request_info.uri, -1)) != NULL) {
		struct ah	ah;
		char		buf[MAX_REQUEST_SIZE];
		void		*user_data = cb->user_data;

		authorized = FALSE;
		if (parse_auth_header(conn, buf, sizeof(buf), &ah)) {
			cb->func(conn, &conn->request_info, &user_data);
			authorized = (bool_t) (long) user_data;
		}
	}

	return (authorized);
}

static void
send_authorization_request(struct mg_connection *conn)
{
	(void) mg_printf(conn,
	    "HTTP/1.1 401 Unauthorized\r\n"
	    "WWW-Authenticate: Digest qop=\"auth\", "
	    "realm=\"%s\", nonce=\"%lu\"\r\n\r\n",
	    conn->ctx->options[OPT_AUTH_DOMAIN], (unsigned long) time(NULL));
}

static bool_t
is_authorized_for_put(struct mg_connection *conn)
{
	FILE	*fp;
	int	ret = FALSE;

	if ((fp = fopen(conn->ctx->options[OPT_AUTH_PUT], "r")) != NULL) {
		set_close_on_exec(fileno(fp));
		ret = authorize(conn, fp);
		(void) fclose(fp);
	}

	return (ret);
}
#endif /* NO_AUTH */

static bool_t
does_client_want_keep_alive(const struct mg_connection *conn)
{
	const char *value = mg_get_header(conn, "Connection");

	/* HTTP/1.1 assumes keep-alive, if Connection header is not set */
	return ((value == NULL && conn->request_info.http_version_major == 1 &&
	    conn->request_info.http_version_minor == 1) || (value != NULL &&
	    !mg_strcasecmp(value, "keep-alive")));
}

struct de {
	struct mg_connection	*conn;
	char			*file_name;
	struct stat		st;
};

static void
print_dir_entry(struct de *de)
{
	char		size[64], mod[64];

	if (S_ISDIR(de->st.st_mode)) {
		(void) mg_snprintf(size, sizeof(size), "%s", "&lt;DIR&gt;");
	} else {
		if (de->st.st_size < 1024)
			(void) mg_snprintf(size, sizeof(size),
			    "%lu", (unsigned long) de->st.st_size);
		else if (de->st.st_size < 1024 * 1024)
			(void) mg_snprintf(size, sizeof(size),
			    "%.1fk", (double) de->st.st_size / 1024);
		else if (de->st.st_size < 1024 * 1024 * 1024)
			(void) mg_snprintf(size, sizeof(size),
			    "%.1fM", (double) de->st.st_size / 1048576);
		else
			(void) mg_snprintf(size, sizeof(size),
			    "%.1fG", (double) de->st.st_size / 1073741824);
	}
	(void) strftime(mod, sizeof(mod), "%d-%b-%Y %H:%M",
		localtime(&de->st.st_mtime));
	de->conn->num_bytes_sent += mg_printf(de->conn,
	    "<tr><td><a href=\"%s%s\">%s%s</a></td>"
	    "<td>&nbsp;%s</td><td>&nbsp;&nbsp;%s</td></tr>\n",
	    de->conn->request_info.uri, de->file_name, de->file_name,
	    S_ISDIR(de->st.st_mode) ? "/" : "", mod, size);
}

static int
compare_dir_entries(const void *p1, const void *p2)
{
	const struct de	*a = (struct de *) p1, *b = (struct de *) p2;
	const char	*q = a->conn->request_info.query_string;
	int		cmp_result = 0;

	if (*q == 'n') {
		cmp_result = strcmp(a->file_name, b->file_name);
	} else if (*q == 's') {
		cmp_result = a->st.st_size == b->st.st_size ? 0 :
			a->st.st_size > b->st.st_size ? 1 : -1;
	} else if (*q == 'd') {
		cmp_result = a->st.st_mtime == b->st.st_mtime ? 0 :
			a->st.st_mtime > b->st.st_mtime ? 1 : -1;
	}

	return (q[1] == 'd' ? -cmp_result : cmp_result);
}

static void
send_directory(struct mg_connection *conn, const char *dir)
{
	struct dirent	*dp;
	DIR		*dirp;
	struct de	*entries = NULL;
	char		path[FILENAME_MAX];
	int sort_direction;
	int		i, num_entries = 0, arr_size = 128;

	if ((dirp = opendir(dir)) == NULL) {
		send_error(conn, 500, "Cannot open directory",
		    "Error: opendir(%s): %s", path, strerror(ERRNO));
		return;
	}

	(void) mg_printf(conn, "%s",
	    "HTTP/1.1 200 OK\r\n"
	    "Connection: close\r\n"
	    "Content-Type: text/html; charset=utf-8\r\n\r\n");
	
	sort_direction = conn->request_info.query_string != NULL &&
	   ( conn->request_info.query_string[1] == 'd') ? 'a' : 'd';

	while ((dp = readdir(dirp)) != NULL) {

		/* Do not show current dir and passwords file */
		if (!strcmp(dp->d_name, ".") ||
		    !strcmp(dp->d_name, "..") ||
		    !strcmp(dp->d_name, PASSWORDS_FILE_NAME))
			continue;

		if (entries == NULL || num_entries >= arr_size) {
			arr_size *= 2;
			entries = (struct de *) realloc(entries,
			    arr_size * sizeof(entries[0]));
		}
		
		if (entries == NULL) {
			send_error(conn, 500, "Cannot open directory",
			    "%s", "Error: cannot allocate memory");
			return;
		}

		(void) mg_snprintf(path, sizeof(path), "%s%c%s",
		    dir, DIRSEP, dp->d_name);
		
		(void) stat(path, &entries[num_entries].st);
		entries[num_entries].conn = conn;
		entries[num_entries].file_name = mg_strdup(dp->d_name);
		num_entries++;
	}
	(void) closedir(dirp);

	if (conn->request_info.query_string != NULL)
		qsort(entries, num_entries,
		    sizeof(entries[0]), compare_dir_entries);

	conn->num_bytes_sent += mg_printf(conn,
	    "<html><head><title>Index of %s</title>"
	    "<style>th {text-align: left;}</style></head>"
	    "<body><h1>Index of %s</h1><pre><table cellpadding=\"0\">"
	    "<tr><th><a href=\"?n%c\">Name</a></th>"
	    "<th><a href=\"?d%c\">Modified</a></th>"
	    "<th><a href=\"?s%c\">Size</a></th></tr>"
	    "<tr><td colspan=\"3\"><hr></td></tr>",
	    conn->request_info.uri, conn->request_info.uri,
	    sort_direction, sort_direction, sort_direction);
	
	/* Print first entry - link to a parent directory */
	conn->num_bytes_sent += mg_printf(conn,
	    "<tr><td><a href=\"%s%s\">%s</a></td>"
	    "<td>&nbsp;%s</td><td>&nbsp;&nbsp;%s</td></tr>\n",
	    conn->request_info.uri, "..", "Parent directory", "-", "-");	

	for (i = 0; i < num_entries; i++) {
		print_dir_entry(&entries[i]);
		free(entries[i].file_name);
	}
	free(entries);

	conn->num_bytes_sent += mg_printf(conn, "%s", "</table></body></html>");
	conn->request_info.status_code = 200;
}

/*
 * Send len bytes from the opened file to the client.
 */
static void
send_opened_file_stream(struct mg_connection *conn, int fd, uint64_t len)
{
	char	buf[BUFSIZ];
	int	n;

	while (len > 0) {
		n = sizeof(buf);
		if ((uint64_t) n > len)
			n = (int) len;
		if ((n = read(fd, buf, n)) <= 0)
			break;
		conn->num_bytes_sent += mg_write(conn, buf, n);
		len -= n;
	}
}

static void
send_file(struct mg_connection *conn, const char *path, struct stat *stp)
{
	char		date[64], lm[64], etag[64], range[64];
	static const char	*fmt = "%a, %d %b %Y %H:%M:%S GMT"; /*ROB: should be 'static' */
	const char *msg = "OK";
	const char	*mime_type, *s;
	time_t		curtime = time(NULL);
	uint64_t cl, r1, r2;
	int		fd, n;

	mime_type = get_mime_type(path);
	cl = stp->st_size;
	conn->request_info.status_code = 200;
	range[0] = '\0';

	if ((fd = mg_open(path, O_RDONLY | O_BINARY, 0644)) == -1) {
		send_error(conn, 500, http_500_error,
		    "fopen(%s): %s", path, strerror(ERRNO));
		return;
	}
	set_close_on_exec(fd);

	/* If Range: header specified, act accordingly */
	s = mg_get_header(conn, "Range");
	r1 = r2 = 0;
	if (s != NULL && (n = sscanf(s,"bytes=" U64 "-" U64 "", &r1, &r2)) > 0) {
		conn->request_info.status_code = 206;
		(void) lseek(fd, (long) r1, SEEK_SET);
		cl = n == 2 ? r2 - r1 + 1: cl - r1;
		(void) mg_snprintf(range, sizeof(range),
		    "Content-Range: bytes " U64 "-" U64 "/" U64 "\r\n",
		    r1, r1 + cl - 1, cl);
		msg = "Partial Content";
	}

	/* Prepare Etag, Date, Last-Modified headers 
	 * ROB: changed from 'localtime' to 'gmtime' */
	(void) strftime(date, sizeof(date), fmt, gmtime(&curtime));
	(void) strftime(lm, sizeof(lm), fmt, gmtime(&stp->st_mtime));
	(void) mg_snprintf(etag, sizeof(etag), "%lx.%lx",
	    (unsigned long) stp->st_mtime, (unsigned long) stp->st_size);

	/* Since we send Content-Length, we can keep the connection alive */
	conn->keep_alive = does_client_want_keep_alive(conn);

	(void) mg_printf(conn,
	    "HTTP/1.1 %d %s\r\n"
	    "Date: %s\r\n"
	    "Last-Modified: %s\r\n"
	    "Etag: \"%s\"\r\n"
	    "Content-Type: %s\r\n"
	    "Content-Length: " U64 "\r\n"
	    "Connection: %s\r\n"
	    "Accept-Ranges: bytes\r\n"
	    "%s\r\n",
	    conn->request_info.status_code, msg, date, lm, etag, mime_type, cl,
	    conn->keep_alive ? "keep-alive" : "close", range);

	if (strcmp(conn->request_info.request_method, "HEAD") != 0)
		send_opened_file_stream(conn, fd, cl);
	(void) close(fd);
}

static void
parse_http_headers(char **buf, struct mg_request_info *ri)
{
	int	i;

	for (i = 0; i < MAX_HTTP_HEADERS; i++) {
		ri->http_headers[i].name = skip(buf, ": ");
		ri->http_headers[i].value = skip(buf, "\r\n");
		if (ri->http_headers[i].name[0] == '\0')
			break;
		ri->num_headers = i + 1;
	}
}

static bool_t
is_known_http_method(const char *method)
{
	return (!strcmp(method, "GET") ||
	    !strcmp(method, "POST") ||
	    !strcmp(method, "HEAD") ||
	    !strcmp(method, "PUT") ||
	    !strcmp(method, "DELETE"));
}

static void
parse_proxy_info(char **buf, struct mg_request_info *ri)
{
	char *p;

	ri->proxy_protocol = 0;
	ri->proxy_host = 0;
	ri->proxy_port = "80";

	while (isspace(**buf) && **buf != '\r' && **buf != '\n')
		(*buf)++;

	if (!isalpha(**buf))
		return;

	ri->proxy_protocol = skip(buf, ":");

	/* shift left hostname */
	for (p = *buf; *p == '/'; p++)
		;
	for (; *p != '/'; p++)
		;
	memmove(*buf, (*buf)+1, p-(*buf));

	while (**buf == '/')
		(*buf)++;

	ri->proxy_host = *buf;
	
	while (**buf && **buf != ':' && **buf != '/' && **buf != '\\' && **buf != '\n')
		(*buf)++;
	if (**buf == ':') {
		**buf = '\0';
		(*buf)++;
		ri->proxy_port = *buf;
	}
	if (**buf == '/') {
		**buf = '\0';
		(*buf)++;
	}
}

static bool_t
parse_http_request(char *buf, struct mg_request_info *ri, const struct usa *usa)
{
	char	*http_version;
	int	n, success_code = FALSE;

	ri->request_method = skip(&buf, " ");
	parse_proxy_info(&buf, ri);
	ri->uri = skip(&buf, " ");
	http_version = skip(&buf, "\r\n");

	if (is_known_http_method(ri->request_method) &&
	    ri->uri[0] == '/' &&
	    sscanf(http_version, "HTTP/%d.%d%n",
	    &ri->http_version_major, &ri->http_version_minor, &n) == 2 &&
	    http_version[n] == '\0') {
		parse_http_headers(&buf, ri);
		ri->remote_port = ntohs(usa->u.sin.sin_port);
		(void) memcpy(&ri->remote_ip, &usa->u.sin.sin_addr.s_addr, 4);
		ri->remote_ip = ntohl(ri->remote_ip);
		success_code = TRUE;
	}

	return (success_code);
}

static int
read_request(int fd, SOCKET sock, SSL *ssl, char *buf, int bufsiz, int *nread)
{
	int	n, request_len;

	request_len = 0;
	while (*nread < bufsiz && request_len == 0) {
		n = pull(fd, sock, ssl, buf + *nread, bufsiz - *nread);
		if (n <= 0) {
			break;
		} else {
			*nread += n;
			request_len = get_request_len(buf, (size_t) *nread);
		}
	}

	return (request_len);
}

/*
 * For given directory path, substitute it to valid index file.
 * Return 0 if index file has been found, -1 if not found
 */
static bool_t
send_index_file(struct mg_connection *conn,
		char *buf, size_t buf_len, struct stat *stp)
{
	const char	*s;
	size_t		len, n;

	n = strlen(buf);
	buf[n] = DIRSEP;

	mg_lock(conn->ctx);
	s = conn->ctx->options[OPT_INDEX_FILES];
	FOR_EACH_WORD_IN_LIST(s, len) {
		if (len > buf_len - n - 1)
			continue;
		(void) mg_strlcpy(buf + n + 1, s, len + 1);
		if (stat(buf, stp) == 0) {
			send_file(conn, buf, stp);
			mg_unlock(conn->ctx);
			return (TRUE);
		}
	}
	mg_unlock(conn->ctx);

	buf[n] = '\0';

	return (FALSE);
}

static void
mg_bind(struct mg_context *ctx, const char *uri_regex, int status_code,
		mg_callback_t func, bool_t is_auth, void *user_data)
{
	struct callback	*cb;

	if (ctx->num_callbacks >= (int) ARRAY_SIZE(ctx->callbacks) - 1) {
		cry("Too many callbacks! Increase MAX_CALLBACKS.");
	} else {
		cb = &ctx->callbacks[ctx->num_callbacks];
		cb->uri_regex = uri_regex ? mg_strdup(uri_regex) : NULL;
		cb->func = func;
		cb->is_auth = is_auth;
		cb->status_code = status_code;
		cb->user_data = user_data;
		ctx->num_callbacks++;
	}
}

void
mg_bind_to_uri(struct mg_context *ctx, const char *uri_regex,
		mg_callback_t func, void *user_data)
{
	assert(func != NULL);
	assert(uri_regex != NULL);
	mg_bind(ctx, uri_regex, -1, func, FALSE, user_data);
}

void
mg_bind_to_error_code(struct mg_context *ctx, int error_code,
		mg_callback_t func, void *user_data)
{
	assert(error_code >= 0 && error_code < 1000);
	assert(func != NULL);
	mg_bind(ctx, NULL, error_code, func, FALSE, user_data);
}

void
mg_protect_uri(struct mg_context *ctx, const char *uri_regex,
		mg_callback_t func, void *user_data)
{
	assert(func != NULL);
	assert(uri_regex != NULL);
	mg_bind(ctx, uri_regex, -1, func, TRUE, user_data);
}

static int
not_modified(const struct mg_connection *conn, const struct stat *stp)
{
	const char *ims = mg_get_header(conn, "If-Modified-Since");
	return (ims != NULL && stp->st_mtime < date_to_epoch(ims));
}

static bool_t
append_chunk(struct mg_request_info *ri, int fd, const char *buf, int len)
{
	bool_t	ret_code = TRUE;

	if (fd == -1) {
		/* TODO: check for NULL here */
		ri->post_data = (char *) realloc(ri->post_data,
		    ri->post_data_len + len);
		(void) memcpy(ri->post_data + ri->post_data_len, buf, len);
		ri->post_data_len += len;
	} else if (push(fd, INVALID_SOCKET,
	    NULL, buf, (uint64_t) len) != (uint64_t) len) {
		ret_code = FALSE;
	}

	return (ret_code);
}

int mg_read(struct mg_connection *conn, void *in_buf, unsigned len)
{
	struct mg_request_info *ri = &conn->request_info;
	char *buf = (char*)in_buf;
	unsigned extra = 0;
	int result;

	/* First, see if there is any remaining data after the request headers
	 * that was already read from the socket */
	if (ri->post_data_len) {
		int bytes_to_read = (int)len;
		if (bytes_to_read > ri->post_data_len)
			bytes_to_read = ri->post_data_len;
		memcpy(buf, ri->post_data, bytes_to_read);
		ri->post_data += bytes_to_read;
		ri->post_data_len -= bytes_to_read;
		buf += bytes_to_read;
		len -= bytes_to_read;
		if (len == 0)
			return bytes_to_read;
		else
			extra = bytes_to_read;
	}

	/* Second, read bytes from the socket */
	result = pull(-1, conn->sock, conn->ssl, buf, len);
	if (result <= 0) {
		if (extra)
			return extra;
		else
			return result;
	} else
		return (int)(result + extra);
}

static bool_t
handle_request_body(struct mg_connection *conn, int fd)
{
	struct mg_request_info	*ri = &conn->request_info;
	const char	*expect, *tmp;
	uint64_t	content_len;
	char		buf[BUFSIZ];
	int		to_read, nread, already_read;
	bool_t		success_code = FALSE;

	content_len = get_content_length(conn);
	expect = mg_get_header(conn, "Expect");

	if (content_len == UNKNOWN_CONTENT_LENGTH) {
		send_error(conn, 411, "Length Required", "");
	} else if (expect != NULL && mg_strcasecmp(expect, "100-continue")) {
		send_error(conn, 417, "Expectation Failed", "");
	} else {
		if (expect != NULL)
			(void) mg_printf(conn, "HTTP/1.1 100 Continue\r\n\r\n");

		already_read = ri->post_data_len;
		assert(already_read >= 0);

		if (content_len <= (uint64_t) already_read) {
			ri->post_data_len = (int) content_len;
			/*
			 * If fd == -1, this is embedded mode, and we do not
			 * have to do anything: POST data is already there,
			 * no need to allocate a buffer and copy it in.
			 * If fd != -1, we need to write the data.
			 */
			success_code = (fd == -1) || (push(fd, INVALID_SOCKET,
			    NULL, ri->post_data, content_len) == content_len) ?
			    TRUE : FALSE;
		} else {

			if (fd == -1) {
				conn->free_post_data = TRUE;
				tmp = ri->post_data;
				/* +1 in case if already_read == 0 */
				ri->post_data = (char*)malloc(already_read + 1);
				(void) memcpy(ri->post_data, tmp, already_read);
			} else {
				(void) push(fd, INVALID_SOCKET, NULL,
				    ri->post_data, (uint64_t) already_read);
			}

			content_len -= already_read;

			while (content_len > 0) {
				to_read = sizeof(buf);
				if ((uint64_t) to_read > content_len)
					to_read = (int) content_len;
				nread = pull(-1, conn->sock,
				    conn->ssl, buf, to_read);
				if (nread <= 0)
					break;
				if (!append_chunk(ri, fd, buf, nread))
					break;
				content_len -= nread;
			}
			success_code = content_len == 0 ? TRUE : FALSE;
		}

		/* Each error code path in this function must send an error */
		if (success_code != TRUE)
			send_error(conn, 577, http_500_error,
			   "%s", "Error handling body data");
	}

	return (success_code);
}

#if !defined(NO_CGI)
struct cgi_env_block {
	char	buf[CGI_ENVIRONMENT_SIZE];	/* Environment buffer	*/
	int	len;				/* Space taken		*/
	char	*vars[MAX_CGI_ENVIR_VARS];	/* char **envp		*/
	int	nvars;				/* Number of variables	*/
};

static char *
addenv(struct cgi_env_block *block, const char *fmt, ...)
{
	int	n, space;
	char	*added;
	va_list	ap;

	space = sizeof(block->buf) - block->len - 2;
	assert(space >= 0);
	added = block->buf + block->len;

	va_start(ap, fmt);
	n = mg_vsnprintf(added, (size_t) space, fmt, ap);
	va_end(ap);

	if (n > 0 && n < space &&
	    block->nvars < (int) ARRAY_SIZE(block->vars) - 2) {
		block->vars[block->nvars++] = block->buf + block->len;
		block->len += n + 1;	/* Include \0 terminator */
	}

	return (added);
}

static void
prepare_cgi_environment(struct mg_connection *conn, const char *prog,
		struct cgi_env_block *blk)
{
	const char	*s, *script_filename, *root;
	char		*p;
	int		i;

	blk->len = blk->nvars = 0;

	/* SCRIPT_FILENAME */
	script_filename = prog;
	if ((s = strrchr(prog, '/')) != NULL)
		script_filename = s + 1;

	mg_lock(conn->ctx);
	root = conn->ctx->options[OPT_ROOT];
	addenv(blk, "SERVER_NAME=%s", conn->ctx->options[OPT_AUTH_DOMAIN]);
	mg_unlock(conn->ctx);

	/* Prepare the environment block */
	addenv(blk, "%s", "GATEWAY_INTERFACE=CGI/1.1");
	addenv(blk, "%s", "SERVER_PROTOCOL=HTTP/1.1");
	addenv(blk, "%s", "REDIRECT_STATUS=200");	/* PHP */
	addenv(blk, "SERVER_PORT=%d", ntohs(conn->lsa.u.sin.sin_port));
	addenv(blk, "SERVER_ROOT=%s", root);
	addenv(blk, "DOCUMENT_ROOT=%s", root);
	addenv(blk, "REQUEST_METHOD=%s", conn->request_info.request_method);
	addenv(blk, "REMOTE_ADDR=%s", inet_ntoa(conn->rsa.u.sin.sin_addr));
	addenv(blk, "REMOTE_PORT=%d", conn->request_info.remote_port);
	addenv(blk, "REQUEST_URI=%s", conn->request_info.uri);
	addenv(blk, "SCRIPT_NAME=%s", prog + strlen(root));
	addenv(blk, "SCRIPT_FILENAME=%s", script_filename);	/* PHP */
	addenv(blk, "PATH_TRANSLATED=%s", prog);

	if ((s = mg_get_header(conn, "Content-Type")) != NULL)
		addenv(blk, "CONTENT_TYPE=%s", s);

	if (conn->request_info.query_string != NULL)
		addenv(blk, "QUERY_STRING=%s", conn->request_info.query_string);

	if ((s = mg_get_header(conn, "Content-Length")) != NULL)
		addenv(blk, "CONTENT_LENGTH=%s", s);

	if ((s = getenv("PATH")) != NULL)
		addenv(blk, "PATH=%s", s);

#if defined(_WIN32)
	if ((s = getenv("COMSPEC")) != NULL)
		addenv(blk, "COMSPEC=%s", s);
	if ((s = getenv("SYSTEMROOT")) != NULL)
		addenv(blk, "SYSTEMROOT=%s", s);
#else
	if ((s = getenv("LD_LIBRARY_PATH")) != NULL)
		addenv(blk, "LD_LIBRARY_PATH=%s", s);
#endif /* _WIN32 */

	if ((s = getenv("PERLLIB")) != NULL)
		addenv(blk, "PERLLIB=%s", s);

	if (conn->request_info.remote_user != NULL) {
		addenv(blk, "REMOTE_USER=%s", conn->request_info.remote_user);
		addenv(blk, "%s", "AUTH_TYPE=Digest");
	}

	/* Add all headers as HTTP_* variables */
	for (i = 0; i < conn->request_info.num_headers; i++) {
		p = addenv(blk, "HTTP_%s=%s",
		    conn->request_info.http_headers[i].name,
		    conn->request_info.http_headers[i].value);

		/* Convert variable name into uppercase, and change - to _ */
		for (; *p != '=' && *p != '\0'; p++) {
			if (*p == '-')
				*p = '_';
			*p = (char)(toupper(* (unsigned char *) p) & 0xff);
		}
	}

	blk->vars[blk->nvars++] = NULL;
	blk->buf[blk->len++] = '\0';

	assert(blk->nvars < (int) ARRAY_SIZE(blk->vars));
	assert(blk->len > 0);
	assert(blk->len < (int) sizeof(blk->buf));
}

static void
send_cgi(struct mg_connection *conn, const char *prog)
{
	int			headers_len, data_len, i, n;
	const char		*status;
	char			buf[MAX_REQUEST_SIZE], *pbuf;
	struct mg_request_info	ri;
	struct cgi_env_block	blk;
	char			dir[FILENAME_MAX], *p;
	int			fd_stdin[2], fd_stdout[2];

	prepare_cgi_environment(conn, prog, &blk);

	/* CGI must be executed in its own directory */
	(void) mg_snprintf(dir, sizeof(dir), "%s", prog);
	if ((p = strrchr(dir, DIRSEP)) != NULL)
		*p++ = '\0';

	fd_stdin[0] = fd_stdin[1] = fd_stdout[0] = fd_stdout[1] = -1;
	if (pipe(fd_stdin) != 0 || pipe(fd_stdout) != 0) {
		send_error(conn, 500, http_500_error,
		    "Cannot create CGI pipe: %s", strerror(ERRNO));
		goto done;
	}

	if (!spawn_process(conn, p, blk.buf, blk.vars,
	    fd_stdin[0], fd_stdout[1], dir)) {
		goto done;
	}	

	/*
	 * spawn_process() must close those!
	 * If we don't mark them as closed, close() attempt before
	 * return from this function throws an exception on Windows.
	 * Windows does not like when closed descriptor is closed again.
	 */
	fd_stdin[0] = fd_stdout[1] = -1;

	/* Send POST data to the CGI process if needed */
	if (!strcmp(conn->request_info.request_method, "POST") &&
	    !handle_request_body(conn, fd_stdin[1])) {
		goto done;
	}

	/*
	 * Now read CGI reply into a buffer. We need to set correct
	 * status code, thus we need to see all HTTP headers first.
	 * Do not send anything back to client, until we buffer in all
	 * HTTP headers.
	 */
	data_len = 0;
	headers_len = read_request(fd_stdout[0], INVALID_SOCKET, NULL,
	    buf, sizeof(buf), &data_len);
	if (headers_len <= 0) {
		send_error(conn, 500, http_500_error,
		    "CGI program sent malformed HTTP headers: [%.*s]",
		    data_len, buf);
		goto done;
	}
	pbuf = buf;
	buf[headers_len - 1] = '\0';
	parse_http_headers(&pbuf, &ri);

	/* Make up and send the status line */
	status = get_header(&ri, "Status");
	conn->request_info.status_code = status == NULL ? 200 : atoi(status);
	(void) mg_printf(conn, "HTTP/1.1 %d OK\r\n",
	    conn->request_info.status_code);

	/* Send headers */
	for (i = 0; i < ri.num_headers; i++)
		(void) mg_printf(conn, "%s: %s\r\n",
		    ri.http_headers[i].name,
		    ri.http_headers[i].value);
	(void) mg_write(conn, "\r\n", 2);

	/* Send headers, and the rest of the data */
	conn->num_bytes_sent += mg_write(conn,
	    buf + headers_len, data_len - headers_len);
	while ((n = pull(fd_stdout[0],
	    INVALID_SOCKET, NULL, buf, sizeof(buf))) > 0)
		conn->num_bytes_sent += mg_write(conn, buf, n);

done:
	if (fd_stdin[0] != -1) (void) close(fd_stdin[0]);
	if (fd_stdin[1] != -1) (void) close(fd_stdin[1]);
	if (fd_stdout[0] != -1) (void) close(fd_stdout[0]);
	if (fd_stdout[1] != -1) (void) close(fd_stdout[1]);
}
#endif /* !NO_CGI */

#if !defined(NO_AUTH)
/*
 * For a given PUT path, create all intermediate subdirectories
 * for given path. Return 0 if the path itself is a directory,
 * or -1 on error, 1 if OK.
 */
static int
put_dir(const char *path)
{
	char		buf[FILENAME_MAX];
	const char	*s, *p;
	struct stat	st;
	size_t		len;

	for (s = p = path + 2; (p = strchr(s, '/')) != NULL; s = ++p) {
		len = p - path;
		assert(len < sizeof(buf));
		(void) memcpy(buf, path, len);
		buf[len] = '\0';

		/* Try to create intermediate directory */
		if (mg_stat(buf, &st) == -1 && mg_mkdir(buf, 0755) != 0)
			return (-1);

		/* Is path itself a directory ? */
		if (p[1] == '\0')
			return (0);
	}

	return (1);
}

static void
put_file(struct mg_connection *conn, const char *path)
{
	struct stat	st;
	int		rc, fd;

	conn->request_info.status_code = mg_stat(path, &st) == 0 ? 200 : 201;

	if (mg_get_header(conn, "Range")) {
		send_error(conn, 501, "Not Implemented",
		    "%s", "Range support for PUT requests is not implemented");
	} else if ((rc = put_dir(path)) == 0) {
		send_error(conn, 200, "OK", "");
	} else if (rc == -1) {
		send_error(conn, 500, http_500_error,
		    "put_dir(%s): %s", path, strerror(ERRNO));
	} else if ((fd = mg_open(path,
	    O_WRONLY | O_BINARY | O_CREAT | O_TRUNC, 0644)) == -1) {
		send_error(conn, 500, http_500_error,
		    "open(%s): %s", path, strerror(ERRNO));
	} else {
		set_close_on_exec(fd);
		if (handle_request_body(conn, fd))
			send_error(conn, conn->request_info.status_code,
			    "OK", "");
		(void) close(fd);
	}
}
#endif /* NO_AUTH */

#if !defined(NO_SSI)
static void
do_ssi_include(struct mg_connection *conn, const char *ssi, char *tag)
{
	char	file_name[BUFSIZ], path[FILENAME_MAX], *p;
	FILE	*fp;

	/*
	 * sscanf() is safe here, since send_ssi_file() also uses buffer
	 * of size BUFSIZ to get the tag. So strlen(tag) is always < BUFSIZ.
	 */
	if (sscanf(tag, " virtual=\"%[^\"]\"", file_name) == 1) {
		/* File name is relative to the webserver root */
		mg_lock(conn->ctx);
		(void) mg_snprintf(path, sizeof(path), "%s%c%s",
		    conn->ctx->options[OPT_ROOT], DIRSEP, file_name);
		mg_unlock(conn->ctx);
	} else if (sscanf(tag, " file=\"%[^\"]\"", file_name) == 1) {
		/*
		 * File name is relative to the webserver working directory
		 * or it is absolute system path
		 */
		(void) mg_snprintf(path, sizeof(path), "%s", file_name);
	} else if (sscanf(tag, " \"%[^\"]\"", file_name) == 1) {
		/* File name is relative to the currect document */
		(void) mg_snprintf(path, sizeof(path), "%s", ssi);
		if ((p = strrchr(path, DIRSEP)) != NULL)
			p[1] = '\0';
		(void) mg_snprintf(path + strlen(path),
		    sizeof(path) - strlen(path), "%s", file_name);
	} else {
		cry("Bad SSI #include: [%s]", tag);
		return;
	}

	if ((fp = fopen(path, "rb")) == NULL) {
		cry("Cannot open SSI #include: [%s]: fopen(%s): %s",
		    tag, path, strerror(ERRNO));
	} else {
		set_close_on_exec(fileno(fp));
		send_opened_file_stream(conn, fileno(fp), MAX64);
		(void) fclose(fp);
	}
}

static void
do_ssi_exec(struct mg_connection *conn, char *tag)
{
	char	cmd[BUFSIZ];
	FILE	*fp;

	if (sscanf(tag, " \"%[^\"]\"", cmd) != 1) {
		cry("Bad SSI #exec: [%s]", tag);
	} else if ((fp = popen(cmd, "r")) == NULL) {
		cry("Cannot SSI #exec: [%s]: %s", cmd, strerror(ERRNO));
	} else {
		send_opened_file_stream(conn, fileno(fp), MAX64);
		(void) pclose(fp);
	}
}

static void
send_ssi_file(struct mg_connection *conn, const char *path, FILE *fp)
{
	char	buf[BUFSIZ];
	int	ch, len, in_ssi_tag;

	in_ssi_tag = FALSE;
	len = 0;

	while ((ch = fgetc(fp)) != EOF) {
		if (in_ssi_tag && ch == '>') {
			in_ssi_tag = FALSE;
			buf[len++] = (char)(ch & 0xff);
			buf[len] = '\0';
			assert(len <= (int) sizeof(buf));
			if (len < 6 || memcmp(buf, "<!--#", 5) != 0) {
				/* Not an SSI tag, pass it */
				(void) mg_write(conn, buf, len);
			} else {
				if (!memcmp(buf + 5, "include", 7)) {
					do_ssi_include(conn, path, buf + 12);
				} else if (!memcmp(buf + 5, "exec", 4)) {
					do_ssi_exec(conn, buf + 9);
				} else {
					cry("%s: unknown SSI command: \"%s\"",
						path, buf);
				}
			}
			len = 0;
		} else if (in_ssi_tag) {
			if (len == 5 && memcmp(buf, "<!--#", 5) != 0) {
				/* Not an SSI tag */
				in_ssi_tag = FALSE;
			} else if (len == (int) sizeof(buf) - 2) {
				cry("%s: SSI tag is too large", path);
				len = 0;
			}
			buf[len++] = (char)(ch & 0xff);
		} else if (ch == '<') {
			in_ssi_tag = TRUE;
			if (len > 0)
				(void) mg_write(conn, buf, len);
			len = 0;
			buf[len++] = (char)(ch & 0xff);
		} else {
			buf[len++] = (char)(ch & 0xff);
			if (len == (int) sizeof(buf)) {
				(void) mg_write(conn, buf, len);
				len = 0;
			}
		}
	}

	/* Send the rest of buffered data */
	if (len > 0)
		(void) mg_write(conn, buf, len);

}

static void
send_ssi(struct mg_connection *conn, const char *path)
{
	FILE	*fp;

	if ((fp = fopen(path, "rb")) == NULL) {
		send_error(conn, 500, http_500_error,
		    "fopen(%s): %s", path, strerror(ERRNO));
	} else {
		set_close_on_exec(fileno(fp));
		(void) mg_printf(conn, "%s", "HTTP/1.1 200 OK\r\n"
		    "Content-Type: text/html\r\nConnection: close\r\n\r\n");
		send_ssi_file(conn, path, fp);
		(void) fclose(fp);
	}
}
#endif /* !NO_SSI */

static void
analyze_request(struct mg_connection *conn)
{
	struct mg_request_info *ri = &conn->request_info;
	char			path[FILENAME_MAX], *uri = ri->uri;
	struct stat		st;
	const struct callback	*cb;

	if ((conn->request_info.query_string = strchr(uri, '?')) != NULL)
		* conn->request_info.query_string++ = '\0';

	(void) url_decode(uri, (int) strlen(uri), uri, strlen(uri) + 1, FALSE);
	remove_double_dots(uri);
	make_path(conn->ctx, uri, path, sizeof(path));

#if !defined(NO_PROXY)
	if (ri->proxy_protocol && ri->proxy_host && strcmp(ri->proxy_host, "hamster") != 0) {
		if ((cb = find_callback(conn->ctx, FALSE, ri->proxy_protocol, -1)) != NULL) {
			cb->func(conn, &conn->request_info, cb->user_data);
		} else {
			send_error(conn, 404, "something's wrong here", "");
		}
	} else
#endif
#if !defined(NO_AUTH)
	if (!check_authorization(conn, path)) {
		send_authorization_request(conn);
	} else
#endif /* !NO_AUTH */
	if ((cb = find_callback(conn->ctx, FALSE, uri, -1)) != NULL) {
		if (strcmp(ri->request_method, "POST") ||
		    (!strcmp(ri->request_method, "POST") &&
			handle_request_body(conn, -1))) {
			cb->func(conn, &conn->request_info, cb->user_data);
		}
	} else
#if !defined(NO_AUTH)
	if (strstr(path, PASSWORDS_FILE_NAME)) {
		/* Do not allow to view passwords files */
		send_error(conn, 403, "Forbidden", "");
	} else if ((!strcmp(ri->request_method, "PUT") ||
	    !strcmp(ri->request_method, "DELETE")) &&
	    (conn->ctx->options[OPT_AUTH_PUT] == NULL ||
	     !is_authorized_for_put(conn))) {
		send_authorization_request(conn);
	} else if (!strcmp(ri->request_method, "PUT")) {
		put_file(conn, path);
	} else if (!strcmp(ri->request_method, "DELETE")) {
		if (mg_remove(path) == 0)
			send_error(conn, 200, "OK", "");
		else
			send_error(conn, 500, http_500_error,
			    "remove(%s): %s", path, strerror(ERRNO));
	} else
#endif /* NO_AUTH */
	if (mg_stat(path, &st) != 0) {
		send_error(conn, 404, "Not Found", "%s", "");
	} else if (S_ISDIR(st.st_mode) && uri[strlen(uri) - 1] != '/') {
		(void) mg_printf(conn,
		    "HTTP/1.1 301 Moved Permanently\r\n"
		    "Location: %s/\r\n\r\n", uri);
	} else if (S_ISDIR(st.st_mode)) {
	       	if (send_index_file(conn, path, sizeof(path), &st)) {
			/* do nothing */
		} else if (is_true(conn->ctx->options[OPT_DIR_LIST])) {
			send_directory(conn, path);
		} else {
			send_error(conn, 403, "Directory Listing Denied",
			    "Directory listing denied");
		}
#if !defined(NO_CGI)
	} else if (match_extension(path,
	    conn->ctx->options[OPT_CGI_EXTENSIONS])) {
		if (strcmp(ri->request_method, "POST") &&
		    strcmp(ri->request_method, "GET")) {
			send_error(conn, 501, "Not Implemented",
			    "Method %s is not implemented", ri->request_method);
		} else {
			send_cgi(conn, path);
		}
#endif /* NO_CGI */
#if !defined(NO_SSI)
	} else if (match_extension(path,
	    conn->ctx->options[OPT_SSI_EXTENSIONS])) {
		send_ssi(conn, path);
#endif /* NO_SSI */
	} else if (not_modified(conn, &st)) {
		send_error(conn, 304, "Not Modified", "");
	} else {
		send_file(conn, path, &st);
	}
}

static void
close_all_listening_sockets(struct mg_context *ctx)
{
	int	i;

	for (i = 0; i < ctx->num_listeners; i++)
		(void) closesocket(ctx->listeners[i].sock);
	ctx->num_listeners = 0;
}

const char *mg_get_option2(struct mg_context *ctx, const char *option_name);


static bool_t
set_ports_option(struct mg_context *ctx, const char *p)
{
	SOCKET	sock;
	size_t	len;
	int	is_ssl, port;
	const char *sz_ip = mg_get_option2(ctx, "ip");
	int ip = 0;
printf("DEBUG: set_ports_option(%s)\n", p);

	if (sz_ip)
		ip = ntohl(inet_addr(sz_ip));
	if (ip >= 0xFFFFffff)
		ip = ntohl(inet_addr("127.0.0.1"));

	close_all_listening_sockets(ctx);

	FOR_EACH_WORD_IN_LIST(p, len) {

		is_ssl	= p[len - 1] == 's' ? 1 : 0;
		port	= atoi(p);

		if (ctx->num_listeners >=
		    (int) (ARRAY_SIZE(ctx->listeners) - 1)) {
			cry("%s", "Too many listeninig sockets");
			return (FALSE);
		} else if ((sock = mg_open_listening_port(ip, port)) == -1) {
			cry("cannot open port %d", port);
			return (FALSE);
		} else if (is_ssl && ctx->ssl_ctx == NULL) {
			(void) closesocket(sock);
			cry("cannot add SSL socket, "
			    "please specify certificate file");
			return (FALSE);
		} else {
			ctx->listeners[ctx->num_listeners].sock = sock;
			ctx->listeners[ctx->num_listeners].is_ssl = is_ssl;
			ctx->num_listeners++;
		}
	}

	return (TRUE);
}

static void
log_header(const struct mg_connection *conn, const char *header, FILE *fp)
{
	const char	*header_value;

	if ((header_value = mg_get_header(conn, header)) == NULL) {
		(void) fprintf(fp, "%s", " -");
	} else {
		(void) fprintf(fp, " \"%s\"", header_value);
	}
}

static void
log_access(const struct mg_connection *conn)
{
	const struct mg_request_info *ri;
	char		date[64];

	if (conn->ctx->access_log == NULL)
		return;

	(void) strftime(date, sizeof(date), "%d/%b/%Y:%H:%M:%S",
			localtime(&conn->birth_time));

	ri = &conn->request_info;
	(void) fprintf(conn->ctx->access_log,
	    "%s - %s [%s %+05d] \"%s %s HTTP/%d.%d\" %d " U64 "",
	    inet_ntoa(conn->rsa.u.sin.sin_addr),
	    ri->remote_user == NULL ? "-" : ri->remote_user,
	    date, tz_offset,
	    ri->request_method ? ri->request_method : "-",
	    ri->uri ? ri->uri : "-",
	    ri->http_version_major, ri->http_version_minor,
	    conn->request_info.status_code,
	    (uint64_t) conn->num_bytes_sent);
	log_header(conn, "Referer", conn->ctx->access_log);
	log_header(conn, "User-Agent", conn->ctx->access_log);
	(void) fputc('\n', conn->ctx->access_log);
	(void) fflush(conn->ctx->access_log);
}

static bool_t
isbyte(int n) {
	return (n >= 0 && n <= 255);
}

static bool_t
check_acl(struct mg_context *ctx, const struct usa *usa)
{
	int		a, b, c, d, n, mask, allowed;
	char		flag, *s;
	size_t		len;
	uint32_t	acl_subnet, acl_mask, remote_ip;

	(void) memcpy(&remote_ip, &usa->u.sin.sin_addr, sizeof(remote_ip));

	mg_lock(ctx);
	s = ctx->options[OPT_ACL];

	/* Allow by default, if no ACL is set */
	if (s == NULL) {
		mg_unlock(ctx);
		return (TRUE);
	}

	/* If any ACL is set, deny by default */
	allowed = '-';
	FOR_EACH_WORD_IN_LIST(s, len) {

		mask = 32;

		if (sscanf(s, "%c%d.%d.%d.%d%n",&flag,&a,&b,&c,&d,&n) != 5) {
			cry("[%s]: subnet must be [+|-]x.x.x.x[/x]", s);
		} else if (flag != '+' && flag != '-') {
			cry("flag must be + or -: [%s]", s);
		} else if (!isbyte(a)||!isbyte(b)||!isbyte(c)||!isbyte(d)) {
			cry("bad ip address: [%s]", s);
		} else if (sscanf(s + n, "/%d", &mask) == 0) {
			/* Do nothing, no mask specified */
		} else if (mask < 0 || mask > 32) {
			cry("bad subnet mask: %d [%s]", n, s);
		}

		acl_subnet = (a << 24) | (b << 16) | (c << 8) | d;
		acl_mask = mask ? 0xffffffffU << (32 - mask) : 0;

		if (acl_subnet == (ntohl(remote_ip) & acl_mask))
			allowed = flag;
	}
	mg_unlock(ctx);

	return (allowed == '+');
}

static void
add_to_set(SOCKET fd, fd_set *set, int *max_fd)
{
	FD_SET(fd, set);
	if (fd > (SOCKET) *max_fd)
		*max_fd = (int) fd;
}

/*
 * Deallocate mongoose context, free up the resources
 */
static void
mg_fini(struct mg_context *ctx)
{
	int	i;

	close_all_listening_sockets(ctx);

	for (i = 0; i < ctx->num_callbacks; i++)
		if (ctx->callbacks[i].uri_regex != NULL)
			free(ctx->callbacks[i].uri_regex);

	for (i = 0; i < NUM_OPTIONS; i++)
		if (ctx->options[i] != NULL)
			free(ctx->options[i]);

	if (ctx->access_log)
		(void) fclose(ctx->access_log);
	if (ctx->error_log)
		(void) fclose(ctx->error_log);

	/* TODO: free SSL context */
	(void) pthread_mutex_destroy(&ctx->mutex);

	free(ctx);
}

#if !defined(_WIN32)
static bool_t
set_uid_option(struct mg_context *ctx, const char *uid)
{
	struct passwd	*pw;
	int		retval = FALSE;

	ctx = NULL; /* Unused */

	if ((pw = getpwnam(uid)) == NULL)
		cry("%s: unknown user [%s]", __func__, uid);
	else if (setgid(pw->pw_gid) == -1)
		cry("%s: setgid(%s): %s", __func__, uid, strerror(errno));
	else if (setuid(pw->pw_uid) == -1)
		cry("%s: setuid(%s): %s", __func__, uid, strerror(errno));
	else
		retval = TRUE;

	return (retval);
}
#endif /* !_WIN32 */

#if !defined(NO_SSL)
void
mg_set_ssl_password_callback(struct mg_context *ctx, mg_spcb_t func)
{
	ctx->ssl_password_callback = func;
}

/*
 * Dynamically load SSL library. Set up ctx->ssl_ctx pointer.
 */
static bool_t
set_ssl_option(struct mg_context *ctx, const char *pem)
{
	SSL_CTX		*CTX;
	void		*lib;
	union {void *p; void (*fp)(void);} u;
	struct ssl_func	*fp;
	int		retval = FALSE;

	/* Load SSL library dynamically */
	if ((lib = dlopen(SSL_LIB, RTLD_LAZY)) == NULL) {
		cry("set_ssl_option: cannot load %s", SSL_LIB);
		return (FALSE);
	}

	for (fp = ssl_sw; fp->name != NULL; fp++) {
#ifdef _WIN32
		/* GetProcAddress() returns pointer to function */
		u.fp = (void (*)(void)) dlsym(lib, fp->name);
#else
		/*
		 * dlsym() on UNIX returns void *.
		 * ISO C forbids casts of data pointers to function
		 * pointers. We need to use a union to make a cast.
		 */
		u.p = dlsym(lib, fp->name);
#endif /* _WIN32 */
		if (u.fp == NULL) {
			cry("set_ssl_option: cannot find %s", fp->name);
			return (FALSE);
		} else {
			fp->ptr = u.fp;
		}
	}

	/* Initialize SSL crap */
	SSL_library_init();

	if ((CTX = SSL_CTX_new(SSLv23_server_method())) == NULL)
		cry("SSL_CTX_new error");
	else if (ctx->ssl_password_callback != NULL)
		SSL_CTX_set_default_passwd_cb(CTX, ctx->ssl_password_callback);

	if (CTX != NULL && SSL_CTX_use_certificate_file(
	    CTX, pem, SSL_FILETYPE_PEM) == 0)
		cry("cannot open %s", pem);
	else if (CTX != NULL && SSL_CTX_use_PrivateKey_file(
	    CTX, pem, SSL_FILETYPE_PEM) == 0)
		cry("cannot open %s", pem);
	else
		retval = TRUE;

	ctx->ssl_ctx = CTX;

	return (retval);
}
#endif /* !NO_SSL */

static bool_t
open_log_file(FILE **fpp, const char *path)
{
	bool_t	retval = TRUE;

	if (*fpp != NULL)
		(void) fclose(*fpp);

	if (path == NULL) {
		*fpp = NULL;
	} else if ((*fpp = fopen(path, "a")) == NULL) {
		cry("cannot open log file %s: %s",
		    path, strerror(errno));
		retval = FALSE;
	} else {
		set_close_on_exec(fileno(*fpp));
	}

	return (retval);
}

static bool_t
set_alog_option(struct mg_context *ctx, const char *path)
{
	return (open_log_file(&ctx->access_log, path));
}

static bool_t
set_elog_option(struct mg_context *ctx, const char *path)
{
	return (open_log_file(&ctx->error_log, path));
}

#if !defined(NO_AUTH)
static bool_t
set_gpass_option(struct mg_context *ctx, const char *path)
{
	ctx = NULL;
	return (access(path, R_OK) == 0);
}
#endif /* !NO_AUTH */

static void
admin_page(struct mg_connection *conn, const struct mg_request_info *ri,
		void *user_data)
{
	const struct mg_option	*list;
	const char		*option_name, *option_value;
	int			i;

	user_data = NULL; /* Unused */

	(void) mg_printf(conn,
	    "HTTP/1.1 200 OK\r\n"
	    "Content-Type: text/html\r\n\r\n"
	    "<html><body><h1>Mongoose v. %s</h1>", mg_version());

	if (!strcmp(ri->request_method, "POST")) {
		option_name = mg_get_var(conn, "o");
		option_value = mg_get_var(conn, "v");
		if (mg_set_option(conn->ctx,
		    option_name, option_value) == -1) {
			(void) mg_printf(conn,
			    "<p style=\"background: red\">Error setting "
			    "option \"%s\"</p>",
			    option_name ? option_name : "(null)");
		} else {
			(void) mg_printf(conn,
			    "<p style=\"color: green\">Saved: %s=%s</p>",
			    option_name, option_value ? option_value : "NULL");
		}
	}

	/* Print table with all options */
	list = mg_get_option_list();
	(void) mg_printf(conn, "%s", "<table border=\"1\""
	    "<tr><th>Option</th><th>Description</th>"
	    "<th colspan=2>Value</th></tr>");

	for (i = 0; list[i].name != NULL; i++) {
		option_value = mg_get_option(conn->ctx, list[i].name);
		if (option_value == NULL)
			option_value = "";
		(void) mg_printf(conn,
		    "<form method=post><tr><td>%s</td><td>%s</td>"
		    "<input type=hidden name=o value='%s'>"
		    "<td><input type=text name=v value='%s'></td>"
		    "<td><input type=submit value=save></td></form></tr>",
		    list[i].name, list[i].description, list[i].name,
		    option_value);
	}

	(void) mg_printf(conn, "%s", "</table></body></html>");
}

static bool_t
set_admin_uri_option(struct mg_context *ctx, const char *uri)
{
	mg_bind_to_uri(ctx, uri, &admin_page, NULL);
	return (TRUE);
}

static const struct mg_option known_options[] = {
	{"root", "\tWeb root directory", NULL},
	{"index_files",	"Index files", "index.html,index.htm,index.cgi"},
#if !defined(NO_SSL)
	{"ssl_cert", "SSL certificate file", NULL},
#endif /* !NO_SSL */
	{"ports", "Listening ports", NULL},
	{"dir_list", "Directory listing", "yes"},
	{"protect", "URI to htpasswd mapping", NULL},
#if !defined(NO_CGI)
	{"cgi_ext", "CGI extensions", "cgi,pl,php"},
	{"cgi_interp", "CGI interpreter to use with all CGI scripts", NULL},
#endif /* NO_CGI */
	{"ssi_ext", "SSI extensions", "shtml,shtm"},
#if !defined(NO_AUTH)
	{"auth_realm", "Authentication domain name", "mydomain.com"},
	{"auth_gpass", "Global passwords file", NULL},
	{"auth_PUT", "PUT,DELETE auth file", NULL},
#endif /* !NO_AUTH */
#if !defined(_WIN32)
	{"uid", "\tRun as user", NULL},
#endif /* !_WIN32 */
	{"access_log", "Access log file", NULL},
	{"error_log", "Error log file", NULL},
	{"aliases", "Path=URI mappings", NULL},
	{"admin_uri", "Administration page URI", NULL},
	{"acl", "\tAllow/deny IP addresses/subnets", NULL},
	{"ip", "IP address to bind server to", "127.0.0.1"},
	{NULL, NULL, NULL}
};

static const struct option_setter {
	int	context_index;
	bool_t (*setter)(struct mg_context *, const char *);
} setters[] = {
	{OPT_ROOT,		NULL},
	{OPT_INDEX_FILES,	NULL},
#if !defined(NO_SSL)
	{OPT_SSL_CERTIFICATE,	&set_ssl_option},
#endif /* !NO_SSL */
	{OPT_PORTS,		&set_ports_option},
	{OPT_DIR_LIST,		NULL},
	{OPT_PROTECT,		NULL},
#if !defined(NO_CGI)
	{OPT_CGI_EXTENSIONS,	NULL},
	{OPT_CGI_INTERPRETER,	NULL},
#endif /* NO_CGI */
	{OPT_SSI_EXTENSIONS,	NULL},
#if !defined(NO_AUTH)
	{OPT_AUTH_DOMAIN,	NULL},
	{OPT_AUTH_GPASSWD,	&set_gpass_option},
	{OPT_AUTH_PUT,		NULL},
#endif /* !NO_AUTH */
#if !defined(_WIN32)
	{OPT_UID,		&set_uid_option},
#endif /* !_WIN32 */
	{OPT_ACCESS_LOG,	&set_alog_option},
	{OPT_ERROR_LOG,		&set_elog_option},
	{OPT_ALIASES,		NULL},
	{OPT_ADMIN_URI,		&set_admin_uri_option},
	{OPT_ACL,		NULL},
	{OPT_IP,		NULL},
	{-1,			NULL}
};

static const struct mg_option *
find_opt(const char *opt_name)
{
	int	i;

	for (i = 0; known_options[i].name != NULL; i++)
		if (!strcmp(opt_name, known_options[i].name))
			return (known_options + i);

	return (NULL);
}

int
mg_set_option(struct mg_context *ctx, const char *opt, const char *val)
{
	const struct mg_option	*option;
	int			i, ctx_index, retval;

	mg_lock(ctx);
	if (opt != NULL && (option = find_opt(opt)) != NULL) {
		i = (int) (option - known_options);

		if (setters[i].setter != NULL) {
			retval = setters[i].setter(ctx, val);
		} else
			retval = TRUE;

		/* Free old value if any */
		ctx_index = setters[i].context_index;
		if (ctx->options[ctx_index] != NULL)
			free(ctx->options[ctx_index]);

		/* Set new option value */
		ctx->options[ctx_index] = val ? mg_strdup(val) : NULL;
	} else {
		retval = -1;
	}
	mg_unlock(ctx);

	return (retval);
}

const struct mg_option *
mg_get_option_list(void)
{
	return (known_options);
}

const char *
mg_get_option2(struct mg_context *ctx, const char *option_name)
{
	const struct mg_option	*o;
	const char			*value = NULL;

	value = NULL;
	if ((o = find_opt(option_name)) != NULL)
		value = ctx->options[setters[o - known_options].context_index];
	return (value);
}
const char *
mg_get_option(struct mg_context *ctx, const char *option_name)
{
	const struct mg_option	*o;
	const char			*value = NULL;

	mg_lock(ctx);
	value = NULL;
	if ((o = find_opt(option_name)) != NULL)
		value = ctx->options[setters[o - known_options].context_index];
	mg_unlock(ctx);

	return (value);
}

static void
reset_per_request_attributes(struct mg_connection *conn)
{
	if (conn->request_info.remote_user != NULL)
		free(conn->request_info.remote_user);
	if (conn->free_post_data && conn->request_info.post_data != NULL)
		free((void *)conn->request_info.post_data);
}

static void
close_socket_gracefully(SOCKET sock)
{
	char	buf[BUFSIZ];
	int	n;

	/* Send FIN to the client */
	(void) shutdown(sock, SHUT_WR);

	/*
	 * Read and discard pending data. If we do not do that and close the
	 * socket, the data in the send buffer may be discarded. This
	 * behaviour is seen on Windows, when client keeps sending data
	 * when server decide to close the connection; then when client
	 * does recv() it gets no data back.
	 */
	do {
		n = pull(-1, sock, NULL, buf, sizeof(buf));
	} while (n > 0);

	/* Now we know that our FIN is ACK-ed, safe to close */
	(void) closesocket(sock);
}

static void
close_connection(struct mg_connection *conn)
{
	reset_per_request_attributes(conn);
	if (conn->ssl)
		SSL_free(conn->ssl);
	if (conn->sock != INVALID_SOCKET) {
		close_socket_gracefully(conn->sock);
	}
	free(conn);
}

static void
reset_connection_attributes(struct mg_connection *conn)
{
	reset_per_request_attributes(conn);
	conn->free_post_data = FALSE;
	conn->request_info.status_code = -1;
	conn->keep_alive = FALSE;
	conn->num_bytes_sent = 0;
	(void) memset(&conn->request_info, 0, sizeof(conn->request_info));
}

static void
shift_to_next(struct mg_connection *conn, char *buf, int req_len, int *nread)
{
	uint64_t	cl;
	int		over_len, body_len;

	cl = get_content_length(conn);
	over_len = *nread - req_len;
	assert(over_len >= 0);

	if (cl == UNKNOWN_CONTENT_LENGTH) {
		body_len = 0;
	} else if (cl < (uint64_t) over_len) {
		body_len = (int) cl;
	} else {
		body_len = over_len;
	}

	*nread -= req_len + body_len;
	(void) memmove(buf, buf + req_len + body_len, *nread);
}

static void
process_new_connection(struct mg_connection *conn)
{
	struct mg_request_info *ri = &conn->request_info;
	char	buf[MAX_REQUEST_SIZE];
	int	request_len, nread;

	nread = 0;
	do {
		/* If next request is not pipelined, read it in */
		if ((request_len = get_request_len(buf, (size_t) nread)) == 0)
			request_len = read_request(-1, conn->sock, conn->ssl,
			    buf, sizeof(buf), &nread);
		assert(nread >= request_len);

		/*
		 * This sets conn->keep_alive to FALSE, so by default
		 * we break the loop.
		 */
		reset_connection_attributes(conn);

		/* 0-terminate the request: parse_request uses sscanf */
		if (request_len > 0)
			buf[request_len - 1] = '\0';

		if (request_len > 0 &&
		    parse_http_request(buf, ri, &conn->rsa)) {
			if (ri->http_version_major != 1 ||
			     (ri->http_version_major == 1 &&
			     (ri->http_version_minor < 0 ||
			     ri->http_version_minor > 1))) {
				send_error(conn, 505,
				    "HTTP version not supported",
				    "%s", "Weird HTTP version");
				log_access(conn);
			} else {
				ri->post_data = buf + request_len;
				ri->post_data_len = nread - request_len;
				analyze_request(conn);
				log_access(conn);
				shift_to_next(conn, buf, request_len, &nread);
			}
		} else {
			/* Do not put garbage in the access log */
			send_error(conn, 400, "Bad Request",
			    "Can not parse request: [%.*s]", nread, buf);
		}

	} while (conn->keep_alive);

	close_connection(conn);
}

static void
accept_new_connection(const struct listener *l, struct mg_context *ctx)
{
	struct mg_connection	*conn = NULL;
	bool_t			ok = FALSE;

	if ((conn = (struct mg_connection*) calloc(1, sizeof(*conn))) == NULL) {
		cry("Cannot allocate new connection");
	} else if ((conn->rsa.len = sizeof(conn->rsa.u.sin)) <= 0) {
		/* Never ever happens. */
		abort();
	} else if ((conn->sock = accept(l->sock,
	    &conn->rsa.u.sa, &conn->rsa.len)) == -1) {
		cry("accept: %d", ERRNO);
	} else if (!check_acl(ctx, &conn->rsa)) {
		cry("%s is not allowed to connect",
		    inet_ntoa(conn->rsa.u.sin.sin_addr));
	} else if (l->is_ssl && (conn->ssl = SSL_new(ctx->ssl_ctx)) == NULL) {
		cry("%s: SSL_new: %s", __func__, strerror(ERRNO));
	} else if (l->is_ssl && SSL_set_fd(conn->ssl, conn->sock) != 1) {
		cry("%s: SSL_set_fd: %s", __func__, strerror(ERRNO));
	} else if (l->is_ssl && SSL_accept(conn->ssl) != 1) {
		cry("%s: SSL handshake failed", __func__);
	} else {
		conn->ctx = ctx;
		conn->birth_time = time(NULL);
		if (start_thread((mg_thread_func_t)
		    process_new_connection, conn) == 0)
			ok = TRUE;
	}

	if (conn != NULL && ok == FALSE)
		close_connection(conn);
}

static void
event_loop(struct mg_context *ctx)
{
	fd_set		read_set;
	struct timeval	tv;
	int		i, max_fd;

	while (ctx->stop_flag == 0) {
		FD_ZERO(&read_set);
		max_fd = -1;

		/* Add listening sockets to the read set */
		for (i = 0; i < ctx->num_listeners; i++)
			add_to_set(ctx->listeners[i].sock, &read_set, &max_fd);

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		if (select(max_fd + 1, &read_set, NULL, NULL, &tv) < 0) {
#ifdef _WIN32
			/*
			 * On windows, if read_set and write_set are empty,
			 * select() returns "Invalid parameter" error
			 * (at least on my Windows XP Pro). So in this case,
			 * we sleep here.
			 */
			Sleep(1000);
#endif /* _WIN32 */
		} else {
			for (i = 0; i < ctx->num_listeners; i++)
				if (FD_ISSET(ctx->listeners[i].sock, &read_set))
					accept_new_connection(
					    ctx->listeners + i, ctx);
		}
	}

	/* Stop signal received: somebody called mg_stop. Quit. */
	mg_fini(ctx);
}

void
mg_stop(struct mg_context *ctx)
{
	ctx->stop_flag = 1;
}

struct mg_context *
mg_start(void)
{
	struct mg_context	*ctx;
	int			i;

	if ((ctx = (struct mg_context *) calloc(1, sizeof(*ctx))) == NULL) {
		cry("cannot allocate mongoose context");
		return (NULL);
	}

	/* Initialize options. First pass: set default option values */
	for (i = 0; known_options[i].name != NULL; i++)
		ctx->options[setters[i].context_index] =
			known_options[i].default_value  == NULL ?
			NULL : mg_strdup(known_options[i].default_value);

	/* Call setter functions */
	for (i = 0; known_options[i].name != NULL; i++)
		if (setters[i].setter &&
		    ctx->options[setters[i].context_index] != NULL)
			if (setters[i].setter(ctx,
			    ctx->options[setters[i].context_index]) == FALSE) {
				mg_fini(ctx);
				return (NULL);
			}

	/* Initial document root is set to current working directory */
	ctx->options[OPT_ROOT] = getcwd(NULL, 0);

#if 0
	tm->tm_gmtoff - 3600 * (tm->tm_isdst > 0 ? 1 : 0);
#endif

#ifdef _WIN32
	{WSADATA data;	WSAStartup(MAKEWORD(2,2), &data);}
#endif /* _WIN32 */

	(void) pthread_mutex_init(&ctx->mutex, NULL);
	start_thread((mg_thread_func_t) event_loop, ctx);

	return (ctx);
}
