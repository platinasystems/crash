/* tools.c - core analysis suite
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * 11/09/99, 1.0    Initial Release
 * 11/12/99, 1.0-1  Bug fixes
 * 12/10/99, 1.1    Fixes, new commands, support for v1 SGI dumps
 * 01/18/00, 2.0    Initial gdb merger, support for Alpha
 * 02/01/00, 2.1    Bug fixes, new commands, options, support for v2 SGI dumps
 * 02/29/00, 2.2    Bug fixes, new commands, options
 * 04/11/00, 2.3    Bug fixes, new command, options, initial PowerPC framework
 * 04/12/00  ---    Transition to BitKeeper version control
 * 
 * BitKeeper ID: @(#)tools.c 1.16
 *
 * 09/28/00  ---    Transition to CVS version control
 *
 * CVS: $Revision: 1.56 $ $Date: 2002/01/29 22:20:13 $
 */

#include "defs.h"
#include <ctype.h>

static int calculate(char *, ulong *, ulonglong *, ulong);
static void print_number(struct number_option *, int, int);
static long alloc_hq_entry(void);
struct hq_entry;
static void dealloc_hq_entry(struct hq_entry *);

/*
 *  General purpose error reporting routine.  Type INFO prints the message
 *  and returns.  Type FATAL aborts the command in progress, and longjmps
 *  back to the appropriate recovery location.  If a FATAL occurs during 
 *  program initialization, exit() is called.
 *
 *  The idea is to get the message out so that it is seen by the user
 *  regardless of how the command output may be piped or redirected.
 *  Besides stderr, check whether the output is going to a file or pipe, and
 *  if so, intermingle the error message there as well.
 */
int
__error(int type, char *fmt, ...)
{
	int end_of_line, new_line;
        char buf[BUFSIZE];
	va_list ap;

	if (MCLXDEBUG(1)) {
                ulong retaddr[4] = { 0 };

                retaddr[0] = (ulong) __builtin_return_address(0);
#if defined(X86) || defined(PPC)
                retaddr[1] = (ulong) __builtin_return_address(1);
                retaddr[2] = (ulong) __builtin_return_address(2);
                retaddr[3] = (ulong) __builtin_return_address(2);
#endif

		console("error() trace: %lx => %lx => %lx => %lx\n",
			retaddr[3], retaddr[2], retaddr[1], retaddr[0]);
	}

	va_start(ap, fmt);
	(void)vsnprintf(buf, BUFSIZE, fmt, ap);
        va_end(ap);

	if (!fmt && FATAL_ERROR(type)) {
		fprintf(stdout, "\n");
		exit(1);
	}

	end_of_line = FATAL_ERROR(type) && !(pc->flags & RUNTIME);

	if ((new_line = (buf[0] == '\n')))
		shift_string_left(buf, 1);

	if (pc->stdpipe) {
		fprintf(pc->stdpipe, "%s%s: %s%s", 
			new_line ? "\n" : "", pc->curcmd, 
			type == WARNING ? "WARNING: " : "", buf);
		fflush(pc->stdpipe);
	} else { 
		fprintf(stdout, "%s%s: %s%s", 
			new_line || end_of_line ? "\n" : "",
			type == WARNING ? "WARNING" : pc->curcmd, 
			buf, end_of_line ? "\n" : "");
		fflush(stdout);
	}

        if ((fp != stdout) && (fp != pc->stdpipe)) {
                fprintf(fp, "%s%s: %s", new_line ? "\n" : "",
			type == WARNING ? "WARNING" : pc->curcmd, buf);
		fflush(fp);
	}

	if (pc->flags & DROP_CORE) {
		drop_core("DROP_CORE flag set\n");
	}

        switch (type)
        {
        case FATAL:
                if (pc->flags & IN_FOREACH) 
                        RESUME_FOREACH();
		/* FALLTHROUGH */

	case FATAL_RESTART:
                if (pc->flags & RUNTIME) 
                        RESTART();
                else {
			if (REMOTE())
				remote_exit();
                        exit(1);
		}

	default:
        case INFO:
	case WARNING:
                return FALSE;
        }
}

/*
 *  Parse a line into tokens, populate the passed-in argv[] array, and return
 *  the count of arguments found.  This function modifies the passed-string 
 *  by inserting a NULL character at the end of each token.  Expressions 
 *  encompassed by parentheses, and strings encompassed by apostrophes, are 
 *  collected into single tokens.
 */
int
parse_line(char *str, char *argv[])
{
	int i, j;
    	int string;
	int expression;

	for (i = 0; i < MAXARGS; i++)
		argv[i] = NULL;

	clean_line(str);

        if (str == NULL || strlen(str) == 0)
                return(0);

        i = j = 0;
        string = expression = FALSE;
        argv[j++] = str;

    	while (TRUE) {
		if (j == MAXARGS)
			error(FATAL, "too many arguments in string!\n");

        	while (str[i] != ' ' && str[i] != '\t' && str[i] != NULLCHAR) {
            		i++;
        	}

	        switch (str[i])
	        {
	        case ' ':
	        case '\t':
	            str[i++] = NULLCHAR;
	
	            if (str[i] == '"') {    
	                str[i] = ' ';
	                string = TRUE;
	                i++;
	            }

                    if (str[i] == '(') {     
                        expression = TRUE;
                    }
	
	            while (str[i] == ' ' || str[i] == '\t') {
	                i++;
	            }
	
	            if (str[i] != NULLCHAR && str[i] != '\n') {
	                argv[j++] = &str[i];
	                if (string) {
	                        string = FALSE;
	                        while (str[i] != '"' && str[i] != NULLCHAR)
	                                i++;
	                        if (str[i] == '"')
	                                str[i] = ' ';
	                }
                        if (expression) {
                                expression = FALSE;
                                while (str[i] != ')' && str[i] != NULLCHAR)
                                        i++;
                        }
	                break;
	            }
	                        /* else fall through */
	        case '\n':
	            str[i] = NULLCHAR;
	                        /* keep falling... */
	        case NULL:
	            argv[j] = NULLCHAR;
	            return(j);
	        }
    	}  
}

/*
 *  Defuse controversy re: extensions to ctype.h 
 */
int 
whitespace(int c)
{
	return ((c == ' ') ||(c == '\t'));
}

int
ascii(int c)
{
	return ((c >= 0) && ( c <= 0x7f));
}

/*
 *  Strip line-ending whitespace and linefeeds.
 */
char *
strip_line_end(char *line)
{
	strip_linefeeds(line);
	strip_ending_whitespace(line);
	return(line);
}

/*
 *  Strip line-beginning and line-ending whitespace and linefeeds.
 */
char *
clean_line(char *line)
{
	strip_beginning_whitespace(line);
        strip_linefeeds(line);
        strip_ending_whitespace(line);
        return(line);
}

/*
 *  Strip line-ending linefeeds in a string.
 */
char *
strip_linefeeds(char *line)
{
	char *p;

	if (line == NULL || strlen(line) == 0)
		return(line);

	p = &LASTCHAR(line);

	while (*p == '\n') {
		*p = NULLCHAR;
		if (--p < line)
			break; 
	}

	return(line);
}

/*
 *  Strip a specified line-ending character in a string.
 */
char *
strip_ending_char(char *line, char c)
{
        char *p;

        if (line == NULL || strlen(line) == 0)
                return(line);

        p = &LASTCHAR(line);

        if (*p == c)
                *p = NULLCHAR;

        return(line);
}

/*
 *  Strip a specified line-beginning character in a string.
 */
char *
strip_beginning_char(char *line, char c)
{
        if (line == NULL || strlen(line) == 0)
                return(line);

        if (FIRSTCHAR(line) == c)
                shift_string_left(line, 1);

        return(line);
}




/*
 *  Strip line-ending whitespace.
 */
char *
strip_ending_whitespace(char *line)
{
        char *p;

	if (line == NULL || strlen(line) == 0)
                return(line);

        p = &LASTCHAR(line);

        while (*p == ' ' || *p == '\t') {
                *p = NULLCHAR;
                if (p == line)
                        break;
                p--;
        }

        return(line);
}

/*
 *  Strip line-beginning whitespace.
 */
char *
strip_beginning_whitespace(char *line)
{
	char buf[BUFSIZE];
        char *p;

	if (line == NULL || strlen(line) == 0)
                return(line);

	strcpy(buf, line);
	p = &buf[0];
	while (*p == ' ' || *p == '\t')
		p++;
	strcpy(line, p);

        return(line);
}

/*
 *  End line at first comma found.
 */
char *
strip_comma(char *line)
{
	char *p;

	if ((p = strstr(line, ",")))
		*p = NULLCHAR;

	return(line);
}

/*
 *  Strip the 0x from the beginning of a hexadecimal value string.
 */
char *
strip_hex(char *line)
{
	if (STRNEQ(line, "0x")) 
		shift_string_left(line, 2);	

	return(line);
}

/*
 *  Turn a string into upper-case.
 */
char *
upper_case(char *s, char *buf)
{
	char *p1, *p2;

	p1 = s;
	p2 = buf;

	while (*p1) {
		*p2 = toupper(*p1);
		p1++, p2++;	
	}

	*p2 = NULLCHAR;

	return(buf);
}

/*
 *  Return pointer to first non-space/tab in a string.
 */
char *
first_nonspace(char *s)
{
        return(s + strspn(s, " \t"));
}

/*
 *  Return pointer to first space/tab in a string.  If none are found,
 *  return a pointer to the string terminating NULL.
 */
char *
first_space(char *s)
{
        return(s + strcspn(s, " \t"));
}

/*
 *  Replace the first space/tab found in a string with a NULL character.
 */
char *
null_first_space(char *s)
{
	char *p1;

	p1 = first_space(s);
	if (*p1)
		*p1 = NULLCHAR;

	return s;
}

/*
 *  Replace any instances of the characters in string c that are found in
 *  string s with the character passed in r.
 */
char *
replace_string(char *s, char *c, char r)
{
	int i, j;

	for (i = 0; s[i]; i++) {
		for (j = 0; c[j]; j++) {
			if (s[i] == c[j])
				s[i] = r;
		}
	}

	return s;
}


/*
 *  Prints a string verbatim, allowing strings with % signs to be displayed
 *  without printf conversions.
 */
void
print_verbatim(FILE *filep, char *line)
{
	int i;

        for (i = 0; i < strlen(line); i++) {
                fputc(line[i], filep);
		fflush(filep);
	}
}

char *
fixup_percent(char *s)
{
	char *p1;

	if ((p1 = strstr(s, "%")) == NULL)
		return s;

	s[strlen(s)+1] = NULLCHAR;
       	memmove(p1+1, p1, strlen(p1));
	*p1 = '%';

	return s;
}

/*
 *  Convert an indeterminate number string to either a hexadecimal or decimal 
 *  long value.  Translate with a bias towards decimal unless HEX_BIAS is set.
 */
ulong
stol(char *s, int flags, int *errptr)
{
	if ((flags & HEX_BIAS) && hexadecimal(s, 0)) 
        	return(htol(s, flags, errptr));
	else {
        	if (decimal(s, 0))
                	return(dtol(s, flags, errptr));
        	else if (hexadecimal(s, 0))
                	return(htol(s, flags, errptr));
	}

	if (!(flags & QUIET))
        	error(INFO, "not a valid number: %s\n", s);

        switch (flags & (FAULT_ON_ERROR|RETURN_ON_ERROR))
        {
        case FAULT_ON_ERROR:
               	RESTART();

        case RETURN_ON_ERROR:
		if (errptr)
			*errptr = TRUE;
		break;
        }

	return UNUSED;
}

ulonglong
stoll(char *s, int flags, int *errptr)
{
        if ((flags & HEX_BIAS) && hexadecimal(s, 0))
                return(htoll(s, flags, errptr));
        else {
                if (decimal(s, 0))
                        return(dtoll(s, flags, errptr));
                else if (hexadecimal(s, 0))
                        return(htoll(s, flags, errptr));
        }
 
	if (!(flags & QUIET))
        	error(INFO, "not a valid number: %s\n", s);

        switch (flags & (FAULT_ON_ERROR|RETURN_ON_ERROR))
        {
        case FAULT_ON_ERROR:
                RESTART();

        case RETURN_ON_ERROR:
                if (errptr)
                        *errptr = TRUE;
                break;
        }

        return UNUSED;
}

/*
 *  Append a two-character string to a number to make 1, 2, 3 and 4 into 
 *  1st, 2nd, 3rd, 4th, and so on...
 */
char *
ordinal(ulong val, char *buf)
{
	char *p1;
	
	sprintf(buf, "%ld", val);
	p1 = &buf[strlen(buf)-1];

	switch (*p1)
	{
	case '1':
		strcat(buf, "st");
		break;
	case '2':
		strcat(buf, "nd");
		break;
	case '3':
		strcat(buf, "rd");
		break;
	default:
		strcat(buf, "th");
		break;
	}

	return buf;
}

/*
 *  Convert a string into:
 *
 *   1.  an evaluated expression if it's enclosed within parentheses.
 *   2.  to a decimal value if the string is all decimal characters.
 *   3.  to a hexadecimal value if the string is all hexadecimal characters.
 *   4.  to a symbol value if the string is a known symbol.
 *
 *  If HEX_BIAS is set, pass the value on to htol().
 */
ulong
convert(char *s, int flags, int *errptr, ulong numflag)
{
	struct syment *sp;

	if ((numflag & NUM_EXPR) && can_eval(s))
             	return(eval(s, flags, errptr));

	if ((flags & HEX_BIAS) && (numflag & NUM_HEX) && hexadecimal(s, 0))
                return(htol(s, flags, errptr));
	else {
		if ((numflag & NUM_DEC) && decimal(s, 0))
	        	return(dtol(s, flags, errptr));
		if ((numflag & NUM_HEX) && hexadecimal(s, 0))
	        	return(htol(s, flags, errptr));
	}
	
	if ((sp = symbol_search(s)))
		return(sp->value);

        error(INFO, "cannot convert \"%s\"\n", s);

        switch (flags & (FAULT_ON_ERROR|RETURN_ON_ERROR))
        {
        case FAULT_ON_ERROR:
                RESTART();

        case RETURN_ON_ERROR:
                if (errptr)
                	*errptr = TRUE;
		break;
        }

        return UNUSED;
}

/*
 *  Convert a string to a hexadecimal long value.
 */
ulong
htol(char *s, int flags, int *errptr)
{
    	long i, j; 
	ulong n;

    	if (s == NULL) { 
		if (!(flags & QUIET))
			error(INFO, "received NULL string\n");
		goto htol_error;
	}

    	if (STRNEQ(s, "0x") || STRNEQ(s, "0X"))
		s += 2;

    	if (strlen(s) > MAX_HEXADDR_STRLEN) { 
		if (!(flags & QUIET))
			error(INFO, 
			    "input string too large: \"%s\" (%d vs %d)\n", 
				s, strlen(s), MAX_HEXADDR_STRLEN);
		goto htol_error;
	}

    	for (n = i = 0; s[i] != 0; i++) {
	        switch (s[i]) 
	        {
	            case 'a':
	            case 'b':
	            case 'c':
	            case 'd':
	            case 'e':
	            case 'f':
	                j = (s[i] - 'a') + 10;
	                break;
	            case 'A':
	            case 'B':
	            case 'C':
	            case 'D':
	            case 'E':
	            case 'F':
	                j = (s[i] - 'A') + 10;
	                break;
	            case '1':
	            case '2':
	            case '3':
	            case '4':
	            case '5':
	            case '6':
	            case '7':
	            case '8':
	            case '9':
	            case '0':
	                j = s[i] - '0';
	                break;
		    case 'x':
		    case 'X':
		    case 'h':
			continue;
	            default:
			if (!(flags & QUIET))
				error(INFO, "invalid input: \"%s\"\n", s);
			goto htol_error;
	        }
	        n = (16 * n) + j;
    	}

    	return(n);

htol_error:
	switch (flags & (FAULT_ON_ERROR|RETURN_ON_ERROR))
	{
	case FAULT_ON_ERROR:
		RESTART();

	case RETURN_ON_ERROR:
		if (errptr)
			*errptr = TRUE;
		break;
	}

	return BADADDR;
}

/*
 *  Convert a string to a hexadecimal unsigned long long value.
 */
ulonglong
htoll(char *s, int flags, int *errptr)
{
    	long i, j; 
	ulonglong n;

    	if (s == NULL) { 
		if (!(flags & QUIET))
			error(INFO, "received NULL string\n");
		goto htoll_error;
	}

    	if (STRNEQ(s, "0x") || STRNEQ(s, "0X"))
		s += 2;

    	if (strlen(s) > LONG_LONG_PRLEN) { 
		if (!(flags & QUIET))
			error(INFO, 
			    "input string too large: \"%s\" (%d vs %d)\n", 
				s, strlen(s), LONG_LONG_PRLEN);
		goto htoll_error;
	}

    	for (n = i = 0; s[i] != 0; i++) {
	        switch (s[i]) 
	        {
	            case 'a':
	            case 'b':
	            case 'c':
	            case 'd':
	            case 'e':
	            case 'f':
	                j = (s[i] - 'a') + 10;
	                break;
	            case 'A':
	            case 'B':
	            case 'C':
	            case 'D':
	            case 'E':
	            case 'F':
	                j = (s[i] - 'A') + 10;
	                break;
	            case '1':
	            case '2':
	            case '3':
	            case '4':
	            case '5':
	            case '6':
	            case '7':
	            case '8':
	            case '9':
	            case '0':
	                j = s[i] - '0';
	                break;
		    case 'x':
		    case 'X':
		    case 'h':
			continue;
	            default:
			if (!(flags & QUIET))
				error(INFO, "invalid input: \"%s\"\n", s);
			goto htoll_error;
	        }
	        n = (16 * n) + j;
    	}

    	return(n);

htoll_error:
	switch (flags & (FAULT_ON_ERROR|RETURN_ON_ERROR))
	{
	case FAULT_ON_ERROR:
		RESTART();

	case RETURN_ON_ERROR:
		if (errptr)
			*errptr = TRUE;
		break;
	}

	return UNUSED;
}


/*
 *  Convert a string to a decimal long value.
 */
ulong
dtol(char *s, int flags, int *errptr)
{
        ulong retval;
        char *p, *orig;
        int j;

        if (s == NULL) {
		if (!(flags & QUIET))
                	error(INFO, "received NULL string\n");
                goto dtol_error;
        }

	if (strlen(s) == 0)
                goto dtol_error;

        p = orig = &s[0];
        while (*p++ == ' ')
                s++;

        for (j = 0; s[j] != '\0'; j++)
                if ((s[j] < '0' || s[j] > '9'))
                        break ;

	if (s[j] != '\0') {
		if (!(flags & QUIET))
                	error(INFO, "%s: \"%c\" is not a digit 0 - 9\n", 
				orig, s[j]);
                goto dtol_error;
	} else if (sscanf(s, "%lu", &retval) != 1) {
		if (!(flags & QUIET))
                	error(INFO, "invalid expression\n");
                goto dtol_error;
        }

        return(retval);

dtol_error:
        switch (flags & (FAULT_ON_ERROR|RETURN_ON_ERROR))
        {
        case FAULT_ON_ERROR:
                RESTART();

        case RETURN_ON_ERROR:
		if (errptr)
			*errptr = TRUE;
                break;
        }

	return UNUSED;
}


/*
 *  Convert a string to a decimal long value.
 */
ulonglong
dtoll(char *s, int flags, int *errptr)
{
        ulonglong retval;
        char *p, *orig;
        int j;

        if (s == NULL) {
		if (!(flags & QUIET))
                	error(INFO, "received NULL string\n");
                goto dtoll_error;
        }

	if (strlen(s) == 0)
                goto dtoll_error;

        p = orig = &s[0];
        while (*p++ == ' ')
                s++;

        for (j = 0; s[j] != '\0'; j++)
                if ((s[j] < '0' || s[j] > '9'))
                        break ;

	if (s[j] != '\0') {
		if (!(flags & QUIET))
                	error(INFO, "%s: \"%c\" is not a digit 0 - 9\n", 
				orig, s[j]);
                goto dtoll_error;
	} else if (sscanf(s, "%llu", &retval) != 1) {
		if (!(flags & QUIET))
                	error(INFO, "invalid expression\n");
                goto dtoll_error;
        }

        return (retval);

dtoll_error:
        switch (flags & (FAULT_ON_ERROR|RETURN_ON_ERROR))
        {
        case FAULT_ON_ERROR:
                RESTART();

        case RETURN_ON_ERROR:
		if (errptr)
			*errptr = TRUE;
                break;
        }

	return ((ulonglong)(-1));
}


/*
 *  Convert a string to a decimal integer value.
 */
unsigned int
dtoi(char *s, int flags, int *errptr)
{
        unsigned int retval;
        char *p;
        int j;

        if (s == NULL) {
		if (!(flags & QUIET))
                	error(INFO, "received NULL string\n");
                goto dtoi_error;
        }

        p = &s[0];
        while (*p++ == ' ')
                s++;

        for (j = 0; s[j] != '\0'; j++)
                if ((s[j] < '0' || s[j] > '9'))
                        break ;

        if (s[j] != '\0' || (sscanf(s, "%d", &retval) != 1)) {
		if (!(flags & QUIET))
                	error(INFO, "%s: \"%c\" is not a digit 0 - 9\n", 
				s, s[j]);
                goto dtoi_error;
        }

        return(retval);

dtoi_error:
        switch (flags & (FAULT_ON_ERROR|RETURN_ON_ERROR))
        {
        case FAULT_ON_ERROR:
                RESTART();

        case RETURN_ON_ERROR:
		if (errptr)
			*errptr = TRUE;
                break;
        }

        return((unsigned int)(-1));
}

/*
 *  Determine whether a string contains only decimal characters.
 *  If count is non-zero, limit the search to count characters.
 */
int
decimal(char *s, int count)
{
    	char *p;
	int cnt;

	if (!count)
		strip_line_end(s);
	else
		cnt = count;

    	for (p = &s[0]; *p; p++) {
	        switch(*p)
	        {
	            case '0':
	            case '1':
	            case '2':
	            case '3':
	            case '4':
	            case '5':
	            case '6':
	            case '7':
	            case '8':
	            case '9':
	            case ' ':
	                break;
	            default:
	                return FALSE;
	        }

		if (count && (--cnt == 0))
			break;
    	}

    	return TRUE;
}

/*
 *  Extract a hexadecimal number from a string.  If first_instance is FALSE,
 *  and two possibilities are found, a fatal error results.
 */
int
extract_hex(char *s, ulong *result, char stripchar, ulong first_instance)
{
	int i, found;
        char *arglist[MAXARGS];
        int argc;
	ulong value;
	char *buf;

	buf = GETBUF(strlen(s));
	strcpy(buf, s);
	argc = parse_line(buf, arglist);

	for (i = found = 0; i < argc; i++) {
		if (stripchar) 
			strip_ending_char(arglist[i], stripchar);
		
		if (hexadecimal(arglist[i], 0)) {
			if (found) {
				FREEBUF(buf);
				error(FATAL, 
				    "two hexadecimal args in: \"%s\"\n",
					strip_linefeeds(s));
			}
			value = htol(arglist[i], FAULT_ON_ERROR, NULL);
			found = TRUE;
			if (first_instance)
				break;
		}
	}

	FREEBUF(buf);

	if (found) {
		*result = value;
		return TRUE;
	} 

	return FALSE;
}


/*
 *  Determine whether a string contains only printable ASCII characters.
 */
int
ascii_string(char *s)
{
        char *p;

        for (p = &s[0]; *p; p++) {
		if (!ascii(*p)) 
			return FALSE;
        }

        return TRUE;
}


/*
 *  Determine whether a string contains only hexadecimal characters.
 *  If count is non-zero, limit the search to count characters.
 */
int
hexadecimal(char *s, int count)
{
    	char *p;
	int cnt;

	if (!count)
		strip_line_end(s);
	else
		cnt = count;

	for (p = &s[0]; *p; p++) {
        	switch(*p) 
		{
	        case 'a':
	        case 'b':
	        case 'c':
	        case 'd':
	        case 'e':
	        case 'f':
	        case 'A':
	        case 'B':
	        case 'C':
	        case 'D':
	        case 'E':
	        case 'F':
	        case '1':
	        case '2':
	        case '3':
	        case '4':
	        case '5':
	        case '6':
	        case '7':
	        case '8':
	        case '9':
	        case '0':
	        case 'x':
	        case 'X':
	                break;

	        case ' ':
	                if (*(p+1) == NULLCHAR)
	                    break;
	                else
	                    return FALSE;
		default:
			return FALSE;
        	}

		if (count && (--cnt == 0))
			break;
    	}

    	return TRUE;
}

/*
 *  Determine whether a string contains only hexadecimal characters.
 *  and cannot be construed as a decimal number.
 *  If count is non-zero, limit the search to count characters.
 */
int
hexadecimal_only(char *s, int count)
{
    	char *p;
	int cnt, only;

	if (!count)
		strip_line_end(s);
	else
		cnt = count;

	only = 0;

	for (p = &s[0]; *p; p++) {
        	switch(*p) 
		{
	        case 'a':
	        case 'b':
	        case 'c':
	        case 'd':
	        case 'e':
	        case 'f':
	        case 'A':
	        case 'B':
	        case 'C':
	        case 'D':
	        case 'E':
	        case 'F':
                case 'x':
                case 'X':
			only++;
			break;
	        case '1':
	        case '2':
	        case '3':
	        case '4':
	        case '5':
	        case '6':
	        case '7':
	        case '8':
	        case '9':
	        case '0':
	                break;

	        case ' ':
	                if (*(p+1) == NULLCHAR)
	                    break;
	                else
	                    return FALSE;
		default:
			return FALSE;
        	}

		if (count && (--cnt == 0))
			break;
    	}

    	return only;
}

/*
 *  Translate a hexadecimal string into its ASCII components.
 */
void
cmd_ascii(void)
{
        int i;
        ulonglong value;
	char *s;
        int c, prlen, bytes;

	optind = 1;
	if (!args[optind]) {
		fprintf(fp, "\n");
		fprintf(fp, "      0    1   2   3   4   5   6   7\n");
		fprintf(fp, "    +-------------------------------\n");
		fprintf(fp, "  0 | NUL DLE  SP  0   @   P   '   p\n");
		fprintf(fp, "  1 | SOH DC1  !   1   A   Q   a   q\n");
		fprintf(fp, "  2 | STX DC2  %c   2   B   R   b   r\n", 0x22);
		fprintf(fp, "  3 | ETX DC3  #   3   C   S   c   s\n");
		fprintf(fp, "  4 | EOT DC4  $   4   D   T   d   t\n");
		fprintf(fp, "  5 | ENQ NAK  %c   5   E   U   e   u\n", 0x25);
		fprintf(fp, "  6 | ACK SYN  &   6   F   V   f   v\n");
		fprintf(fp, "  7 | BEL ETB  `   7   G   W   g   w\n");
		fprintf(fp, "  8 |  BS CAN  (   8   H   X   h   x\n");
		fprintf(fp, "  9 |  HT  EM  )   9   I   Y   i   y\n");
		fprintf(fp, "  A |  LF SUB  *   :   J   Z   j   z\n");
		fprintf(fp, "  B |  VT ESC  +   ;   K   [   k   {\n");
		fprintf(fp, "  C |  FF  FS  ,   <   L   %c   l   |\n", 0x5c);
		fprintf(fp, "  D |  CR  GS  _   =   M   ]   m   }\n");
		fprintf(fp, "  E |  SO  RS  .   >   N   ^   n   ~\n");
		fprintf(fp, "  F |  SI  US  /   ?   O   -   o  DEL\n");
		fprintf(fp, "\n");
		return;
	}
	
        while (args[optind]) {

		s = args[optind];
        	if (STRNEQ(s, "0x") || STRNEQ(s, "0X"))
                	s += 2;

                if (strlen(s) > LONG_PRLEN) {
			prlen = LONG_LONG_PRLEN;
			bytes = sizeof(long long);
		} else {
			prlen = LONG_PRLEN;
			bytes = sizeof(long);
		}
		
                value = htoll(s, FAULT_ON_ERROR, NULL);
                fprintf(fp, "%.*llx: ", prlen, value);
		for (i = 0; i < bytes; i++) {
			c = (value >> (8*i)) & 0xff;
			if ((c >= 0x20) && (c < 0x7f)) {
				fprintf(fp, "%c", (char)c);
				continue;
			}
			if (c > 0x7f) {
				fprintf(fp, "<%02x>", c);
				continue;
			}
			switch (c)
			{
			case 0x0: fprintf(fp, "<NUL>"); break;
			case 0x1: fprintf(fp, "<SOH>"); break;
			case 0x2: fprintf(fp, "<STX>"); break;
			case 0x3: fprintf(fp, "<ETX>"); break;
			case 0x4: fprintf(fp, "<EOT>"); break;
			case 0x5: fprintf(fp, "<ENQ>"); break;
			case 0x6: fprintf(fp, "<ACK>"); break;
			case 0x7: fprintf(fp, "<BEL>"); break;
			case 0x8: fprintf(fp, "<BS>"); break;
			case 0x9: fprintf(fp, "<HT>"); break;
			case 0xa: fprintf(fp, "<LF>"); break;
			case 0xb: fprintf(fp, "<VT>"); break;
			case 0xc: fprintf(fp, "<FF>"); break;
			case 0xd: fprintf(fp, "<CR>"); break;
			case 0xe: fprintf(fp, "<SO>"); break;
			case 0xf: fprintf(fp, "<SI>"); break;
			case 0x10: fprintf(fp, "<DLE>"); break;
			case 0x11: fprintf(fp, "<DC1>"); break;
			case 0x12: fprintf(fp, "<DC2>"); break;
			case 0x13: fprintf(fp, "<DC3>"); break;
			case 0x14: fprintf(fp, "<DC4>"); break;
			case 0x15: fprintf(fp, "<NAK>"); break;
			case 0x16: fprintf(fp, "<SYN>"); break;
			case 0x17: fprintf(fp, "<ETB>"); break;
			case 0x18: fprintf(fp, "<CAN>"); break;
			case 0x19: fprintf(fp, "<EM>"); break;
			case 0x1a: fprintf(fp, "<SUB>"); break;
			case 0x1b: fprintf(fp, "<ESC>"); break;
			case 0x1c: fprintf(fp, "<FS>"); break;
			case 0x1d: fprintf(fp, "<GS>"); break;
			case 0x1e: fprintf(fp, "<RS>"); break;
			case 0x1f: fprintf(fp, "<US>"); break;
			case 0x7f: fprintf(fp, "<DEL>"); break;
			}
		}
		fprintf(fp, "\n");

                optind++;
        }

}

/*
 *  Counts number of leading whitespace characters in a string.
 */
int
count_leading_spaces(char *s)
{
        return (strspn(s, " \t"));
}

/*
 *  Prints the requested number of spaces.
 */
void
pad_line(FILE *filep, int cnt, char c)
{
	int i;

	for (i = 0; i < cnt; i++) 
		fputc(c, filep);
}

/*
 *  Returns appropriate number of inter-field spaces in a usable string.
 *  MINSPACE is defined as -100, but implies the minimum space between two
 *  fields.  Currently this can be either one or two spaces, depending upon
 *  the architecture.  Since the mininum space must be at least 1, MINSPACE,
 *  MINSPACE-1 and MINSPACE+1 are all valid, special numbers.  Otherwise
 *  the space count must be greater than or equal to 0.
 */
char *
space(int cnt)
{
	static char spacebuf[20] = "                    ";

	if ((cnt > 20) || (cnt < (MINSPACE-1)))
		error(FATAL, "illegal spacing request: %d\n", cnt);
	if (cnt < (MINSPACE-1))
		error(FATAL, "illegal spacing request\n");
	if ((cnt > MINSPACE+1) && (cnt < 0))
		error(FATAL, "illegal spacing request\n");

	switch (cnt)
	{
	case (MINSPACE-1):
		if (VADDR_PRLEN > 8)
			return (&spacebuf[20]);    /* NULL */
		else
			return (&spacebuf[20-1]);  /* 1 space */

	case MINSPACE:
		if (VADDR_PRLEN > 8)
			return (&spacebuf[20-1]);  /* 1 space */
		else
			return (&spacebuf[20-2]);  /* 2 spaces */

	case (MINSPACE+1):
                if (VADDR_PRLEN > 8) 
                        return (&spacebuf[20-2]);  /* 2 spaces */
                else    
                        return (&spacebuf[20-3]);  /* 3 spaces */

	default:
		return (&spacebuf[20-cnt]);        /* as requested */
	}
}

/*
 *  Determine whether substring s1, with length len, and contained within
 *  string s, is surrounded by <bracket> characters.  If len is 0, calculate
 *  it.
 */
int
bracketed(char *s, char *s1, int len)
{
	char *s2;

	if (!len) {
		if (!(s2 = strstr(s1, ">")))
			return FALSE;
		len = s2-s1;
	}

	if (((s1-s) < 1) || (*(s1-1) != '<') || 
	    ((s1+len) >= &s[strlen(s)]) || (*(s1+len) != '>'))
		return FALSE;

	return TRUE;
}

/*
 *  Counts the number of a specified character in a string.
 */
int
count_chars(char *s, char c)
{
	char *p;
	int count;

	if (!s)
		return 0;

	count = 0;

	for (p = s; *p; p++) {
		if (*p == c)
			count++;
	}

	return count;
}

/*
 *  Counts the number of a specified characters in a buffer.
 */
long count_buffer_chars(char *bufptr, char c, long len)
{
	long i, cnt;

	for (i = cnt = 0; i < len; i++, bufptr++) {
		if (*bufptr == c)
			cnt++;
	}

	return cnt;
}

/*
 *  Concatenates the tokens in the global args[] array into one string,
 *  separating each token with one space.  If the no_options flag is set,
 *  don't include any args beginning with a dash character.
 */
char *
concat_args(char *buf, int arg, int no_options)
{
	int i;

	BZERO(buf, BUFSIZE);

        for (i = arg; i < argcnt; i++) {
		if (no_options && STRNEQ(args[i], "-"))
			continue;
                strcat(buf, args[i]);
                strcat(buf, " ");
        }

	return(strip_ending_whitespace(buf));
}

/*
 *  Shifts the contents of a string to the left by cnt characters, 
 *  disposing the leftmost characters.
 */
char *
shift_string_left(char *s, int cnt)
{
	int origlen;

	if (!cnt)
		return(s);

	origlen = strlen(s);
	memmove(s, s+cnt, (origlen-cnt));
	*(s+(origlen-cnt)) = NULLCHAR;
	return(s);
}

/*
 *  Shifts the contents of a string to the right by cnt characters,
 *  inserting space characters.  (caller confirms space is available)
 */
char *
shift_string_right(char *s, int cnt)
{
	int i;
        int origlen;

	if (!cnt)
		return(s);

        origlen = strlen(s);
        memmove(s+cnt, s, origlen);
        *(s+(origlen+cnt)) = NULLCHAR;

	for (i = 0; i < cnt; i++)
		s[i] = ' ';

        return(s);
}

/*
 *  Create a string in a buffer of a given size, centering, or justifying 
 *  left or right as requested.  If the opt argument is used, then the string
 *  is created with its string/integer value.  If opt is NULL, then the
 *  string is already in contained in string s (not justified). 
 */
char *
mkstring(char *s, int size, ulong flags, const char *opt)
{
	int i;
	int len;
	int extra;
	int left;
	int right;
	char buf[BUFSIZE];

	switch (flags & (LONG_DEC|LONG_HEX|INT_HEX|INT_DEC)) 
	{
	case LONG_DEC:
		sprintf(s, "%lu", (ulong)opt);
		break;
	case LONG_HEX:
		sprintf(s, "%lx", (ulong)opt);
		break;
	case INT_DEC:
		sprintf(s, "%u", (uint)((ulong)opt));
		break;
	case INT_HEX:
		sprintf(s, "%x", (uint)((ulong)opt));
		break;
	default:
		if (opt)
			strcpy(s, opt);
		break;
	}

	/*
	 *  At this point, string s has the string to be justified,
	 *  and has room to work with.  The relevant flags from this
	 *  point on are of CENTER, LJUST and RJUST.  If the length 
	 *  of string s is already larger than the requested size, 
	 *  just return it as is.
	 */
	len = strlen(s);
	if (size <= len) 
		return(s);
	extra = size - len;

	if (flags & CENTER) {
		/*
		 *  If absolute centering is not possible, justify the
		 *  string as requested -- or to the left if no justify
		 *  argument was passed in.
		 */
		if (extra % 2) {
			switch (flags & (LJUST|RJUST))
			{
			default:
			case LJUST:
				right = (extra/2) + 1;
				left = extra/2;
				break;
			case RJUST:
				right = extra/2;
				left = (extra/2) + 1;
				break;
			}
		}
		else 
			left = right = extra/2;
	
		bzero(buf, BUFSIZE);
		for (i = 0; i < left; i++)
			strcat(buf, " ");
		strcat(buf, s);
		for (i = 0; i < right; i++)
			strcat(buf, " ");
	
		strcpy(s, buf);
		return(s);
	}

	if (flags & LJUST) {
		for (i = 0; i < extra; i++)
			strcat(s, " ");
	} else if (flags & RJUST) 
		shift_string_right(s, extra);

	return(s);
}

/*
 *  Prints the requested number of BACKSPACE characters.
 */
void
backspace(int cnt)
{
	int i;

	for (i = 0; i < cnt; i++) 
		fprintf(fp, "\b");
}

/*
 *  Set/display process context or internal variables.  Processes are set
 *  by their task or PID number, or to the panic context with the -p flag.
 *  Internal variables may be viewed or changed, depending whether an argument 
 *  follows the variable name.  If no arguments are entered, the current
 *  process context is dumped.  The current set of variables and their
 *  acceptable settings are:
 *
 *        debug  "on", "off", or any number.  "on" sets it to a value of 1.
 *         hash  "on", "off", or any number.  Non-zero numbers are converted 
 *               to "on", zero is converted to "off".
 *       scroll  "on", "off", or any number.  Non-zero numbers are converted 
 *               to "on", zero is converted to "off".
 *       silent  "on", "off", or any number.  Non-zero numbers are converted
 *               to "on", zero is converted to "off".
 *      refresh  "on", "off", or any number.  Non-zero numbers are converted
 *               to "on", zero is converted to "off".
 *          sym  regular filename
 *      console  device filename
 *        radix  10 or 16
 *         core  (no arg) drop core when error() is called.
 *           vi  (no arg) set editing mode to vi (from .rc file only).
 *        emacs  (no arg) set editing mode to emacs (from .rc file only).
 *     namelist  kernel name (from .rc file only).
 *     dumpfile  dumpfile name (from .rc file only).
 *
 *  gdb variable settings not changeable by gdb's "set" command:
 *
 *    print_max  value (default is 200).
 */
void
cmd_set(void)
{
	int i;
	int c;
	ulong value;
	int cpu;
	int runtime;
	char buf[BUFSIZE];
	struct task_context *tc;

	runtime = pc->flags & RUNTIME;

        while ((c = getopt(argcnt, args, "pc:")) != EOF) {
                switch(c)
		{
		case 'c':
			if (!runtime) {
				error(INFO, 
				    "cpu setting not allowed from .%src\n",
					pc->program_name);
				break;
			}
		        if (ACTIVE()) {
                		error(INFO, "not allowed on a live system\n");
				argerrs++;
				break;
			}
			cpu = dtoi(optarg, FAULT_ON_ERROR, NULL);
			set_cpu(cpu);
			return;

		case 'p':
			if (!runtime)
				return;

			if (ACTIVE()) {
				set_context(NO_TASK, pc->program_pid);
				show_context(CURRENT_CONTEXT(), 0, FALSE);
				return;
			}

			if (!tt->panic_task) {
                		error(INFO, "no panic task found!\n");
				return;
			}
        		set_context(tt->panic_task, NO_PID);
			show_context(CURRENT_CONTEXT(), 0, FALSE);
			return;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs) {
		if (runtime)
			cmd_usage(pc->curcmd, SYNOPSIS);
		return;
	}

	if (!args[optind]) {
		if (runtime)
			show_context(CURRENT_CONTEXT(), 0, FALSE);
		return;
	}

	while (args[optind]) {
		if (STREQ(args[optind], "debug")) {
                        if (args[optind+1]) {
                                optind++;
                                if (STREQ(args[optind], "on"))
                                        pc->debug = 1;
                                else if (STREQ(args[optind], "off"))
                                        pc->debug = 0;
				else if (IS_A_NUMBER(args[optind])) 
					pc->debug = stol(args[optind], 
						FAULT_ON_ERROR, NULL);
				else
					goto invalid_set_command;
                        }
			if (runtime)
                        	fprintf(fp, "debug: %ld\n", pc->debug);

			set_lkcd_debug(pc->debug);
			set_vas_debug(pc->debug);

                } else if (STREQ(args[optind], "hash")) {
                        if (args[optind+1]) {
                                optind++;
                                if (STREQ(args[optind], "on"))
                                        pc->flags |= HASH;
                                else if (STREQ(args[optind], "off"))
                                        pc->flags &= ~HASH;
				else if (IS_A_NUMBER(args[optind])) {
					value = stol(args[optind],
                                    		FAULT_ON_ERROR, NULL);
					if (value)
						pc->flags |= HASH;
					else
						pc->flags &= ~HASH;
				} else
					goto invalid_set_command;
                        }

			if (runtime)
                        	fprintf(fp, "hash: %s\n",
                                	pc->flags & HASH ? "on" : "off");

               } else if (STREQ(args[optind], "refresh")) {
                        if (args[optind+1]) {
                                optind++;
                                if (STREQ(args[optind], "on"))
                                        tt->flags |= TASK_REFRESH;
                                else if (STREQ(args[optind], "off")) {
                                        tt->flags &= ~TASK_REFRESH;
					if (!runtime)
						tt->flags |= TASK_REFRESH_OFF;
                                } else if (IS_A_NUMBER(args[optind])) {
                                        value = stol(args[optind],
                                                FAULT_ON_ERROR, NULL);
                                        if (value)
                                                tt->flags |= TASK_REFRESH;
                                        else {
                                                tt->flags &= ~TASK_REFRESH;
						if (!runtime)
							tt->flags |= 
							    TASK_REFRESH_OFF;
					}
                                } else
					goto invalid_set_command;
                        }

                        if (runtime)
                                fprintf(fp, "refresh: %s\n",
                               	    tt->flags & TASK_REFRESH ?  "on" : "off");

               } else if (STREQ(args[optind], "scroll")) {
                        if (args[optind+1] && pc->scroll_command) {
                                optind++;
                                if (STREQ(args[optind], "on"))
                                        pc->flags |= SCROLL;
                                else if (STREQ(args[optind], "off"))
                                        pc->flags &= ~SCROLL;
                                else if (IS_A_NUMBER(args[optind])) {
                                        value = stol(args[optind],
                                                FAULT_ON_ERROR, NULL);
                                        if (value)
                                                pc->flags |= SCROLL;
                                        else
                                                pc->flags &= ~SCROLL;
                                } else
					goto invalid_set_command;
                        }

			if (runtime)
                        	fprintf(fp, "scroll: %s\n",
                                	pc->flags & SCROLL ? "on" : "off");

               } else if (STREQ(args[optind], "silent")) {
                        if (args[optind+1]) {
                                optind++;
                                if (STREQ(args[optind], "on")) {
                                        pc->flags |= SILENT;
					pc->flags &= ~SCROLL;
				}
                                else if (STREQ(args[optind], "off"))
                                        pc->flags &= ~SILENT;
                                else if (IS_A_NUMBER(args[optind])) {
                                        value = stol(args[optind],
                                                FAULT_ON_ERROR, NULL);
                                        if (value) {
                                                pc->flags |= SILENT;
						pc->flags &= ~SCROLL;
					}
                                        else
                                                pc->flags &= ~SILENT;
                                } else
					goto invalid_set_command;

				if (!(pc->flags & SILENT))
                                	fprintf(fp, "silent: off\n");

                        } else if (runtime && !(pc->flags & SILENT))
                               	fprintf(fp, "silent: off\n");
			
                } else if (STREQ(args[optind], "console")) {
			int assignment;

                        if (args[optind+1]) {
                                create_console_device(args[optind+1]);
				optind++;
				assignment = optind;
			} else
				assignment = 0;

			if (runtime) {
				fprintf(fp, "console: ");
				if (pc->console)
					fprintf(fp, "%s\n", pc->console);
				else {
					if (assignment)
						fprintf(fp, 
					            "assignment to %s failed\n",
						    	args[assignment]);
					else
						fprintf(fp, "not set\n");
				}		
			}

		} else if (STREQ(args[optind], "core")) {
			if (pc->flags & DROP_CORE)
				pc->flags &= ~DROP_CORE;
			else
				pc->flags |= DROP_CORE;
		
			fprintf(fp, "%s on call to error().\n",
				pc->flags & DROP_CORE ? 
				"Drop core" : "Do NOT drop core");

                } else if (STREQ(args[optind], "radix")) {
                       if (args[optind+1]) {
                                optind++;
                                if (STREQ(args[optind], "10") ||
				    STRNEQ(args[optind], "dec") ||
				    STRNEQ(args[optind], "ten")) 
					pc->output_radix = 10;
                                else if (STREQ(args[optind], "16") ||
			            STRNEQ(args[optind], "hex") ||
				    STRNEQ(args[optind], "six")) 
					pc->output_radix = 16;
				else 
					goto invalid_set_command;
			} 

                        if (runtime) {
				sprintf(buf, "set output-radix %d",
					pc->output_radix);
                                gdb_pass_through(buf, NULL, GNU_FROM_TTY_OFF);
                        	fprintf(fp, "output radix: %d (%s)\n",
					pc->output_radix, 
					pc->output_radix == 10 ? 
					"decimal" : "hex");
			}

                } else if (STREQ(args[optind], "hex")) {
			pc->output_radix = 16;
			if (runtime) {
				gdb_pass_through("set output-radix 16", 
					NULL, GNU_FROM_TTY_OFF);
				fprintf(fp, "output radix: 16 (hex)\n");
			}

                } else if (STREQ(args[optind], "dec")) {
			pc->output_radix = 10;
			if (runtime) {
                                gdb_pass_through("set output-radix 10", 
                                        NULL, GNU_FROM_TTY_OFF);
				fprintf(fp, "output radix: 10 (decimal)\n");
			}

                } else if (STREQ(args[optind], "vi")) {
			if (runtime)
				error(FATAL, 
		               "cannot change %s editing mode during runtime\n",
				    	pc->editing_mode); 
			else
				pc->editing_mode = "vi";

                } else if (STREQ(args[optind], "emacs")) {
			if (runtime)
				error(FATAL, 
		               "cannot change %s editing mode during runtime\n",
					pc->editing_mode);
			else
				pc->editing_mode = "emacs";

                } else if (STREQ(args[optind], "print_max")) {
			optind++;
			if (args[optind]) {
				if (decimal(args[optind], 0))
					print_max = atoi(args[optind]);
				else if (hexadecimal(args[optind], 0))
					print_max = (unsigned int)
					    htol(args[optind], 
						FAULT_ON_ERROR, NULL);
				else
					goto invalid_set_command;

			}
			fprintf(fp, "print_max: %d\n", print_max);

                } else if (STREQ(args[optind], "dumpfile")) {
			optind++;
                        if (!runtime && args[optind]) {
				pc->flags &= ~(LKCD|MCLXCD|S390D|S390XD);
				if (is_lkcd_compressed_dump(args[optind])) 
                               		pc->flags |= LKCD;
                        	else if (is_mclx_compressed_dump(args[optind])) 
                                	pc->flags |= MCLXCD;
                        	else 
                                	error(FATAL, 
					    "%s: not a compressed dumpfile\n",
                                        	args[optind]);
				if ((pc->dumpfile = (char *)
				    malloc(strlen(args[optind])+1)) == NULL) {
					error(INFO, 
				 "cannot malloc memory for dumpfile: %s: %s\n",
						args[optind], strerror(errno));
				} else 
					strcpy(pc->dumpfile, args[optind]);
					
			}

                } else if (STREQ(args[optind], "namelist")) {
			optind++;
                        if (!runtime && args[optind]) {
                		if (!is_elf_file(args[optind])) 
                                	error(FATAL, 
			       "%s: not a kernel namelist (from .%src file)\n",
                                        	args[optind],
						pc->program_name);
                                if ((pc->namelist = (char *)
                                    malloc(strlen(args[optind])+1)) == NULL) {
                                        error(INFO,
                                  "cannot malloc memory for namelist: %s: %s\n",
                                                args[optind], strerror(errno));
                                } else
                                        strcpy(pc->namelist, args[optind]);
			}

                } else if (STREQ(args[optind], "free")) {

			fprintf(fp, "%d pages freed\n",
				dumpfile_memory(DUMPFILE_FREE_MEM));

		} else if (runtime) {
			ulong pid, task;

	                switch (str_to_context(args[optind], &value, &tc))
	                {
	                case STR_PID:
                                pid = value;
                                task = NO_TASK;
                        	if (set_context(task, pid))
                                	show_context(CURRENT_CONTEXT(),
						0, FALSE);
	                        break;
	
	                case STR_TASK:
                                task = value;
                                pid = NO_PID;
                                if (set_context(task, pid))
                                        show_context(CURRENT_CONTEXT(), 
                                                0, FALSE);
	                        break;
	
	                case STR_INVALID:
	                        error(INFO, "invalid task or pid value: %s\n",
	                                args[optind]);
	                        break;
	                }
		}
		optind++;
	}

	return;

invalid_set_command:

	sprintf(buf, "invalid command");
	if (!runtime)
		sprintf(&buf[strlen(buf)], " in .%src file", pc->program_name);
	strcat(buf, ": ");
	for (i = 0; i < argcnt; i++)
		sprintf(&buf[strlen(buf)], "%s ", args[i]);
	strcat(buf, "\n");
	error(runtime ? FATAL : INFO, buf);
}


/*
 *  Evaluate an expression, which can consist of a single symbol, single value,
 *  or an expression consisting of two values and an operator.  If the 
 *  expression contains redirection characters, the whole expression must
 *  be enclosed with parentheses.  The result is printed in decimal, hex,
 *  octal and binary.  Input number values can only be hex or decimal, with
 *  a bias towards decimal (use 0x when necessary).
 */
void 
cmd_eval(void)
{
	int expression, flags;
	int bitflag, longlongflag;
	struct number_option nopt;
	char buf1[BUFSIZE];

	/*
	 *  getopt() is not used to avoid confusion with minus sign.
	 */
	optind = 1;
	bitflag = 0;
	longlongflag = 0;

	if (STREQ(args[optind], "-lb") || STREQ(args[optind], "-bl")) {
		longlongflag++;
		bitflag++;
		optind++;
	} else if (STREQ(args[optind], "-l")) {
		longlongflag++;
		optind++;
		if (STREQ(args[optind], "-b") && args[optind+1]) { 
			optind++;
			bitflag++;
		}
	} else if (STREQ(args[optind], "-b")) { 
		if (STREQ(args[optind+1], "-l")) { 
			if (args[optind+2]) {
				bitflag++;
				longlongflag++;
				optind += 2;
			} else
                		cmd_usage(pc->curcmd, SYNOPSIS);
		} else if (args[optind+1]) {
			bitflag++;
			optind++;
		}
	}

        if (!args[optind])
                cmd_usage(pc->curcmd, SYNOPSIS);

	if (BITS64())
		longlongflag = 0;
	flags = longlongflag ? (LONG_LONG|RETURN_ON_ERROR) : FAULT_ON_ERROR;

	expression = TRUE;
	BZERO(buf1, BUFSIZE);
	buf1[0] = '(';

        while (args[optind]) {
                if (*args[optind] == '(') {
			if (eval_common(args[optind], flags, NULL, &nopt))
				print_number(&nopt, bitflag, longlongflag);
			else
				error(FATAL, "invalid expression: %s\n", 
					args[optind]);
			return;
                }
		else {
			expression = FALSE;
			strcat(buf1, args[optind]);
			strcat(buf1, " ");
		}
		optind++;
        }
	clean_line(buf1);
	strcat(buf1, ")");

	if (eval_common(buf1, flags, NULL, &nopt))
        	print_number(&nopt, bitflag, longlongflag);
	else
		error(FATAL, "invalid expression: %s\n", buf1);
}

/*
 *  Pre-check a string for eval-worthiness.  This allows callers to avoid
 *  having to encompass a non-whitespace expression with parentheses.
 *  Note that the data being evaluated is not error-checked here, but
 *  rather that it exists in the proper format.
 */
int
can_eval(char *s)
{
	char *op;
	char *element1, *element2;
	char work[BUFSIZE];

	/*
	 *  If we've got a () pair containing any sort of stuff in between,
	 *  then presume it's eval-able.  It might contain crap, but it 
	 *  should be sent to eval() regardless.
	 */
	if ((FIRSTCHAR(s) == '(') &&
	    (count_chars(s, '(') == 1) &&
	    (count_chars(s, ')') == 1) &&
	    (strlen(s) > 2) &&
	    (LASTCHAR(s) == ')'))
		return TRUE;

	/*
	 *  If the string contains any of the operators except the shifters,
         *  and has any kind of data on either side, it's also eval-able.
	 */
	strcpy(work, s);

        if (!(op = strpbrk(work, "><+-&|*/%^")))
		return FALSE; 

        element1 = &work[0];
        *op = NULLCHAR;
	element2 = op+1;

	if (!strlen(element1) || !strlen(element2))
		return FALSE;

	return TRUE;
}

/*
 *  Evaluate an expression involving two values and an operator.  
 */
#define OP_ADD   (1)
#define OP_SUB   (2)
#define OP_AND   (3)
#define OP_OR    (4)
#define OP_MUL   (5)
#define OP_DIV   (6)
#define OP_MOD   (7)
#define OP_SL    (8)
#define OP_SR    (9)
#define OP_EXOR (10)

ulong
eval(char *s, int flags, int *errptr)
{
	struct number_option nopt;

	if (eval_common(s, flags, errptr, &nopt)) {
		return(nopt.num);
	} else {
	        switch (flags & (FAULT_ON_ERROR|RETURN_ON_ERROR))
	        {
	        case FAULT_ON_ERROR:
	                error(FATAL, "invalid expression: %s\n", s);
	
	        case RETURN_ON_ERROR:
	                error(INFO, "invalid expression: %s\n", s);
	                if (errptr)
	                        *errptr = TRUE;
	                break;
	        }
        	return UNUSED;
	}
}

ulonglong
evall(char *s, int flags, int *errptr)
{
        struct number_option nopt;

        if (eval_common(s, flags, errptr, &nopt)) {
                return(nopt.ll_num);
        } else {
                switch (flags & (FAULT_ON_ERROR|RETURN_ON_ERROR))
                {
                case FAULT_ON_ERROR:
                        error(FATAL, "invalid expression: %s\n", s);

                case RETURN_ON_ERROR:
                        error(INFO, "invalid expression: %s\n", s);
                        if (errptr)
                                *errptr = TRUE;
                        break;
                }
                return UNUSED;
        }
}


int
eval_common(char *s, int flags, int *errptr, struct number_option *np)
{
	char *p1, *p2;
        char *op, opcode;
	ulong value1;
	ulong value2;
	ulonglong ll_value1;
	ulonglong ll_value2;
	char work[BUFSIZE];
	char *element1;
	char *element2;
	struct syment *sp;

	if (strstr(s, "(") || strstr(s, ")")) {
		p1 = s;
		if (*p1 != '(')
			goto malformed;
		if (LASTCHAR(s) != ')')
			goto malformed;
		p2 = &LASTCHAR(s);
		if (strstr(s, ")") != p2)
			goto malformed;
	
		strcpy(work, p1+1);
		LASTCHAR(work) = NULLCHAR;
	
		if (strstr(work, "(") || strstr(work, ")")) 
			goto malformed;
	} else
		strcpy(work, s);

        if (work[0] == '-') {
                shift_string_right(work, 1);
                work[0] = '0';
        }

        if (!(op = strpbrk(work, "><+-&|*/%^"))) {
		if (calculate(work, &value1, &ll_value1, 
		    flags & (HEX_BIAS|LONG_LONG))) { 
			if (flags & LONG_LONG) {
				np->ll_num = ll_value1;
				return TRUE;
			} else {
				np->num = value1;
				return TRUE;
			}
		}
               	goto malformed;
        }

	switch (*op)
        {
        case '+': 
		opcode = OP_ADD; 
		break;

        case '-': 
		opcode = OP_SUB; 
		break;

        case '&': 
		opcode = OP_AND; 
		break;

        case '|': 
		opcode = OP_OR; 
		break;

        case '*': 
		opcode = OP_MUL; 
		break;

        case '%': 
		opcode = OP_MOD; 
		break;

        case '/': 
		opcode = OP_DIV; 
		break;

	case '<': 
		if (*(op+1) != '<')
			goto malformed;
		opcode = OP_SL;
	        break;

	case '>': 
                if (*(op+1) != '>')
                        goto malformed;
                opcode = OP_SR;
	        break;

	case '^':
		opcode = OP_EXOR;
		break;
	}

        element1 = &work[0];
	*op = NULLCHAR;
	if ((opcode == OP_SL) || (opcode == OP_SR)) {
		*(op+1) = NULLCHAR;
		element2 = op+2;
	} else 
		element2 = op+1;

        if (strlen(clean_line(element1)) == 0)
                goto malformed;

        if (strlen(clean_line(element2)) == 0)
                goto malformed;

	if ((sp = symbol_search(element1)))
                value1 = sp->value;
	else {
		if (!calculate(element1, &value1, &ll_value1, 
		    flags & (HEX_BIAS|LONG_LONG)))
			goto malformed;
	}

        if ((sp = symbol_search(element2)))
                value2 = sp->value;
        else if (!calculate(element2, &value2, &ll_value2, 
	    	flags & (HEX_BIAS|LONG_LONG)))
		goto malformed;

	if (flags & LONG_LONG) {
                switch (opcode)
                {
                case OP_ADD:
                        np->ll_num = (ll_value1 + ll_value2);
			break;           
                case OP_SUB:
                        np->ll_num = (ll_value1 - ll_value2);
			break;           
                case OP_AND:
                        np->ll_num = (ll_value1 & ll_value2);
			break;           
                case OP_OR:
                        np->ll_num = (ll_value1 | ll_value2);
			break;           
                case OP_MUL:
                        np->ll_num = (ll_value1 * ll_value2);
			break;           
                case OP_DIV:
                        np->ll_num = (ll_value1 / ll_value2);
			break;           
                case OP_MOD:
                        np->ll_num = (ll_value1 % ll_value2);
			break;           
                case OP_SL:
                        np->ll_num = (ll_value1 << ll_value2);
			break;           
                case OP_SR:
                        np->ll_num = (ll_value1 >> ll_value2);
			break;           
                case OP_EXOR:
                        np->ll_num = (ll_value1 ^ ll_value2);
			break;
                }
	} else {
		switch (opcode)
		{
		case OP_ADD: 
			np->num = (value1 + value2);
			break;
		case OP_SUB:
			np->num = (value1 - value2);
			break;
		case OP_AND: 
			np->num = (value1 & value2);
			break;
		case OP_OR:  
			np->num = (value1 | value2);
			break;
		case OP_MUL: 
			np->num = (value1 * value2);
			break;
		case OP_DIV: 
			np->num = (value1 / value2);
			break;
		case OP_MOD: 
			np->num = (value1 % value2);
			break;
		case OP_SL:  
			np->num = (value1 << value2);
			break;
		case OP_SR:  
			np->num = (value1 >> value2);
			break;
		case OP_EXOR:
			np->num = (value1 ^ value2);
			break;
		}
	}

	return TRUE;

malformed:
	return FALSE;
}


/*
 *  Take string containing a number, and possibly a multiplier, and calculate
 *  its real value.  The allowable multipliers are k, K, m, M, g and G, for
 *  kilobytes, megabytes and gigabytes.
 */
static int
calculate(char *s, ulong *value, ulonglong *llvalue, ulong flags)
{
	ulong factor, bias;
	int errflag;
	int ones_complement;
	ulong localval;
	ulonglong ll_localval;
	struct syment *sp;

	bias = flags & HEX_BIAS;

	if (*s == '~') {
		ones_complement = TRUE;
		s++;
	} else
		ones_complement = FALSE;

        if ((sp = symbol_search(s))) {
		if (flags & LONG_LONG) {
			*llvalue = (ulonglong)sp->value;
			if (ones_complement)
                		*llvalue = ~(*llvalue);
		} else 
                	*value = ones_complement ? ~(sp->value) : sp->value;
		return TRUE;
	}

	factor = 1;
	errflag = 0;

        switch (LASTCHAR(s))
        {
        case 'k':
        case 'K':
                LASTCHAR(s) = NULLCHAR;
                if (IS_A_NUMBER(s))
                        factor = 1024;
		else
			return FALSE;
                break;

        case 'm':
        case 'M':
                LASTCHAR(s) = NULLCHAR;
                if (IS_A_NUMBER(s))
                        factor = (1024*1024);
		else 
			return FALSE;
                break;

        case 'g':
        case 'G':
                LASTCHAR(s) = NULLCHAR;
                if (IS_A_NUMBER(s))
                        factor = (1024*1024*1024);
		else
			return FALSE;
                break;

        default:
		if (!IS_A_NUMBER(s))
			return FALSE;
		break;
        }

	if (flags & LONG_LONG) {
                ll_localval = stoll(s, RETURN_ON_ERROR|bias, &errflag);
                if (errflag)
                        return FALSE;

                if (ones_complement)
                        *llvalue = ~(ll_localval * factor);
                else
                        *llvalue = ll_localval * factor;
	} else {
		localval = stol(s, RETURN_ON_ERROR|bias, &errflag);
		if (errflag)
			return FALSE;

		if (ones_complement)
			*value = ~(localval * factor);
		else
			*value = localval * factor;
	}

	return TRUE;
}


/*
 *  Print a 32-bit or 64-bit number in hexadecimal, decimal, octal and binary,
 *  also showing the bits set if appropriate.
 *  
 */
static void
print_number(struct number_option *np, int bitflag, int longlongflag)
{
	int i;
	ulong hibit;
	ulonglong ll_hibit;
        int ccnt;
        ulong mask;
	ulonglong ll_mask;
        char *hdr = "   bits set: ";
        char buf[BUFSIZE];
        int hdrlen;

	if (longlongflag) {
                ll_hibit = (ulonglong)(1) << ((sizeof(long long)*8)-1);
                
                fprintf(fp, "hexadecimal: %llx  ", np->ll_num);
                if (np->ll_num >= KILOBYTES(1)) {
                        if ((np->ll_num % GIGABYTES(1)) == 0)
                                fprintf(fp, "(%lldGB)", 
					np->ll_num / GIGABYTES(1));
                        else if ((np->ll_num % MEGABYTES(1)) == 0)
                                fprintf(fp, "(%lldMB)", 
					np->ll_num / MEGABYTES(1));
                        else if ((np->ll_num % KILOBYTES(1)) == 0)
                                fprintf(fp, "(%lldKB)",
					 np->ll_num / KILOBYTES(1));
                }
                fprintf(fp, "\n");

                fprintf(fp, "    decimal: %llu  ", np->ll_num);
                if ((long long)np->ll_num < 0)
                        fprintf(fp, "(%lld)\n", (long long)np->ll_num);
                else
                        fprintf(fp, "\n");
                fprintf(fp, "      octal: %llo\n", np->ll_num);
                fprintf(fp, "     binary: ");
                for(i = 0, ll_mask = np->ll_num; i < (sizeof(long long)*8); 
		    i++, ll_mask <<= 1)
                        if (ll_mask & ll_hibit)
                                fprintf(fp, "1");
                        else
                                fprintf(fp, "0");
                fprintf(fp,"\n");
	} else {
		hibit = (ulong)(1) << ((sizeof(long)*8)-1);
	
	        fprintf(fp, "hexadecimal: %lx  ", np->num);
	        if (np->num >= KILOBYTES(1)) {
	                if ((np->num % GIGABYTES(1)) == 0)
	                        fprintf(fp, "(%ldGB)", np->num / GIGABYTES(1));
	                else if ((np->num % MEGABYTES(1)) == 0)
	                        fprintf(fp, "(%ldMB)", np->num / MEGABYTES(1));
	                else if ((np->num % KILOBYTES(1)) == 0)
	                        fprintf(fp, "(%ldKB)", np->num / KILOBYTES(1));
	        }
	        fprintf(fp, "\n");
	
	        fprintf(fp, "    decimal: %lu  ", np->num);
		if ((long)np->num < 0)
	                fprintf(fp, "(%ld)\n", (long)np->num);
	        else
	                fprintf(fp, "\n");
	        fprintf(fp, "      octal: %lo\n", np->num);
	        fprintf(fp, "     binary: ");
	        for(i = 0, mask = np->num; i < (sizeof(long)*8); 
		    i++, mask <<= 1)
	                if (mask & hibit)
	                        fprintf(fp, "1");
	                else
	                        fprintf(fp, "0");
	        fprintf(fp,"\n");
	}

	if (!bitflag)
		return;

	hdrlen = strlen(hdr);
	ccnt = hdrlen;
	fprintf(fp, "%s", hdr);

	if (longlongflag) {
	        for (i = 63; i >= 0; i--) {
	                ll_mask = (ulonglong)(1) << i;
	                if (np->ll_num & ll_mask) {
	                        sprintf(buf, "%d ", i);
	                        fprintf(fp, "%s", buf);
	                        ccnt += strlen(buf);
	                        if (ccnt >= 77) {
	                                fprintf(fp, "\n");
	                                INDENT(strlen(hdr));
	                                ccnt = hdrlen;
	                        }
	                }
	        }
	} else {
	        for (i = BITS()-1; i >= 0; i--) {
	                mask = (ulong)(1) << i;
	                if (np->num & mask) {
	                        sprintf(buf, "%d ", i);
	                        fprintf(fp, "%s", buf);
	                        ccnt += strlen(buf);
	                        if (ccnt >= 77) {
	                                fprintf(fp, "\n");
	                                INDENT(strlen(hdr));
	                                ccnt = hdrlen;
	                        }
	                }
	        }
	}
        fprintf(fp, "\n");
}


/*
 *  Display the contents of a linked list.  Minimum requirements are a starting
 *  address, typically of a structure which contains the "next" list entry at 
 *  some offset into the structure.  The default offset is zero bytes, and need
 *  not be entered if that's the case.  Otherwise a number argument that's not 
 *  a kernel *  virtual address will be understood to be the offset.  
 *  Alternatively the offset may be entered in "struct.member" format.  Each 
 *  item in the list is dumped, and the list will be considered terminated upon
 *  encountering a "next" value that is:
 *
 *     a NULL pointer. 
 *     a pointer to the starting address. 
 *     a pointer to the entry pointed to by the starting address. 
 *     a pointer to the structure itself.
 *     a pointer to the value specified with the "-e ending_addr" option.
 *
 *  If the structures are linked using list_head structures, the -h or -H 
 *  options must be used.  In that case, the "start" address is:
 *  a pointer to  the embedded list_head structure (-h), or a pointer to a 
 *  LIST_HEAD() structure (-H).
 *
 *  Given that the contents of the structures containing the next pointers
 *  often contain useful data, the "-s structname" also prints each structure
 *  in the list. 
 *
 *  By default, the list members are hashed to guard against duplicate entries
 *  causing the list to wrap back upon itself.
 *
 *  WARNING: There's an inordinate amount of work parsing arguments below
 *  in order to maintain backwards compatibility re: not having to use -o,
 *  which gets sticky with zero-based kernel virtual address space.
 */

void
cmd_list(void)
{
	int c;
	struct list_data list_data, *ld;
	struct datatype_member struct_member, *sm;
	struct syment *sp;
	ulong value; 

	sm = &struct_member;
	ld = &list_data;
	BZERO(ld, sizeof(struct list_data));

        while ((c = getopt(argcnt, args, "Hhs:e:o:")) != EOF) {
                switch(c)
		{
		case 'H':
			ld->flags |= LIST_HEAD_FORMAT;
			ld->flags |= LIST_HEAD_POINTER;
			break;

		case 'h':
			ld->flags |= LIST_HEAD_FORMAT;
			break;

		case 's':
			ld->structname = optarg;
			break;

		case 'o':
			if (ld->flags & LIST_OFFSET_ENTERED) 
                               error(FATAL,
                                "offset value %d (0x%lx) already entered\n",
                                        ld->member_offset, ld->member_offset);
			else if (IS_A_NUMBER(optarg)) 
				ld->member_offset = stol(optarg, 
					FAULT_ON_ERROR, NULL);
			else if (arg_to_datatype(optarg, 
				sm, RETURN_ON_ERROR) > 1) 
				ld->member_offset = sm->member_offset;
			else
				error(FATAL, "invalid -o argument: %s\n",
					optarg);

			ld->flags |= LIST_OFFSET_ENTERED; 
			break;

		case 'e':
			ld->end = htol(optarg, FAULT_ON_ERROR, NULL);
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (args[optind] && args[optind+1] && args[optind+2]) {
		error(INFO, "too many arguments\n");
		cmd_usage(pc->curcmd, SYNOPSIS);
	}

	while (args[optind]) {
		if (strstr(args[optind], ".") &&
		    arg_to_datatype(args[optind], sm, RETURN_ON_ERROR) > 1) {
			if (ld->flags & LIST_OFFSET_ENTERED)
				error(FATAL, 
			           "offset value %ld (0x%lx) already entered\n",
					ld->member_offset, ld->member_offset);
			ld->member_offset = sm->member_offset;
			ld->flags |= LIST_OFFSET_ENTERED;
		} else {
			/* 
			 *  Do an inordinate amount of work to avoid -o...
			 *
			 *  OK, if it's a symbol, then it has to be a start.
			 */
			if ((sp = symbol_search(args[optind]))) {
				if (ld->flags & LIST_START_ENTERED) 
                                        error(FATAL,
                                            "list start already entered\n");
                                ld->start = sp->value;
                                ld->flags |= LIST_START_ENTERED;
				goto next_arg;
			}

			/*
			 *  If it's not a symbol nor a number, bail out.
			 */
			if (!IS_A_NUMBER(args[optind]))	
				error(FATAL, "invalid argument: %s\n",
                                	args[optind]);

			/*
			 *  If the start is known, it's got to be an offset.
			 */
                        if (ld->flags & LIST_START_ENTERED) {
                                value = stol(args[optind], FAULT_ON_ERROR,
                                        NULL);
                                ld->member_offset = value;
                                ld->flags |= LIST_OFFSET_ENTERED;
                                break;
                        }

			/*
			 *  If the offset is known, or there's no subsequent
                         *  argument, then it's got to be a start.
			 */
			if ((ld->flags & LIST_OFFSET_ENTERED) ||
			    !args[optind+1]) {
				value = htol(args[optind], FAULT_ON_ERROR, 
					NULL);
				if (!IS_KVADDR(value))
					error(FATAL, 
				        "invalid kernel virtual address: %s\n",
						args[optind]);
                                ld->start = value;
                                ld->flags |= LIST_START_ENTERED;
				break;
			}

			/*
			 *  Neither start nor offset has been entered, and
			 *  it's a number.  Look ahead to the next argument.
			 *  If it's a symbol, then this must be an offset.
			 */
			if ((sp = symbol_search(args[optind+1]))) {
                                value = stol(args[optind], FAULT_ON_ERROR,
                                        NULL);
                                ld->member_offset = value;
                                ld->flags |= LIST_OFFSET_ENTERED;
                                goto next_arg;
			} else if (!IS_A_NUMBER(args[optind+1]) &&
				!strstr(args[optind+1], "."))
				error(FATAL, "symbol not found: %s\n",
                                        args[optind+1]);
			/*
			 *  Crunch time.  We've got two numbers.  If they're
			 *  both ambigous we must have zero-based kernel 
			 *  virtual address space.
			 */
			if (COMMON_VADDR_SPACE() &&
			    AMBIGUOUS_NUMBER(args[optind]) &&
			    AMBIGUOUS_NUMBER(args[optind+1])) {
				error(INFO, 
                     "ambiguous arguments: \"%s\" and \"%s\": -o is required\n",
					args[optind], args[optind+1]);
				cmd_usage(pc->curcmd, SYNOPSIS);
			}

			if (hexadecimal_only(args[optind], 0)) {
				value = htol(args[optind], FAULT_ON_ERROR, 
					NULL);
                                if (IS_KVADDR(value)) {
                                	ld->start = value;
                                	ld->flags |= LIST_START_ENTERED;
					goto next_arg;
				}
			} 
			value = stol(args[optind], FAULT_ON_ERROR, NULL);
                        ld->member_offset = value;
                        ld->flags |= LIST_OFFSET_ENTERED;
		}
next_arg:
		optind++;
	}

	if (!(ld->flags & LIST_START_ENTERED)) {
		error(INFO, "starting address required\n");
		cmd_usage(pc->curcmd, SYNOPSIS);
	}

	if (ld->flags & LIST_HEAD_FORMAT) {
		ld->list_head_offset = ld->member_offset;
		ld->member_offset = 0;
		if (ld->flags & LIST_HEAD_POINTER) {
			if (!ld->end)
				ld->end = ld->start;
        		readmem(ld->start, KVADDR, &ld->start, sizeof(void *),
				"LIST_HEAD contents", FAULT_ON_ERROR);
			if (ld->start == ld->end) {
				fprintf(fp, "(empty)\n");
				return;
			}
		}
	}

	ld->flags &= ~(LIST_OFFSET_ENTERED|LIST_START_ENTERED);
	ld->flags |= VERBOSE;

	hq_open();
	c = do_list(ld);
	hq_close();
}

/*
 *  Does the work for cmd_list() and any other function that requires the
 *  contents of a linked list.  See cmd_list description above for details.
 */
int
do_list(struct list_data *ld)
{
	ulong next, last, first;
	ulong searchfor;
	int count;

	count = 0;
	searchfor = ld->searchfor;
	ld->searchfor = 0;

	next = ld->start;

	readmem(next + ld->member_offset, KVADDR, &first, sizeof(void *),
        	"first list entry", FAULT_ON_ERROR);

	if (ld->header)
		fprintf(fp, "%s", ld->header);

	while (1) {
		if (ld->flags & VERBOSE) {
			fprintf(fp, "%lx\n", next - ld->list_head_offset);

			if (ld->structname) {
				switch (count_chars(ld->structname, '.'))
				{
				case 0:
					dump_struct(ld->structname, 
						next - ld->list_head_offset, 0);
					break;
				case 1:
					dump_struct_member(ld->structname, 
						next - ld->list_head_offset, 0);
					break;
				default:
					error(FATAL, 
					    "invalid structure reference: %s\n",
						ld->structname);
				}
			}
		}

                if (next && !hq_enter(next - ld->list_head_offset)) {
			if (ld->flags & RETURN_ON_DUPLICATE) {
                        	error(INFO, "\nduplicate list entry: %lx\n", 
					next);
				return -1;
			}
                        error(FATAL, "\nduplicate list entry: %lx\n", next);
		}

		if ((searchfor == next) || 
		    (searchfor == (next - ld->list_head_offset)))
			ld->searchfor = searchfor;

		count++;
                last = next;

                readmem(next + ld->member_offset, KVADDR, &next, sizeof(void *),
                        "list entry", FAULT_ON_ERROR);

		if (next == 0) {
			if (MCLXDEBUG(1))
				console("do_list end: next:%lx\n", next);
			break;
		}

		if (next == ld->end) {
			if (MCLXDEBUG(1))
				console("do_list end: next:%lx == end:%lx\n", 
					next, ld->end);
			break;
		}

		if (next == ld->start) {
			if (MCLXDEBUG(1))
				console("do_list end: next:%lx == start:%lx\n", 
					next, ld->start);
			break;
		}

		if (next == last) {
			if (MCLXDEBUG(1))
				console("do_list end: next:%lx == last:%lx\n", 
					next, last);
			break;
		}

		if ((next == first) && (count != 1)) {
			if (MCLXDEBUG(1))
		      console("do_list end: next:%lx == first:%lx (count %d)\n",
				next, last, count);
			break;
		}
	}

	if (MCLXDEBUG(1))
		console("do_list count: %d\n", count);

	return count;
}

/*
 *  The next set of functions are a general purpose hashing tool used to
 *  identify duplicate entries in a set of passed-in data, and if found, 
 *  to fail the entry attempt.  When a command wishes to verify a list
 *  of contains unique values, the hash functions should be used in the
 *  following order:
 *
 *      hq_open()
 *      hq_enter(value_1)
 *      hq_enter(value_2)
 *      ...
 *      hq_enter(value_n)
 *      hq_close()
 *
 *  If a duplicate entry is passed in between the hq_open()/hq_close() pair,
 *  hq_enter() will return FALSE;
 */

#define HASH_QUEUE_NONE       (0x1)
#define HASH_QUEUE_FULL       (0x2)
#define HASH_QUEUE_OPEN       (0x4)
#define HASH_QUEUE_CLOSED     (0x8)

#define HQ_ENTRY_CHUNK   (1024)
#define NR_HASH_QUEUES   (HQ_ENTRY_CHUNK/8)
#define HQ_SHIFT         (machdep->pageshift)
#define HQ_INDEX(X)      (((X) >> HQ_SHIFT) % NR_HASH_QUEUES)

struct hq_entry {
        int next;
	int order;
        ulong value;
};

struct hq_head {
	int next;
	int qcnt;
};

struct hash_table {
	ulong flags;
	struct hq_head queue_heads[NR_HASH_QUEUES];
	struct hq_entry *memptr;
	long count;
	long index;
	int reallocs;
} hash_table = { 0 };

/*
 *  For starters, allocate a hash table containing HQ_ENTRY_CHUNK entries.
 *  If necessary during runtime, it will be increased in size.
 */
void
hq_init(void)
{
	struct hash_table *ht;

	ht = &hash_table;

        if ((ht->memptr = (struct hq_entry *)malloc(HQ_ENTRY_CHUNK * 
	    sizeof(struct hq_entry))) == NULL) {
		error(INFO, "cannot malloc memory for hash queues: %s\n",
			strerror(errno));
		ht->flags = HASH_QUEUE_NONE;
		pc->flags &= ~HASH;
		return;
	}
        
	BZERO(ht->memptr, HQ_ENTRY_CHUNK * sizeof(struct hq_entry));
	ht->count = HQ_ENTRY_CHUNK;
	ht->index = 0;
}

/*
 *  Get a free hash queue entry.  If there's no more available, realloc()
 *  a new chunk of memory with another HQ_ENTRY_CHUNK entries stuck on the end.
 */
static long
alloc_hq_entry(void)
{
	struct hash_table *ht;
	struct hq_entry *new, *end_of_old;

	ht = &hash_table;

	if (++ht->index == ht->count) {
                if (!(new = (void *)realloc((void *)ht->memptr,
		    (ht->count+HQ_ENTRY_CHUNK) * sizeof(struct hq_entry)))) {
			error(INFO, 
			    "cannot realloc memory for hash queues: %s\n",
				strerror(errno));
			ht->flags |= HASH_QUEUE_FULL;
			return(-1);
		}
		ht->reallocs++;
		ht->memptr = new;
		end_of_old = ht->memptr + ht->count;
		BZERO(end_of_old, HQ_ENTRY_CHUNK * sizeof(struct hq_entry));
		ht->count += HQ_ENTRY_CHUNK;
	}

	return(ht->index);
}

/*
 *  Restore the hash queue to its state before the duplicate entry 
 *  was attempted.
 */ 
static void
dealloc_hq_entry(struct hq_entry *entry)
{
        struct hash_table *ht;
        long hqi;

        ht = &hash_table;
	hqi = HQ_INDEX(entry->value);

	ht->index--;

	BZERO(entry, sizeof(struct hq_entry));
	ht->queue_heads[hqi].qcnt--;
}

/*
 *  Initialize the hash table for a hashing session.
 */
int
hq_open(void)
{
	struct hash_table *ht;

	if (!(pc->flags & HASH))
		return FALSE;

	ht = &hash_table;
	if (ht->flags & HASH_QUEUE_NONE)
		return FALSE;

	ht->flags &= ~(HASH_QUEUE_FULL|HASH_QUEUE_CLOSED);
	BZERO(ht->queue_heads, sizeof(struct hq_head) * NR_HASH_QUEUES);
	BZERO(ht->memptr, ht->count * sizeof(struct hq_entry));
	ht->index = 0;

	ht->flags |= HASH_QUEUE_OPEN;

	return TRUE;
}

/*
 *  Close the hash table, returning the number of items hashed in this session.
 */
int
hq_close(void)
{
	struct hash_table *ht;

	ht = &hash_table;

	ht->flags &= ~(HASH_QUEUE_OPEN);
	ht->flags |= HASH_QUEUE_CLOSED;

	if (!(pc->flags & HASH))
		return(0);

	if (ht->flags & HASH_QUEUE_NONE)
		return(0);

	ht->flags &= ~HASH_QUEUE_FULL;

	return(ht->index);
}

char *corrupt_hq = "corrupt hash queue entry: value: %lx next: %d order: %d\n";

/*
 *  For a given value, allocate a hash queue entry and hash it into the 
 *  open hash table.  If a duplicate entry is found, return FALSE; for all 
 *  other possibilities return TRUE.  Note that it's up to the user to deal 
 *  with failure.
 */
int
hq_enter(ulong value)
{
	struct hash_table *ht;
	struct hq_entry *entry;
	struct hq_entry *list_entry;
	long hqi;
	long index;

	if (!(pc->flags & HASH))
		return TRUE;

	ht = &hash_table;

	if (ht->flags & (HASH_QUEUE_NONE|HASH_QUEUE_FULL))
		return TRUE;

	if (!(ht->flags & HASH_QUEUE_OPEN))
		return TRUE;

	if ((index = alloc_hq_entry()) < 0) 
		return TRUE;

	entry = ht->memptr + index;
	if (entry->next || entry->value || entry->order) {
		error(INFO, corrupt_hq,
			entry->value, entry->next, entry->order);
		ht->flags |= HASH_QUEUE_NONE;
		return TRUE;
	}

	entry->next = 0;
	entry->value = value;
	entry->order = index;

	hqi = HQ_INDEX(value);

	if (ht->queue_heads[hqi].next == 0) {
		ht->queue_heads[hqi].next = index;
		ht->queue_heads[hqi].qcnt = 1;
		return TRUE;
	} else
		ht->queue_heads[hqi].qcnt++;

	list_entry = ht->memptr + ht->queue_heads[hqi].next;

	while (TRUE) {
	        if (list_entry->value == entry->value) {
			dealloc_hq_entry(entry);
                	return FALSE;
		}

		if (list_entry->next >= ht->count) {
			error(INFO, corrupt_hq,
			    	list_entry->value, 
				list_entry->next,
				list_entry->order);
			ht->flags |= HASH_QUEUE_NONE;
			return TRUE;
		}

		if (list_entry->next == 0)
			break;

        	list_entry = ht->memptr + list_entry->next;
	}

	list_entry->next = index;

	return TRUE;
}

/*
 *  "hash -d" output
 */
void
dump_hash_table(int verbose)
{
	int i;
	struct hash_table *ht;
	struct hq_entry *list_entry;
	long elements;
	long queues_in_use;
	int others;
	uint minq, maxq; 

	ht = &hash_table;
	others = 0;

	fprintf(fp, "              flags: %lx (", ht->flags);
        if (ht->flags & HASH_QUEUE_NONE)
                fprintf(fp, "%sHASH_QUEUE_NONE", others++ ? "|" : "");
        if (ht->flags & HASH_QUEUE_OPEN)
                fprintf(fp, "%sHASH_QUEUE_OPEN", others++ ? "|" : "");
        if (ht->flags & HASH_QUEUE_CLOSED)
                fprintf(fp, "%sHASH_QUEUE_CLOSED", others++ ? "|" : "");
        if (ht->flags & HASH_QUEUE_FULL)
                fprintf(fp, "%sHASH_QUEUE_FULL", others++ ? "|" : "");
	fprintf(fp, ")\n");
	fprintf(fp, "   queue_heads[%d]: %lx\n", NR_HASH_QUEUES, 
		(ulong)ht->queue_heads);
	fprintf(fp, "             memptr: %lx\n", (ulong)ht->memptr);
	fprintf(fp, "              count: %ld  ", ht->count);
	if (ht->reallocs)
		fprintf(fp, "  (%d reallocs)", ht->reallocs);
	fprintf(fp, "\n");
	fprintf(fp, "              index: %ld\n", ht->index);

	queues_in_use = 0;
	minq = ~(0);
	maxq = 0;

	for (i = 0; i < NR_HASH_QUEUES; i++) {
               	if (ht->queue_heads[i].next == 0) {
			minq = 0;
                       	continue;
		}

		if (ht->queue_heads[i].qcnt < minq)
			minq = ht->queue_heads[i].qcnt;
		if (ht->queue_heads[i].qcnt > maxq)
			maxq = ht->queue_heads[i].qcnt;

               	queues_in_use++;
	}

	elements = 0;
	list_entry = ht->memptr;
        for (i = 0; i < ht->count; i++, list_entry++) {
	         if (!list_entry->order) {
	                if (list_entry->value || list_entry->next)
				goto corrupt_list_entry;
	                continue;
	         }
	
	         if (list_entry->next >= ht->count)
	                        goto corrupt_list_entry;

	         ++elements;
       	}

	if (elements != ht->index)
        	fprintf(fp, "     elements found: %ld (expected %ld)\n", 
			elements, ht->index);
        fprintf(fp, "      queues in use: %ld of %d\n", queues_in_use, 
		NR_HASH_QUEUES);
	fprintf(fp, " queue length range: %d to %d\n", minq, maxq);

	if (verbose) {
		if (!elements) {
        		fprintf(fp, "            entries: (none)\n");
			return;
		}

        	fprintf(fp, "            entries: ");

        	list_entry = ht->memptr;
	        for (i = 0; i < ht->count; i++, list_entry++) {
	                 if (list_entry->order)
	                        fprintf(fp, "%s%lx (%d)\n", 
					list_entry->order == 1 ?
					"" : "                     ",
	                                list_entry->value, list_entry->order);
	        }
	}
	return;

corrupt_list_entry:

        error(INFO, corrupt_hq,
        	list_entry->value, list_entry->next, list_entry->order);
        ht->flags |= HASH_QUEUE_NONE;
}

/*
 *  Retrieve the count of, and optionally stuff a pre-allocated array with,
 *  the current hash table entries.  The entries will be sorted according
 *  to the order in which they were entered, so from this point on, no
 *  further hq_enter() operations on this list will be allowed.  However, 
 *  multiple calls to retrieve_list are allowed because the second and 
 *  subsequent ones will go directly to where the non-zero (valid) entries 
 *  start in the potentially very large list_entry memory chunk.
 */
int
retrieve_list(ulong array[], int count)
{
        int i; 
        struct hash_table *ht;
        struct hq_entry *list_entry;
        int elements;

        ht = &hash_table;

	list_entry = ht->memptr;
	for (i = elements = 0; i < ht->count; i++, list_entry++) {
		if (!list_entry->order) {
			if (list_entry->value || list_entry->next)
				goto corrupt_list_entry;
			continue;
		}

                if (list_entry->next >= ht->count) 
			goto corrupt_list_entry;

		if (array) 
			array[elements] = list_entry->value; 

                if (++elements == count)
                       	break;
	}

	return elements;

corrupt_list_entry:

        error(INFO, corrupt_hq,
               list_entry->value, list_entry->next, list_entry->order);
        ht->flags |= HASH_QUEUE_NONE;
        return(-1);
}


/*
 *  K&R power function for integers
 */
long
power(long base, int exp)
{
	int i;
	long p;

	p = 1;
	for (i = 1; i <= exp; i++)
		p = p * base;

	return p;
}

/*
 *  Internal buffer allocation scheme to avoid inline malloc() calls and 
 *  resultant memory leaks due to aborted commands.  These buffers are
 *  for TEMPORARY use on a per-command basis.
 */

#define NUMBER_1K_BUFS  (10)
#define NUMBER_2K_BUFS  (10)
#define NUMBER_4K_BUFS  (0)
#define NUMBER_8K_BUFS  (10)
#define NUMBER_32K_BUFS (1)
#define NUMBER_SYM_BUFS (20)

#define SHARED_1K_BUF_FULL   (0x003ff)
#define SHARED_2K_BUF_FULL   (0x003ff)
#define SHARED_4K_BUF_FULL   (0x00000)
#define SHARED_8K_BUF_FULL   (0x003ff)
#define SHARED_32K_BUF_FULL  (0x00001)
#define SHARED_SYM_BUF_FULL  (0xfffff)

#define USE_SYM_BUF(X)  (bp->buf_sym && ((X) == pc->sym_maxline))
#define SYM_BUF_INDEX   (1)

#define SHARED_1K_BUF_AVAIL(X) \
  (NUMBER_1K_BUFS && !(((X) & SHARED_1K_BUF_FULL) == SHARED_1K_BUF_FULL))
#define SHARED_2K_BUF_AVAIL(X) \
  (NUMBER_2K_BUFS && !(((X) & SHARED_2K_BUF_FULL) == SHARED_2K_BUF_FULL))
#define SHARED_4K_BUF_AVAIL(X) \
  (NUMBER_4K_BUFS && !(((X) & SHARED_4K_BUF_FULL) == SHARED_4K_BUF_FULL))
#define SHARED_8K_BUF_AVAIL(X) \
  (NUMBER_8K_BUFS && !(((X) & SHARED_8K_BUF_FULL) == SHARED_8K_BUF_FULL))
#define SHARED_32K_BUF_AVAIL(X) \
  (NUMBER_32K_BUFS && !(((X) & SHARED_32K_BUF_FULL) == SHARED_32K_BUF_FULL))
#define SHARED_SYM_BUF_AVAIL(X) \
  (NUMBER_SYM_BUFS && !(((X) & SHARED_SYM_BUF_FULL) == SHARED_SYM_BUF_FULL))

#define B1K  (0)
#define B2K  (1)
#define B4K  (2)
#define B8K  (3)
#define B32K (4)
#define BSB  (5)

#define SHARED_BUF_SIZES  (BSB+1)
#define MAX_MALLOC_BUFS   (500)
#define MAX_CACHE_SIZE    (KILOBYTES(32))

struct shared_bufs {
	char buf_1K[NUMBER_1K_BUFS][1024];
	char buf_2K[NUMBER_2K_BUFS][2048];
	char buf_4K[NUMBER_4K_BUFS][4096];
	char buf_8K[NUMBER_8K_BUFS][8192];
	char buf_32K[NUMBER_32K_BUFS][32768];
	char *buf_sym;
	long buf_1K_used;
	long buf_2K_used;
	long buf_4K_used;
	long buf_8K_used;
	long buf_32K_used;
	long buf_sym_used;
        long buf_1K_maxuse;
        long buf_2K_maxuse;
        long buf_4K_maxuse;
        long buf_8K_maxuse;
        long buf_32K_maxuse;
	long buf_sym_maxuse;
        long buf_1K_ovf;
        long buf_2K_ovf;
        long buf_4K_ovf;
        long buf_8K_ovf;
        long buf_32K_ovf;
	long buf_sym_ovf;
	int buf_inuse[SHARED_BUF_SIZES];
	char *malloc_bp[MAX_MALLOC_BUFS];
	long smallest;
	long largest;
	long embedded;
	long max_embedded;
	long mallocs;
	long frees;
	double total;
	ulong reqs;
} shared_bufs;

void
buf_init(void)
{
	struct shared_bufs *bp;

	bp = &shared_bufs;
	BZERO(bp, sizeof(struct shared_bufs));

	bp->smallest = 0x7fffffff; 
	bp->total = 0.0;
}

/*
 *  These are the most popular getbuf users, and depending upon the kernel
 *  configuration, pc->sym_maxline can wildly vary in size.  That being the
 *  case, after pc->sym_maxline is determined, this routine is called to
 *  carve out a special-case buffer scheme.
 */
void
sym_buf_init(void)
{
	struct shared_bufs *bp;

	bp = &shared_bufs;

	if ((bp->buf_sym = (char *)malloc(pc->sym_maxline * 20)) == NULL) {
		error(INFO, "symbol file buffer malloc: %s\n", 
			strerror(errno));
		return;
	}
	bp->buf_inuse[BSB] = 0;
}

/*
 *  Free up all buffers used by the last command.
 */
void free_all_bufs(void)
{
	int i;
	struct shared_bufs *bp;

	bp = &shared_bufs;
	bp->embedded = 0;

        for (i = 0; i < SHARED_BUF_SIZES; i++)
                bp->buf_inuse[i] = 0;

	for (i = 0; i < MAX_MALLOC_BUFS; i++) {
		if (bp->malloc_bp[i]) {
			free(bp->malloc_bp[i]);
			bp->malloc_bp[i] = NULL;
			bp->frees++;
		}
	}

	if (bp->mallocs != bp->frees) {
		dump_shared_bufs();
		error(FATAL, "malloc-free mismatch (%ld-%ld)\n",
			bp->mallocs, bp->frees);
	}
}

/*
 *  Free a specific buffer that may have been returned by malloc().
 *  If the address is one of the static buffers, look for it and
 *  clear its inuse bit.
 */
void 
freebuf(char *addr)
{
        int i;
        struct shared_bufs *bp;
	char *bufp;

        bp = &shared_bufs;
	bp->embedded--;

        if (MCLXDEBUG(5)) {
		INDENT(bp->embedded*2);
                fprintf(fp, "FREEBUF(%ld)\n", bp->embedded);
        }

        for (i = 0; bp->buf_sym && (i < NUMBER_SYM_BUFS); i++) {
		
		bufp = bp->buf_sym + (i * pc->sym_maxline);

                if (addr == bufp) {
                        bp->buf_inuse[BSB] &= ~(1 << i);
                        return;
                }
        }

	for (i = 0; i < NUMBER_1K_BUFS; i++) {
		if (addr == (char *)&bp->buf_1K[i]) {
			bp->buf_inuse[B1K] &= ~(1 << i);
			return;
		}
	}

	for (i = 0; i < NUMBER_2K_BUFS; i++) {
		if (addr == (char *)&bp->buf_2K[i]) {
			bp->buf_inuse[B2K] &= ~(1 << i);
			return;
		}
	}

	for (i = 0; i < NUMBER_4K_BUFS; i++) {
		if (addr == (char *)&bp->buf_4K[i]) {
			bp->buf_inuse[B4K] &= ~(1 << i);
			return;
		}
	}

	for (i = 0; i < NUMBER_8K_BUFS; i++) {
		if (addr == (char *)&bp->buf_8K[i]) {
			bp->buf_inuse[B8K] &= ~(1 << i);
			return;
		}
	}

        for (i = 0; i < NUMBER_32K_BUFS; i++) {
                if (addr == (char *)&bp->buf_32K[i]) {
                        bp->buf_inuse[B32K] &= ~(1 << i);
                        return;
                }
        }

        for (i = 0; i < MAX_MALLOC_BUFS; i++) {
                if (bp->malloc_bp[i] == addr) {
                        free(bp->malloc_bp[i]);
                        bp->malloc_bp[i] = NULL;
                        bp->frees++;
                        return;
                }
        }

	error(FATAL, 
	    "freeing an unknown buffer -- shared buffer inconsistency!\n");
}

/* DEBUG */
void
dump_embedded(char *s)
{
        struct shared_bufs *bp;
	char *p1;

	p1 = s ? s : "";

        bp = &shared_bufs;
        console("%s: embedded: %ld  mallocs: %ld  frees: %ld\n", 
		p1, bp->embedded, bp->mallocs, bp->frees);
}
/* DEBUG */
long
get_embedded(void)
{
	struct shared_bufs *bp;

        bp = &shared_bufs;
	return(bp->embedded);
}

/*
 *  "help -b" output
 */
void
dump_shared_bufs(void)
{
        int i;
        struct shared_bufs *bp;

        bp = &shared_bufs;

        fprintf(fp, "   buf_1K_used: %ld\n", bp->buf_1K_used);
        fprintf(fp, "   buf_2K_used: %ld\n", bp->buf_2K_used);
        fprintf(fp, "   buf_4K_used: %ld\n", bp->buf_4K_used);
        fprintf(fp, "   buf_8K_used: %ld\n", bp->buf_8K_used);
        fprintf(fp, "  buf_32K_used: %ld\n", bp->buf_32K_used);
        fprintf(fp, "  buf_sym_used: %ld\n", bp->buf_sym_used);

        fprintf(fp, "    buf_1K_ovf: %ld\n", bp->buf_1K_ovf);
        fprintf(fp, "    buf_2K_ovf: %ld\n", bp->buf_2K_ovf);
        fprintf(fp, "    buf_4K_ovf: %ld\n", bp->buf_4K_ovf);
        fprintf(fp, "    buf_8K_ovf: %ld\n", bp->buf_8K_ovf);
        fprintf(fp, "   buf_32K_ovf: %ld\n", bp->buf_32K_ovf);
        fprintf(fp, "   buf_sym_ovf: %ld\n", bp->buf_sym_ovf);

        fprintf(fp, " buf_1K_maxuse: %2ld of %d\n", bp->buf_1K_maxuse, 
		NUMBER_1K_BUFS);
        fprintf(fp, " buf_2K_maxuse: %2ld of %d\n", bp->buf_2K_maxuse, 
		NUMBER_2K_BUFS);
        fprintf(fp, " buf_4K_maxuse: %2ld of %d\n", bp->buf_4K_maxuse, 
		NUMBER_4K_BUFS);
        fprintf(fp, " buf_8K_maxuse: %2ld of %d\n", bp->buf_8K_maxuse, 
		NUMBER_8K_BUFS);
        fprintf(fp, "buf_32K_maxuse: %2ld of %d\n", bp->buf_32K_maxuse, 
		NUMBER_32K_BUFS);
        fprintf(fp, "buf_sym_maxuse: %2ld of %d\n", bp->buf_sym_maxuse, 
		NUMBER_SYM_BUFS);

	fprintf(fp, "  buf_inuse[%d]: ", SHARED_BUF_SIZES);
	for (i = 0; i < SHARED_BUF_SIZES; i++)
		fprintf(fp, "[%lx]", (ulong)bp->buf_inuse[i]);
	fprintf(fp, "\n");

        for (i = 0; i < MAX_MALLOC_BUFS; i++) 
		if (bp->malloc_bp[i])
			fprintf(fp, "  malloc_bp[%d]: %lx\n", 
				i, (ulong)bp->malloc_bp[i]);

	if (bp->smallest == 0x7fffffff)
        	fprintf(fp, "      smallest: 0\n");
	else 
        	fprintf(fp, "      smallest: %ld\n", bp->smallest);
        fprintf(fp, "       largest: %ld\n", bp->largest);

	fprintf(fp, "      embedded: %ld\n", bp->embedded);
	fprintf(fp, "  max_embedded: %ld\n", bp->max_embedded);
	fprintf(fp, "       mallocs: %ld\n", bp->mallocs);
	fprintf(fp, "         frees: %ld\n", bp->frees);
	fprintf(fp, "    reqs/total: %ld/%.1f\n", bp->reqs, bp->total);
	fprintf(fp, "  average size: %.1f\n", bp->total/bp->reqs);
}

/*
 *  Try to get one of the static buffers first.  If not available, fall
 *  through and get it from malloc(), keeping trace of the returned address.
 */

#define SHARED_BUFSIZE(size) \
                ((size <= 1024) ? 1024 >> 7 : \
                    ((size <= 2048) ? 2048 >> 7 : \
                        ((size <= 4096) ? 4096 >> 7 : \
                            ((size <= 8192) ? 8192 >> 7 : \
                                ((size <= 32768) ? 32768 >> 7 : -1)))))

char *
getbuf(long reqsize)
{
	int i;
	int index;
	int bdx;
	int mask;
	struct shared_bufs *bp;
	char *bufp;

	if (!reqsize) { 
                ulong retaddr = (ulong)__builtin_return_address(0);
                error(FATAL, "zero-size memory allocation! (called from %lx)\n",
                        retaddr);
        }

	bp = &shared_bufs;

	index = USE_SYM_BUF(reqsize) ? SYM_BUF_INDEX : SHARED_BUFSIZE(reqsize);

	if (MCLXDEBUG(1) && (reqsize > MAX_CACHE_SIZE))
		error(WARNING, "unusually large GETBUF request: %ld\n", 
			reqsize);

	if (MCLXDEBUG(5)) {
		INDENT(bp->embedded*2);
		fprintf(fp, "GETBUF(%ld -> %ld)\n", reqsize, bp->embedded);
	}

	bp->embedded++;
	if (bp->embedded > bp->max_embedded)
		bp->max_embedded = bp->embedded;

	if (reqsize < bp->smallest)
		bp->smallest = reqsize;
	if (reqsize > bp->largest)
		bp->largest = reqsize;

	bp->total += reqsize;
	bp->reqs++;

getbuf_retry:

	switch (index)
	{
	case -1:
		break;

	case 1:
                if (SHARED_SYM_BUF_AVAIL(bp->buf_inuse[BSB])) {
                        mask = ~(bp->buf_inuse[BSB]);
                        bdx = ffs(mask) - 1;
			bufp = bp->buf_sym + (bdx * pc->sym_maxline);
                        bp->buf_sym_used++;
                        bp->buf_inuse[BSB] |= (1 << bdx);
                        bp->buf_sym_maxuse = MAX(bp->buf_sym_maxuse,
                                count_bits_int(bp->buf_inuse[BSB]));
                        BZERO(bufp, pc->sym_maxline);
                        return(bufp);
		} else {
			bp->buf_sym_ovf++;
			index = SHARED_BUFSIZE(reqsize);
			goto getbuf_retry;
		}
		break;

	case 8:
                if (SHARED_1K_BUF_AVAIL(bp->buf_inuse[B1K])) {
                        mask = ~(bp->buf_inuse[B1K]);
                        bdx = ffs(mask) - 1;
                        bufp = bp->buf_1K[bdx];
                        bp->buf_1K_used++;
                        bp->buf_inuse[B1K] |= (1 << bdx);
			bp->buf_1K_maxuse = MAX(bp->buf_1K_maxuse, 
				count_bits_int(bp->buf_inuse[B1K]));
                        BZERO(bufp, 1024);
                        return(bufp);
                }
		bp->buf_1K_ovf++;  /* FALLTHROUGH */

	case 16:
                if (SHARED_2K_BUF_AVAIL(bp->buf_inuse[B2K])) {
                        mask = ~(bp->buf_inuse[B2K]);
                        bdx = ffs(mask) - 1;
                        bufp = bp->buf_2K[bdx];
                        bp->buf_2K_used++;
                        bp->buf_inuse[B2K] |= (1 << bdx);
                        bp->buf_2K_maxuse = MAX(bp->buf_2K_maxuse,
                                count_bits_int(bp->buf_inuse[B2K]));
                        BZERO(bufp, 2048);
                        return(bufp);
                }
		bp->buf_2K_ovf++;  /* FALLTHROUGH */

	case 32:
                if (SHARED_4K_BUF_AVAIL(bp->buf_inuse[B4K])) {
                        mask = ~(bp->buf_inuse[B4K]);
                        bdx = ffs(mask) - 1;
                        bufp = bp->buf_4K[bdx];
                        bp->buf_4K_used++;
                        bp->buf_inuse[B4K] |= (1 << bdx);
                        bp->buf_4K_maxuse = MAX(bp->buf_4K_maxuse,
                                count_bits_int(bp->buf_inuse[B4K]));
                        BZERO(bufp, 4096);
                        return(bufp);
                }
		bp->buf_4K_ovf++;  /* FALLTHROUGH */

        case 64:
                if (SHARED_8K_BUF_AVAIL(bp->buf_inuse[B8K])) {
                        mask = ~(bp->buf_inuse[B8K]);
                        bdx = ffs(mask) - 1;
                        bufp = bp->buf_8K[bdx];
                        bp->buf_8K_used++;
                        bp->buf_inuse[B8K] |= (1 << bdx);
                        bp->buf_8K_maxuse = MAX(bp->buf_8K_maxuse,
                                count_bits_int(bp->buf_inuse[B8K]));
                        BZERO(bufp, 8192);
                        return(bufp);
                }
		bp->buf_8K_ovf++;  /* FALLTHROUGH */

	case 256:
               if (SHARED_32K_BUF_AVAIL(bp->buf_inuse[B32K])) {
                        mask = ~(bp->buf_inuse[B32K]);
                        bdx = ffs(mask) - 1;
                        bufp = bp->buf_32K[bdx];
                        bp->buf_32K_used++;
                        bp->buf_inuse[B32K] |= (1 << bdx);
                        bp->buf_32K_maxuse = MAX(bp->buf_32K_maxuse,
                                count_bits_int(bp->buf_inuse[B32K]));
                        BZERO(bufp, 32768);
                        return(bufp);
                }
                bp->buf_32K_ovf++;
		break;
	}

	for (i = 0; i < MAX_MALLOC_BUFS; i++) {
		if (bp->malloc_bp[i])
			continue;

		if ((bp->malloc_bp[i] = (char *)malloc(reqsize))) {
			BZERO(bp->malloc_bp[i], reqsize);
			bp->mallocs++;
			return(bp->malloc_bp[i]);
		}

		break;
	}

	dump_shared_bufs();
	
	return ((char *)(long)
		error(FATAL, "cannot allocate any more memory!\n"));
}

/*
 *  Return the number of bits set in an int or long.
 */

int
count_bits_int(int val)
{
	int i, cnt;
	int total;

	cnt = sizeof(int) * 8;

	for (i = total = 0; i < cnt; i++) {
		if (val & 1)
			total++;
		val >>= 1;
	}

	return total;
}

int
count_bits_long(long val)
{
        int i, cnt;
        int total;

        cnt = sizeof(long) * 8;

        for (i = total = 0; i < cnt; i++) {
                if (val & 1)
                        total++;
                val >>= 1;
        }

        return total;
}

/*
 *  Debug routine to stop whatever's going on in its tracks.
 */
void
drop_core(char *s)
{
	volatile int *nullptr;
	int i;

	if (s && ascii_string(s))
		fprintf(stderr, "%s", s);

	kill((pid_t)pc->program_pid, 3);

	nullptr = NULL;
	while (TRUE)
		i = *nullptr;
}


/*
 *  For debug output to a device other than the current terminal.
 *  pc->console must have been preset by:
 *
 *   1. by an .rc file setting:    "set console /dev/whatever"
 *   2. by a runtime command:      "set console /dev/whatever"
 *   3. during program invocation:  "-c /dev/whatever"
 *
 *  The first time it's called, the device will be opened.
 */
int
console(char *fmt, ...)
{
        char output[BUFSIZE*2];
	va_list ap;

        if (!pc->console || !strlen(pc->console) || 
            (pc->flags & NO_CONSOLE) || (pc->confd == -1))
                return 0;

        if (!fmt || !strlen(fmt))
                return 0;

        va_start(ap, fmt);
        (void)vsnprintf(output, BUFSIZE*2, fmt, ap);
        va_end(ap);

        if (pc->confd == -2) {
                if ((pc->confd = open(pc->console, O_WRONLY|O_NDELAY)) < 0) {
                        error(INFO, "console device %s: %s\n",
                                pc->console, strerror(errno), 0, 0);
                        return 0;
                }
        }

        return(write(pc->confd, output, strlen(output)));
}

/*
 *  Allocate space to store the designated console device name.
 *  If a console device pre-exists, free its name space and close the device.
 */
void
create_console_device(char *dev)
{
        if (pc->console) {
                if (pc->confd != -1)
                        close(pc->confd);
                free(pc->console);
        }

        pc->confd = -2;

        if ((pc->console = (char *)malloc(strlen(dev)+1)) == NULL)
                fprintf(stderr, "console name malloc: %s\n", strerror(errno));
        else {
                strcpy(pc->console, dev);
                if (console("debug console [%ld]: %s\n", 
		    pc->program_pid, (ulong)pc->console) < 0) {
			close(pc->confd);
                	free(pc->console);
			pc->console = NULL;
			pc->confd = -1;
			if (!(pc->flags & RUNTIME))
				error(INFO, "cannot set console to %s\n", dev);
				
		}
        }
}

/*
 *  Disable console output without closing the device.  
 *  Typically used with CONSOLE_OFF() macro.
 */
int
console_off(void)
{
        int orig_no_console;

        orig_no_console = pc->flags & NO_CONSOLE;
        pc->flags |= NO_CONSOLE;

        return orig_no_console;
}

/*
 *  Re-enable console output.  Typically used with CONSOLE_ON() macro.
 */
int
console_on(int orig_no_console)
{
        if (!orig_no_console)
                pc->flags &= ~NO_CONSOLE;

        return(pc->flags & NO_CONSOLE);
}

/*
 *  Print a string to the console device with no formatting, useful for
 *  sending strings containing % signs.
 */
int
console_verbatim(char *s)
{
        char *p;
	int cnt;

        if (!pc->console || !strlen(pc->console) || 
	    (pc->flags & NO_CONSOLE) || (pc->confd == -1))
                return 0;

        if (!s || !strlen(s))
                return 0;

        if (pc->confd == -2) {
                if ((pc->confd = open(pc->console, O_WRONLY|O_NDELAY)) < 0) {
                        fprintf(stderr, "%s: %s\n",
                                pc->console, strerror(errno));
                        return 0;
                }
        }

        for (cnt = 0, p = s; *p; p++) {
                if (write(pc->confd, p, 1) != 1) 
			break;
		cnt++;
        }

	return cnt;
}

/*
 *  Set up a signal handler.
 */
void
sigsetup(int sig, void *handler, struct sigaction *act,struct sigaction *oldact)
{
	BZERO(act, sizeof(struct sigaction));
        act->sa_handler = handler;
        act->sa_flags = SA_NOMASK;
        sigaction(sig, act, oldact);
}

/*
 *  Convert a jiffies-based time value into a string showing the
 *  the number of days, hours:minutes:seconds.
 */
#define SEC_MINUTES  (60)
#define SEC_HOURS    (60 * SEC_MINUTES)
#define SEC_DAYS     (24 * SEC_HOURS)

char *
convert_time(ulong count, char *buf)
{
	ulong total, days, hours, minutes, seconds;

        total = (count)/machdep->hz;

        days = total / SEC_DAYS;
        total %= SEC_DAYS;
        hours = total / SEC_HOURS;
        total %= SEC_HOURS;
        minutes = total / SEC_MINUTES;
        seconds = total % SEC_MINUTES;

	buf[0] = NULLCHAR;

        if (days)
        	sprintf(buf, "%ld days, ", days);
        sprintf(&buf[strlen(buf)], "%02ld:%02ld:%02ld", 
		hours, minutes, seconds);

	return buf;
}
