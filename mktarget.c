/* mktarget.c - core analysis suite
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
 * 01/18/00, 2.0    Initial gdb merger, support for Alpha
 * 02/01/00, 2.1    Bug fixes, new commands, options, support for v2 SGI dumps
 * 02/29/00, 2.2    Bug fixes, new commands, options
 * 04/11/00, 2.3    Bug fixes, new command, options, initial PowerPC framework
 * 04/12/00  ---    Transition to BitKeeper version control
 * 
 * BitKeeper ID: @(#)mktarget.c 1.4
 *
 * 09/28/00  ---    Transition to CVS version control
 *
 * CVS: $Revision: 1.21 $ $Date: 2002/01/24 20:17:38 $
 */

/*
 *  Dynamically update the top-level Makefile: 
 *
 *   -b  define: TARGET, GDB, GDB_FILES, GDB_OFILES
 *       create: build_data.c
 *
 *   -d  define: TARGET, GDB, GDB_FILES, GDB_OFILES, PROGRAM (for daemon)
 *       create: build_data.c
 *
 *   -u   clear: TARGET, GDB, GDB_FILES, GDB_OFILES, RELEASE 
 *        undef: WARNING_ERROR, WARNING_OPTIONS
 *
 *   -r  define: GDB_FILES
 *
 *   -w  define: WARNING_OPTIONS
 *        undef: WARNING_ERROR
 *
 *   -W  define: WARNING_ERROR, WARNING_OPTIONS
 *
 *   -n   undef: WARNING_ERROR, WARNING_OPTIONS
 *
 *   -q  Don't print configuration
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>

void build_configure(void);
void release_configure(char *);
void unconfigure(void);
void set_warnings(int);
void show_configuration(void);
void get_current_configuration(void);
void makefile_setup(FILE **, FILE **);
void makefile_create(FILE **, FILE **);
char *strip_linefeeds(char *);
char *upper_case(char *, char *);
char *lower_case(char *, char *);
char *shift_string_left(char *, int);
char *shift_string_right(char *, int);
int file_exists(char *);
static void make_build_data(char *);


#undef X86
#undef ALPHA
#undef PPC
#undef IA64
#undef S390
#undef S390X

#define X86     1
#define ALPHA   2
#define PPC     3
#define IA64    4
#define S390    5
#define S390X   6

#define TARGET_X86   "TARGET=X86"
#define TARGET_ALPHA "TARGET=ALPHA"
#define TARGET_PPC   "TARGET=PPC"
#define TARGET_IA64  "TARGET=IA64"
#define TARGET_S390  "TARGET=S390"
#define TARGET_S390X "TARGET=S390X"

#define GDB_X86      "GDB=gdb-5.1"
#define GDB_ALPHA    "GDB=gdb-5.1"
#define GDB_PPC      "GDB=gdb-5.1"
#define GDB_IA64     "GDB=gdb-5.1"
#define GDB_S390     "GDB=gdb-5.1"
#define GDB_S390X    "GDB=gdb-5.1"

#define GDB_FILES_X86     "GDB_FILES=${GDB_5.1_FILES}"
#define GDB_FILES_ALPHA   "GDB_FILES=${GDB_5.1_FILES}"
#define GDB_FILES_PPC     "GDB_FILES=${GDB_5.1_FILES}"
#define GDB_FILES_IA64    "GDB_FILES=${GDB_5.1_FILES}"
#define GDB_FILES_S390    "GDB_FILES=${GDB_5.1_FILES}"
#define GDB_FILES_S390X   "GDB_FILES=${GDB_5.1_FILES}"

#define GDB_OFILES_X86    "GDB_OFILES=${GDB_5.1_OFILES}"
#define GDB_OFILES_ALPHA  "GDB_OFILES=${GDB_5.1_OFILES}"
#define GDB_OFILES_PPC    "GDB_OFILES=${GDB_5.1_OFILES}"
#define GDB_OFILES_IA64   "GDB_OFILES=${GDB_5.1_OFILES}"
#define GDB_OFILES_S390   "GDB_OFILES=${GDB_5.1_OFILES}"
#define GDB_OFILES_S390X  "GDB_OFILES=${GDB_5.1_OFILES}"

#define DAEMON  0x1
#define QUIET   0x2

struct target_data {
	int target;
	int flags;
	char program[80];
	char gdb_version[80];
	char release[80];
	char patch_version[80];
	struct stat statbuf;
} target_data = { 0 }; 

int
main(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, "qnWwubdr:")) > 0) {
		switch (c) {
		case 'q':
			target_data.flags |= QUIET;
			break;
		case 'u':
			unconfigure();
			break;
		case 'd':
			target_data.flags |= DAEMON;
		case 'b':
			build_configure();
			break;
		case 'r':
			release_configure(optarg);
			break;
		case 'W':
		case 'w':
		case 'n':
			set_warnings(c);
			break;
		}
	}

	exit(0);
}


void
get_current_configuration(void)
{
	FILE *fp;
	static char buf[512];
	char *p;

#ifdef __alpha__
        target_data.target = ALPHA;
#endif
#ifdef __i386__
        target_data.target = X86;
#endif
#ifdef __powerpc__
        target_data.target = PPC;
#endif
#ifdef __ia64__
        target_data.target = IA64;
#endif
#ifdef __s390__
        target_data.target = S390;
#endif
#ifdef __s390x__
        target_data.target = S390X;
#endif

        if ((fp = fopen("Makefile", "r")) == NULL) {
		perror("Makefile");
		goto get_patch_version;
	}

	while (fgets(buf, 512, fp)) {
		if (strncmp(buf, "PROGRAM=", strlen("PROGRAM=")) == 0) {
			p = strstr(buf, "=") + 1;
			strip_linefeeds(p);
			upper_case(p, target_data.program);
			if (target_data.flags & DAEMON)
				strcat(target_data.program, "D");
			continue;
		}

                if (strncmp(buf, "RELEASE=", strlen("RELEASE=")) == 0) {
			p = strstr(buf, "=") + 1;
			strip_linefeeds(p);
			strcpy(target_data.release, p);
                        continue;
		}

                if (strncmp(buf, "#define BASELEVEL_REVISION",
                    strlen("#define BASELEVEL_REVISION")) == 0) {
                        p = strstr(buf, "\"") + 1;
                        strip_linefeeds(p);
                        p[strlen(p)-1] = '\0';
                        strcpy(target_data.patch_version, p);
                        break;
                }
	}

	fclose(fp);

get_patch_version:

	if (!file_exists("defs.h")) {
		if (file_exists("SCCS/s.defs.h")) {
			system("/usr/bin/get defs.h");
			if (!file_exists("defs.h")) {
				perror("defs.h");
				return;
			}
		}
	}

        if ((fp = fopen("defs.h", "r")) == NULL) {
                perror("defs.h");
		return;
        }

        while (fgets(buf, 512, fp)) {
                if (strncmp(buf, "#define BASELEVEL_REVISION", 
		    strlen("#define BASELEVEL_REVISION")) == 0) {
			p = strstr(buf, "\"") + 1;
			strip_linefeeds(p);
			p[strlen(p)-1] = '\0';
			strcpy(target_data.patch_version, p);
			break;
		}
	}

	fclose(fp);
}

void 
show_configuration(void)
{
	int i;

	if (target_data.flags & QUIET)
		return;

	switch (target_data.target)
	{
	case X86:    
		printf("TARGET: X86\n");
		break;
	case ALPHA: 
		printf("TARGET: ALPHA\n");
		break;
	case PPC:    
		printf("TARGET: PPC\n");
		break;
	case IA64:   
		printf("TARGET: IA64\n");
		break;
	case S390:
		printf("TARGET: S390\n");
		break;
	case S390X:
		printf("TARGET: S390X\n");
		break;
	}

	if (strlen(target_data.program)) {
		for (i = 0; i < (strlen("TARGET")-strlen(target_data.program)); 
		     i++)
			printf(" ");
		printf("%s: ", target_data.program);
		if (strlen(target_data.patch_version))
			printf("%s\n", target_data.patch_version);
		else if (strlen(target_data.release))
			printf("%s\n", target_data.release);
		else
			printf("???\n");
	}

	if (strlen(target_data.gdb_version)) {
		printf("   GDB: %s\n", target_data.gdb_version);
	}

}

void
build_configure(void)
{
	FILE *fp1, *fp2;
	char buf[512];
	char *target;
	char *gdb_version;
	char *gdb_files;
	char *gdb_ofiles;

	get_current_configuration();

	switch (target_data.target)
	{
	case X86:
		target = TARGET_X86;
		gdb_version = GDB_X86;
		gdb_files = GDB_FILES_X86;
		gdb_ofiles = GDB_OFILES_X86;
		break;
	case ALPHA:
		target = TARGET_ALPHA;
		gdb_version = GDB_ALPHA;
                gdb_files = GDB_FILES_ALPHA;
                gdb_ofiles = GDB_OFILES_ALPHA;
		break;
	case PPC:
		target = TARGET_PPC;
		gdb_version = GDB_PPC;
                gdb_files = GDB_FILES_PPC;
                gdb_ofiles = GDB_OFILES_PPC;
		break;
	case IA64:
		target = TARGET_IA64;
		gdb_version = GDB_IA64;
                gdb_files = GDB_FILES_IA64;
                gdb_ofiles = GDB_OFILES_IA64;
		break;
	case S390:
		target = TARGET_S390;
		gdb_version = GDB_S390;
                gdb_files = GDB_FILES_S390;
                gdb_ofiles = GDB_OFILES_S390;
		break;
	case S390X:
		target = TARGET_S390X;
		gdb_version = GDB_S390X;
                gdb_files = GDB_FILES_S390X;
                gdb_ofiles = GDB_OFILES_S390X;
		break;
	}

	makefile_setup(&fp1, &fp2);

	while (fgets(buf, 512, fp1)) {
		if (strncmp(buf, "TARGET=", strlen("TARGET=")) == 0)
			fprintf(fp2, "%s\n", target);
		else if (strncmp(buf, "GDB_FILES=",strlen("GDB_FILES=")) == 0)
			fprintf(fp2, "%s\n", gdb_files);
		else if (strncmp(buf, "GDB_OFILES=",strlen("GDB_OFILES=")) == 0)
                        fprintf(fp2, "%s\n", gdb_ofiles);
                else if (strncmp(buf, "GDB=", strlen("GDB=")) == 0) {
                        fprintf(fp2, "%s\n", gdb_version);
                        sprintf(target_data.gdb_version, "%s", &gdb_version[4]);
		} else
			fprintf(fp2, "%s", buf);

	}

	makefile_create(&fp1, &fp2);

	show_configuration();

	make_build_data(&target[strlen("TARGET=")]);
}

void
release_configure(char *gdb_version)
{
	FILE *fp1, *fp2;
	int found;
	char buf[512];
	char gdb_files[80];

	sprintf(buf, "%s/gdb", gdb_version);
	if (!file_exists(buf)) {
		fprintf(stderr, "make release: no such directory: %s\n", buf);
		exit(1);
	}
	sprintf(gdb_files, "GDB_%s_FILES", 
		&gdb_version[strlen("gdb-")]);

	makefile_setup(&fp1, &fp2);

	found = 0;
	while (fgets(buf, 512, fp1)) {
		if (strncmp(buf, gdb_files, strlen(gdb_files)) == 0)
			found++;
		if (strncmp(buf, "GDB_FILES=",strlen("GDB_FILES=")) == 0)
			fprintf(fp2, "GDB_FILES=${%s}\n", gdb_files);
		else
			fprintf(fp2, "%s", buf);

	}

        if (!found) {
                fprintf(stderr, "make release: cannot find %s\n", gdb_files);
                exit(1);
        }

	makefile_create(&fp1, &fp2);
}

void
unconfigure(void)
{
	FILE *fp1, *fp2;
	char buf[512];

	makefile_setup(&fp1, &fp2);

	while (fgets(buf, 512, fp1)) {
                if (strncmp(buf, "TARGET=", strlen("TARGET=")) == 0)
                        fprintf(fp2, "TARGET=\n");
                else if (strncmp(buf, "GDB_FILES=",strlen("GDB_FILES=")) == 0)
                        fprintf(fp2, "GDB_FILES=\n");
                else if (strncmp(buf, "GDB_OFILES=",strlen("GDB_OFILES=")) == 0)
                        fprintf(fp2, "GDB_OFILES=\n");
                else if (strncmp(buf, "GDB=", strlen("GDB=")) == 0) 
                        fprintf(fp2, "GDB=\n");
                else if (strncmp(buf, "RELEASE=", strlen("RELEASE=")) == 0) 
                        fprintf(fp2, "RELEASE=\n");
                else if (strncmp(buf, "WARNING_ERROR=", 
			strlen("WARNING_ERROR=")) == 0) {
                        shift_string_right(buf, 1);
			buf[0] = '#';
                        fprintf(fp2, "%s", buf);
		} else if (strncmp(buf, "WARNING_OPTIONS=",
                    strlen("WARNING_OPTIONS=")) == 0) {
                        shift_string_right(buf, 1);
			buf[0] = '#';
                        fprintf(fp2, "%s", buf);
		} else
                        fprintf(fp2, "%s", buf);
	}

	makefile_create(&fp1, &fp2);
}

void
set_warnings(int w)
{
        FILE *fp1, *fp2;
        char buf[512];

        makefile_setup(&fp1, &fp2);
 
        while (fgets(buf, 512, fp1)) {
		if (strncmp(buf, "#WARNING_ERROR=", 
		    strlen("#WARNING_ERROR=")) == 0) {
			switch (w)
			{
			case 'W':
				shift_string_left(buf, 1);
				break;
			case 'w':
			case 'n':
				break;
			}
		}

                if (strncmp(buf, "WARNING_ERROR=", 
		    strlen("WARNING_ERROR=")) == 0) {
			switch (w) 
			{
			case 'n':
			case 'w':
				shift_string_right(buf, 1);
				buf[0] = '#';
				break;
			case 'W':
				break;
			}
		}
		
                if (strncmp(buf, "#WARNING_OPTIONS=",
                    strlen("#WARNING_OPTIONS=")) == 0) { 
			switch (w)
			{
			case 'W':
			case 'w':
				shift_string_left(buf, 1);
				break;
			case 'n':
				break;
			}
		}

                if (strncmp(buf, "WARNING_OPTIONS=",
                    strlen("WARNING_OPTIONS=")) == 0) {
			switch (w) 
			{
			case 'w':
			case 'W':
				break;
			case 'n':
				shift_string_right(buf, 1);
				buf[0] = '#';
				break;
			}
		}

                fprintf(fp2, "%s", buf);
        }

        makefile_create(&fp1, &fp2);
}

void
makefile_setup(FILE **fp1, FILE **fp2)
{
        if (stat("Makefile", &target_data.statbuf) == -1) {
                perror("Makefile");
                exit(1);
        }

        if ((*fp1 = fopen("Makefile", "r")) == NULL) {
                perror("fopen");
                fprintf(stderr, "cannot open existing Makefile\n");
                exit(1);
        }

        unlink("Makefile.new");
        if ((*fp2 = fopen("Makefile.new", "w+")) == NULL) {
                perror("fopen");
                fprintf(stderr, "cannot create new Makefile\n");
                exit(1);
        }
}

void
makefile_create(FILE **fp1, FILE **fp2)
{
        fclose(*fp1);
        fclose(*fp2);

        if (system("mv Makefile.new Makefile") != 0) {
                fprintf(stderr, "Makefile: cannot create new Makefile\n");
                fprintf(stderr, "please copy Makefile.new to Makefile\n");
                exit(1);
        }

        if (chown("Makefile", target_data.statbuf.st_uid, 
	    target_data.statbuf.st_gid) == -1) {
                fprintf(stderr,
                    "Makefile: cannot restore original owner/group\n");
        }
}



#define LASTCHAR(s)      (s[strlen(s)-1])

char *
strip_linefeeds(char *line)
{
        char *p;

        if (line == NULL || strlen(line) == 0)
                return(line);

        p = &LASTCHAR(line);

        while (*p == '\n')
                *p = (char)NULL;

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
                
        *p2 = '\0';
        
        return(buf);
}

/*      
 *  Turn a string into lower-case.
 */
char *
lower_case(char *s, char *buf)
{
        char *p1, *p2;
 
        p1 = s;
        p2 = buf;   
 
        while (*p1) {
                *p2 = tolower(*p1);
                p1++, p2++;
        }
  
        *p2 = '\0'; 
  
        return(buf);
}

char *
shift_string_left(char *s, int cnt)
{
        int origlen;

        if (!cnt)
                return(s);

        origlen = strlen(s);
        memmove(s, s+cnt, (origlen-cnt));
        *(s+(origlen-cnt)) = '\0';
        return(s);
}

char *
shift_string_right(char *s, int cnt)
{
        int i;
        int origlen;

        if (!cnt)
                return(s);

        origlen = strlen(s);
        memmove(s+cnt, s, origlen);
        *(s+(origlen+cnt)) = '\0';

        for (i = 0; i < cnt; i++)
                s[i] = ' ';

        return(s);
}


#define TRUE 1
#define FALSE 0

int
file_exists(char *file)
{
        struct stat sbuf;

        if (stat(file, &sbuf) == 0)
                return TRUE;

        return FALSE;
}


void
make_build_data(char *target)
{
        char *p;
        char hostname[80];
	char progname[80];
	char inbuf1[80];
	char inbuf2[80];
	FILE *fp1, *fp2, *fp3;

	unlink("build_data.c");

        fp1 = popen("date", "r");
        fp2 = popen("id", "r");

	if ((fp3 = fopen("build_data.c", "w")) == NULL) {
		perror("build_data.c");
		exit(1);
	}

        if (gethostname(hostname, 80) != 0)
                hostname[0] = '\0';

        fgets(inbuf1, 79, fp1);

        fgets(inbuf2, 79, fp2);
        p = strstr(inbuf2, ")");
        p++;
        *p = '\0';

	lower_case(target_data.program, progname);

	fprintf(fp3, "char *build_command = \"%s\";\n", progname);
        if (strlen(hostname))
                fprintf(fp3, "char *build_data = \"%s by %s on %s\";\n",
                        strip_linefeeds(inbuf1), inbuf2, hostname);
        else
                fprintf(fp3, "char *build_data = \"%s by %s\";\n", 
			strip_linefeeds(inbuf1), inbuf2);

        bzero(inbuf1, 80);
	sprintf(inbuf1, "%s", target_data.patch_version);

        pclose(fp1);
        pclose(fp2);

	fprintf(fp3, "char *build_baselevel = \"%s BASELEVEL_REVISION %s\";\n", 
		target, target_data.patch_version);

        fprintf(fp3, "char *build_version = \"%s\";\n", inbuf1);

	fclose(fp3);
}

