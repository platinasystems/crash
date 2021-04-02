/* configure.c - core analysis suite
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002, 2003, 2004, 2005 David Anderson
 * Copyright (C) 2002, 2003, 2004, 2005 Red Hat, Inc. All rights reserved.
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
 */

/*
 *  define, clear and undef dynamically update the top-level Makefile: 
 *
 *   -b  define: TARGET, GDB, GDB_FILES, GDB_OFILES and TARGET_CFLAGS
 *       create: build_data.c
 *
 *   -d  define: TARGET, GDB, GDB_FILES, GDB_OFILES, TARGET_CFLAGS, and
 *               PROGRAM (for daemon)
 *       create: build_data.c
 *
 *   -u   clear: TARGET, GDB, GDB_FILES, GDB_OFILES, RELEASE and TARGET_CFLAGS 
 *        undef: WARNING_ERROR, WARNING_OPTIONS
 *
 *   -r  define: GDB_FILES, RELEASE
 *       verify that no .rpmmacro file exists for the running shell
 *
 *   -w  define: WARNING_OPTIONS
 *        undef: WARNING_ERROR
 *
 *   -W  define: WARNING_ERROR, WARNING_OPTIONS
 *
 *   -n   undef: WARNING_ERROR, WARNING_OPTIONS
 *
 *   -g  define: GDB
 *
 *   -p  Create or remove .rh_rpm_package file 
 *
 *   -q  Don't print configuration
 *
 *   -s  Create crash.spec file
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>

void build_configure(void);
void release_configure(char *);
void make_rh_rpm_package(char *);
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
char *strip_beginning_whitespace(char *);
char *strip_linefeeds(char *);
int file_exists(char *);
int count_chars(char *, char);
void make_build_data(char *);
void make_spec_file(void);
void gdb_configure(void);
int verify_rpm_targets(void);
int parse_line(char *, char **);
int setup_gdb_defaults(void);
struct supported_gdb_version;
int store_gdb_defaults(struct supported_gdb_version *);

#define TRUE 1
#define FALSE 0

#undef X86
#undef ALPHA
#undef PPC
#undef IA64
#undef S390
#undef S390X
#undef PPC64
#undef X86_64

#define X86     1
#define ALPHA   2
#define PPC     3
#define IA64    4
#define S390    5
#define S390X   6
#define PPC64   7
#define X86_64  8

#define TARGET_X86    "TARGET=X86"
#define TARGET_ALPHA  "TARGET=ALPHA"
#define TARGET_PPC    "TARGET=PPC"
#define TARGET_IA64   "TARGET=IA64"
#define TARGET_S390   "TARGET=S390"
#define TARGET_S390X  "TARGET=S390X"
#define TARGET_PPC64  "TARGET=PPC64"
#define TARGET_X86_64 "TARGET=X86_64"

#define TARGET_CFLAGS_X86    "TARGET_CFLAGS=-D_FILE_OFFSET_BITS=64"
#define TARGET_CFLAGS_ALPHA  "TARGET_CFLAGS="
#define TARGET_CFLAGS_PPC    "TARGET_CFLAGS=-D_FILE_OFFSET_BITS=64"
#define TARGET_CFLAGS_IA64   "TARGET_CFLAGS="
#define TARGET_CFLAGS_S390   "TARGET_CFLAGS=-D_FILE_OFFSET_BITS=64"
#define TARGET_CFLAGS_S390X  "TARGET_CFLAGS="
#define TARGET_CFLAGS_PPC64  "TARGET_CFLAGS=-m64"
#define TARGET_CFLAGS_X86_64 "TARGET_CFLAGS="

/*
 *  The original plan was to allow the use of a particular version
 *  of gdb for a given architecture.  But for practical purposes,
 *  it's a one-size-fits-all scheme, and they all use the default
 *  unless overridden.
 */

#define GDB_5_3  0
#define GDB_6_0  1
#define GDB_6_1  2

int default_gdb = GDB_6_1;

struct supported_gdb_version {
	char *GDB;
	char *GDB_VERSION_IN;
	char *GDB_FILES;
	char *GDB_OFILES;
} supported_gdb_versions[3] = {
	{
	    "GDB=gdb-5.3post-0.20021129.36rh",
	    "Red Hat Linux (5.3post-0.20021129.36rh)",
	    "GDB_FILES=${GDB_5.3post-0.20021129.36rh_FILES}",	   
	    "GDB_OFILES=${GDB_5.3post-0.20021129.36rh_OFILES}"
	},
	{ 
	    "GDB=gdb-6.0",
	    "6.0",
	    "GDB_FILES=${GDB_6.0_FILES}",
	    "GDB_OFILES=${GDB_6.0_OFILES}"
	},
	{
	    "GDB=gdb-6.1",
	    "6.1",
	    "GDB_FILES=${GDB_6.1_FILES}",
	    "GDB_OFILES=${GDB_6.1_OFILES}"
	},
};


char *GDB_X86; 
char *GDB_ALPHA;
char *GDB_PPC;
char *GDB_IA64;
char *GDB_S390;
char *GDB_S390X;
char *GDB_PPC64;
char *GDB_X86_64;

/* 
 * copy of gdb-x.x/gdb/version.in file 
 */
char *GDB_X86_VERSION_IN;
char *GDB_ALPHA_VERSION_IN;
char *GDB_PPC_VERSION_IN;
char *GDB_IA64_VERSION_IN;
char *GDB_S390_VERSION_IN;
char *GDB_S390X_VERSION_IN;
char *GDB_PPC64_VERSION_IN;
char *GDB_X86_64_VERSION_IN;

char *GDB_FILES_X86;
char *GDB_FILES_ALPHA;
char *GDB_FILES_PPC;
char *GDB_FILES_IA64;
char *GDB_FILES_S390;
char *GDB_FILES_S390X;
char *GDB_FILES_PPC64;
char *GDB_FILES_X86_64;

char *GDB_OFILES_X86;
char *GDB_OFILES_ALPHA;
char *GDB_OFILES_PPC;
char *GDB_OFILES_IA64;
char *GDB_OFILES_S390;
char *GDB_OFILES_S390X;
char *GDB_OFILES_PPC64;
char *GDB_OFILES_X86_64;

#define DAEMON  0x1
#define QUIET   0x2

#define MAXSTRLEN 256 
#define MIN(a,b) (((a)<(b))?(a):(b))

struct target_data {
	int target;
	int flags;
	char program[MAXSTRLEN];
	char gdb_version[MAXSTRLEN];
	char gdb_version_in[MAXSTRLEN];
	char release[MAXSTRLEN];
	struct stat statbuf;
} target_data = { 0 }; 

int
main(int argc, char **argv)
{
	int c;

	setup_gdb_defaults();

	while ((c = getopt(argc, argv, "gsqnWwubdr:p:")) > 0) {
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
		case 'p':
			make_rh_rpm_package(optarg);
			break;
		case 'W':
		case 'w':
		case 'n':
			set_warnings(c);
			break;
		case 's':
			make_spec_file();
			break;
		case 'g':
			gdb_configure();
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
#ifdef __powerpc64__
        target_data.target = PPC64;
#endif
#ifdef __x86_64__
        target_data.target = X86_64;
#endif

        if ((fp = fopen("Makefile", "r")) == NULL) {
		perror("Makefile");
		goto get_release;
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
	}

	fclose(fp);

get_release:

	target_data.release[0] = '\0';

	if (file_exists(".rh_rpm_package")) {
        	if ((fp = fopen(".rh_rpm_package", "r")) == NULL) {
			perror(".rh_rpm_package");
		} else {
			if (fgets(buf, 512, fp)) {
				strip_linefeeds(buf);
				if (strlen(buf)) {
					buf[MAXSTRLEN-1] = '\0';
					strcpy(target_data.release, buf);
				} else 
					fprintf(stderr, 
				   "WARNING: .rh_rpm_package file is empty!\n");
			} else
				fprintf(stderr, 
				   "WARNING: .rh_rpm_package file is empty!\n");
			fclose(fp);

			if (strlen(target_data.release))
				return;
		} 
	} else 
		fprintf(stderr, 
			"WARNING: .rh_rpm_package file does not exist!\n");

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
			strcpy(target_data.release, p);
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
	case PPC64:
		printf("TARGET: PPC64\n");
		break;
	case X86_64:
		printf("TARGET: X86_64\n");
		break;
	}

	if (strlen(target_data.program)) {
		for (i = 0; i < (strlen("TARGET")-strlen(target_data.program)); 
		     i++)
			printf(" ");
		printf("%s: ", target_data.program);
		if (strlen(target_data.release))
			printf("%s\n", target_data.release);
		else
			printf("???\n");
	}

	if (strlen(target_data.gdb_version)) 
		printf("   GDB: %s\n\n", &target_data.gdb_version[4]);
}

void
build_configure(void)
{
	FILE *fp1, *fp2;
	char buf[512];
	char *target;
	char *target_CFLAGS;
	char *gdb_version;
	char *gdb_version_in;
	char *gdb_files;
	char *gdb_ofiles;

	get_current_configuration();

	switch (target_data.target)
	{
	case X86:
		target = TARGET_X86;
		target_CFLAGS = TARGET_CFLAGS_X86;
		gdb_version = GDB_X86;
		gdb_version_in = GDB_X86_VERSION_IN;
		gdb_files = GDB_FILES_X86;
		gdb_ofiles = GDB_OFILES_X86;
		break;
	case ALPHA:
		target = TARGET_ALPHA;
		target_CFLAGS = TARGET_CFLAGS_ALPHA;
		gdb_version = GDB_ALPHA;
		gdb_version_in = GDB_ALPHA_VERSION_IN;
                gdb_files = GDB_FILES_ALPHA;
                gdb_ofiles = GDB_OFILES_ALPHA;
		break;
	case PPC:
		target = TARGET_PPC;
		target_CFLAGS = TARGET_CFLAGS_PPC;
		gdb_version = GDB_PPC;
		gdb_version_in = GDB_PPC_VERSION_IN;
                gdb_files = GDB_FILES_PPC;
                gdb_ofiles = GDB_OFILES_PPC;
		break;
	case IA64:
		target = TARGET_IA64;
                target_CFLAGS = TARGET_CFLAGS_IA64;
		gdb_version = GDB_IA64;
		gdb_version_in = GDB_IA64_VERSION_IN;
                gdb_files = GDB_FILES_IA64;
                gdb_ofiles = GDB_OFILES_IA64;
		break;
	case S390:
		target = TARGET_S390;
		target_CFLAGS = TARGET_CFLAGS_S390;
		gdb_version = GDB_S390;
		gdb_version_in = GDB_S390_VERSION_IN;
                gdb_files = GDB_FILES_S390;
                gdb_ofiles = GDB_OFILES_S390;
		break;
	case S390X:
		target = TARGET_S390X;
		target_CFLAGS = TARGET_CFLAGS_S390X;
		gdb_version = GDB_S390X;
		gdb_version_in = GDB_S390X_VERSION_IN;
                gdb_files = GDB_FILES_S390X;
                gdb_ofiles = GDB_OFILES_S390X;
		break;
	case PPC64:
                target = TARGET_PPC64;
                target_CFLAGS = TARGET_CFLAGS_PPC64;
                gdb_version = GDB_PPC64;
                gdb_version_in = GDB_PPC64_VERSION_IN;
                gdb_files = GDB_FILES_PPC64;
                gdb_ofiles = GDB_OFILES_PPC64;
                break;
	case X86_64:
                target = TARGET_X86_64;
                target_CFLAGS = TARGET_CFLAGS_X86_64;
                gdb_version = GDB_X86_64;
                gdb_version_in = GDB_X86_64_VERSION_IN;
                gdb_files = GDB_FILES_X86_64;
                gdb_ofiles = GDB_OFILES_X86_64;
                break;
	}

	makefile_setup(&fp1, &fp2);

	while (fgets(buf, 512, fp1)) {
		if (strncmp(buf, "TARGET=", strlen("TARGET=")) == 0)
			fprintf(fp2, "%s\n", target);
                else if (strncmp(buf, "TARGET_CFLAGS=",
			strlen("TARGET_CFLAGS=")) == 0)
                        fprintf(fp2, "%s\n", target_CFLAGS);
		else if (strncmp(buf, "GDB_FILES=",strlen("GDB_FILES=")) == 0)
			fprintf(fp2, "%s\n", gdb_files);
		else if (strncmp(buf, "GDB_OFILES=",strlen("GDB_OFILES=")) == 0)
                        fprintf(fp2, "%s\n", gdb_ofiles);
                else if (strncmp(buf, "GDB=", strlen("GDB=")) == 0) {
                        fprintf(fp2, "%s\n", gdb_version);
                        sprintf(target_data.gdb_version, "%s", &gdb_version[4]);
			bzero(target_data.gdb_version_in, MAXSTRLEN);
			strncpy(target_data.gdb_version_in, gdb_version_in, 
				MIN(strlen(gdb_version_in), MAXSTRLEN-1));
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
	char gdb_files[MAXSTRLEN];

	if (!verify_rpm_targets())
		exit(1);

	get_current_configuration();

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
		if (strncmp(buf, "GDB_FILES=", strlen("GDB_FILES=")) == 0)
			fprintf(fp2, "GDB_FILES=${%s}\n", gdb_files);
		else if (strncmp(buf, "RELEASE=", strlen("RELEASE=")) == 0)
                        fprintf(fp2, "RELEASE=%s\n", 
				target_data.release);
		else
			fprintf(fp2, "%s", buf);

	}

        if (!found) {
                fprintf(stderr, "make release: cannot find %s\n", gdb_files);
                exit(1);
        }

	makefile_create(&fp1, &fp2);
}

/*
 *  Create an .rh_rpm_package file if the passed-in variable is set.
 */
void 
make_rh_rpm_package(char *package)
{
	char *p;
	FILE *fp;

	if ((strcmp(package, "remove") == 0)) {
		if (file_exists(".rh_rpm_package")) {
			if (unlink(".rh_rpm_package")) {
				perror("unlink");
                		fprintf(stderr, 
					"cannot remove .rh_rpm_package\n");
				exit(1);
			}
		}
		return;
	}

	if (!(p = strstr(package, "=")))
		return;
	
	if (!strlen(++p))
		return;

        if ((fp = fopen(".rh_rpm_package", "w")) == NULL) {
                perror("fopen");
                fprintf(stderr, "cannot open .rh_rpm_package\n");
                exit(1);
        }

	fprintf(fp, "%s\n", strip_linefeeds(p));

	fclose(fp);
}

/*
 *  Verify that the rpm build area will be in /usr/src/redhat by checking
 *  for the default settings (indicated by "rpm --showrc").
 */

#define DEFAULT_RPM_DIR "%{_topdir}/"
#define DEFAULT_TOPDIR  "%{_usrsrc}/redhat"
#define DEFAULT_USRSRC  "%{_usr}/src"
#define DEFAULT_USR     "/usr"

int 
verify_rpm_targets(void)
{
	int errors;
	char inbuf[4096], *p1, *p2;
	FILE *fpr;

	errors = 0;
	fpr = popen("/bin/rpm --showrc", "r");

	while (fgets(inbuf, 4095, fpr)) {
                if ((p1 = strstr(inbuf, ": _topdir	")) &&
                    !strstr(p1, DEFAULT_TOPDIR)) {
                        p2 = p1 + strlen(": _topdir");
                        fprintf(stderr, "non-default rpm top directory: %s",
                                p2+1);
                        errors++;
                }
                if ((p1 = strstr(inbuf, ": _usrsrc	")) &&
                    !strstr(p1, DEFAULT_USRSRC)) {
                        p2 = p1 + strlen(": _usrsrc");
                        fprintf(stderr,"non-default rpm /usr/src directory: %s",
                                p2+1);
                        errors++;
                }
                if ((p1 = strstr(inbuf, ": _usr	")) &&
                    !strstr(p1, DEFAULT_USR)) {
                        p2 = p1 + strlen(": _usr");
                        fprintf(stderr,"non-default rpm /usr directory: %s",                                p2+1);
                        errors++;
                }

		if ((p1 = strstr(inbuf, ": _builddir	")) &&
		    !strstr(p1, DEFAULT_RPM_DIR "BUILD")) { 
			p2 = p1 + strlen(": _builddir");
			fprintf(stderr, "non-default rpm BUILD directory: %s",
				p2+1);
			errors++;
		}
                if ((p1 = strstr(inbuf, ": _rpmdir	")) &&
                    !strstr(p1, DEFAULT_RPM_DIR "RPMS")) {
			p2 = p1 + strlen(": _rpmdir");
                        fprintf(stderr, "non-default rpm RPMS directory: %s",
                                p2+1);
                        errors++;
                }
                if ((p1 = strstr(inbuf, ": _sourcedir	")) &&
                    !strstr(p1, DEFAULT_RPM_DIR "SOURCES")) {
			p2 = p1 + strlen(": _sourcedir");
                        fprintf(stderr, "non-default rpm SOURCES directory: %s",
                                p2+1);
                        errors++;
                }
                if ((p1 = strstr(inbuf, ": _specdir	")) &&
                    !strstr(p1, DEFAULT_RPM_DIR "SPECS")) {
			p2 = p1 + strlen(": _specdir");
                        fprintf(stderr, "non-default rpm SPECS directory: %s",
                                p2+1);
                        errors++;
                }
                if ((p1 = strstr(inbuf, ": _srcrpmdir	")) &&
                    !strstr(p1, DEFAULT_RPM_DIR "SRPMS")) {
			p2 = p1 + strlen(": _srcrpmdir");
                        fprintf(stderr, "non-default rpm SRPMS directory: %s",
                                p2+1);
                        errors++;
                }
	}

	return (errors ? FALSE : TRUE); 
}



void
gdb_configure(void)
{
	FILE *fp1, *fp2;
	char buf[512];
	char *gdb_version;

	get_current_configuration();

	switch (target_data.target)
	{
	case X86:
		gdb_version = GDB_X86;
		break;
	case ALPHA:
		gdb_version = GDB_ALPHA;
		break;
	case PPC:
		gdb_version = GDB_PPC;
		break;
	case IA64:
		gdb_version = GDB_IA64;
		break;
	case S390:
		gdb_version = GDB_S390;
		break;
	case S390X:
		gdb_version = GDB_S390X;
		break;
	case PPC64:
		gdb_version = GDB_PPC64;
		break;
	case X86_64:
		gdb_version = GDB_X86_64;
		break;
	}

	if ((strcmp(gdb_version, GDB_X86) != 0) &&
	    (strcmp(gdb_version, GDB_ALPHA) != 0) &&
	    (strcmp(gdb_version, GDB_PPC) != 0) &&
	    (strcmp(gdb_version, GDB_IA64) != 0) &&
	    (strcmp(gdb_version, GDB_S390) != 0) &&
	    (strcmp(gdb_version, GDB_S390X) != 0) &&
	    (strcmp(gdb_version, GDB_PPC64) != 0) &&
	    (strcmp(gdb_version, GDB_X86_64) != 0)) {
		fprintf(stderr, "divergent gdb versions\n");
		return;
	}

	makefile_setup(&fp1, &fp2);

	while (fgets(buf, 512, fp1)) {
		if (strncmp(buf, "GDB=", strlen("GDB=")) == 0)
			fprintf(fp2, "%s\n", gdb_version);
		else
			fprintf(fp2, "%s", buf);

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
                else if (strncmp(buf, "TARGET_CFLAGS=",
			strlen("TARGET_CFLAGS=")) == 0)
                        fprintf(fp2, "TARGET_CFLAGS=\n");
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

char *
strip_beginning_whitespace(char *line)
{
        char buf[MAXSTRLEN];
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

int
file_exists(char *file)
{
        struct stat sbuf;

        if (stat(file, &sbuf) == 0)
                return TRUE;

        return FALSE;
}

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


void
make_build_data(char *target)
{
        char *p;
        char hostname[MAXSTRLEN];
	char progname[MAXSTRLEN];
	char inbuf1[MAXSTRLEN];
	char inbuf2[MAXSTRLEN];
	char inbuf3[MAXSTRLEN];
	FILE *fp1, *fp2, *fp3, *fp4;

	unlink("build_data.c");

        fp1 = popen("date", "r");
        fp2 = popen("id", "r");
	fp3 = popen("gcc --version", "r");

	if ((fp4 = fopen("build_data.c", "w")) == NULL) {
		perror("build_data.c");
		exit(1);
	}

        if (gethostname(hostname, MAXSTRLEN) != 0)
                hostname[0] = '\0';

        fgets(inbuf1, 79, fp1);

        fgets(inbuf2, 79, fp2);
        p = strstr(inbuf2, ")");
        p++;
        *p = '\0';

        fgets(inbuf3, 79, fp3);

	lower_case(target_data.program, progname);

	fprintf(fp4, "char *build_command = \"%s\";\n", progname);
        if (strlen(hostname))
                fprintf(fp4, "char *build_data = \"%s by %s on %s\";\n",
                        strip_linefeeds(inbuf1), inbuf2, hostname);
        else
                fprintf(fp4, "char *build_data = \"%s by %s\";\n", 
			strip_linefeeds(inbuf1), inbuf2);

        bzero(inbuf1, MAXSTRLEN);
	sprintf(inbuf1, "%s", target_data.release);

	fprintf(fp4, "char *build_target = \"%s\";\n", target);

        fprintf(fp4, "char *build_version = \"%s\";\n", inbuf1);

	fprintf(fp4, "char *compiler_version = \"%s\";\n", 
		strip_linefeeds(inbuf3));

        pclose(fp1);
        pclose(fp2);
        pclose(fp3);
	fclose(fp4);
}

void
make_spec_file(void)
{
	char *Version, *Release;
	char buf[512];

	get_current_configuration();

	Release = strstr(target_data.release, "-");
	if (!Release) {
		fprintf(stderr, 
 	     "\nNOTE: cannot create local spec file: no release number: [%s]\n",
			target_data.release);
		return;
	}
	*Release = '\0';
	Version = target_data.release;
	Release++;

	printf("#\n");
	printf("# crash core analysis suite\n");
	printf("#\n");
	printf("Summary: crash utility for live systems; netdump, diskdump, LKCD or mcore dumpfiles\n");
	printf("Name: %s\n", lower_case(target_data.program, buf));
	printf("Version: %s\n", Version);
	printf("Release: %s\n", Release);
	printf("License: GPL\n");
	printf("Group: Development/Debuggers\n");
	printf("Source: %%{name}-%%{version}-%%{release}.tar.gz\n");
	printf("URL: ftp://people.redhat.com/anderson/%%{name}-%%{version}-%%{release}.tar.gz\n");
	printf("Distribution: Linux 2.2 or greater\n");
	printf("Vendor: Red Hat, Inc.\n");
	printf("Packager: Dave Anderson <anderson@redhat.com>\n");
	printf("ExclusiveOS: Linux\n");
	printf("ExclusiveArch: i386 alpha ia64 ppc ppc64 ppc64pseries ppc64iseries x86_64 s390 s390x\n");
	printf("Buildroot: %%{_tmppath}/%%{name}-root\n");
	printf("BuildRequires: ncurses-devel zlib-devel\n");
	printf("# Patch0: crash-3.3-20.installfix.patch (patch example)\n");
	printf("\n");
	printf("%%description\n");
	printf("The core analysis suite is a self-contained tool that can be used to\n");
	printf("investigate either live systems, kernel core dumps created from the\n");
	printf("netdump and diskdump packages from Red Hat Linux, the mcore kernel patch\n");
	printf("offered by Mission Critical Linux, or the LKCD kernel patch.\n");
	printf("\n");
	printf("%%prep\n");
        printf("%%setup -n %%{name}-%%{version}-%%{release}\n"); 
	printf("# %%patch0 -p1 -b .install (patch example)\n");
	printf("\n");
	printf("%%build\n");
	printf("make RPMPKG=\"%%{version}-%%{release}\"\n");
     /*	printf("make crashd\n"); */
	printf("\n");
	printf("%%install\n");
	printf("rm -rf %%{buildroot}\n");
	printf("mkdir -p %%{buildroot}/usr/bin\n");
	printf("make DESTDIR=%%{buildroot} install\n");
	printf("mkdir -p %%{buildroot}%%{_mandir}/man8\n");
	printf("cp crash.8 %%{buildroot}%%{_mandir}/man8/crash.8\n");
	printf("\n");
	printf("%%clean\n");
	printf("rm -rf %%{buildroot}\n");
	printf("\n");
	printf("%%files\n");
	printf("/usr/bin/crash\n");
	printf("%%{_mandir}/man8/crash.8*\n");
     /*	printf("/usr/bin/crashd\n"); */
	printf("%%doc README\n");
}

/*
 *  Use the default gdb #defines unless there's a .gdb_config file
 *  containing statments for DEFAULT_GDB, DEFAULT_GDB_VERSION_IN,
 *  DEFAULT_GDB_FILES and DEFAULT_GDB_OFILES.
 */
char GDB_override[MAXSTRLEN] = { 0 };
char GDB_VERSION_IN_override[MAXSTRLEN] = { 0 };
char GDB_FILES_override[MAXSTRLEN] = { 0 };
char GDB_OFILES_override[MAXSTRLEN] = { 0 };
struct supported_gdb_version test_gdb_version = { 0 };

int
setup_gdb_defaults(void)
{
	FILE *fp;
	char inbuf[512];
	char buf[512];
	char *p1, *p2;
	int line, bad, cnt;
	char *gdb, *gdb_version_in, *gdb_files, *gdb_ofiles;
	struct supported_gdb_version *sp;

	gdb = gdb_version_in = gdb_files = gdb_ofiles = NULL;
	bad = line = 0;
	sp = NULL;

	/*
	 *  Use the default, allowing for an override in .gdb_config
	 */
        if (!file_exists(".gdb_config")) 
		return store_gdb_defaults(NULL);

        if ((fp = fopen(".gdb_config", "r")) == NULL) {
        	perror(".gdb_config");
		return store_gdb_defaults(NULL);
	}

        while (fgets(inbuf, 512, fp)) {
		line++;
		strip_linefeeds(inbuf);
		strip_beginning_whitespace(inbuf);

		strcpy(buf, inbuf);

		/*
		 *  Simple override.
		 */
		if (strcmp(buf, "5.3") == 0) {
			if (gdb || gdb_version_in || gdb_files || gdb_ofiles) {
				fprintf(stderr, 
				    ".gdb_config[line %d]: mixed supported/test configuration?\n", 
					line);
				bad++;
				break;
			}
			fclose(fp);
			sp = &supported_gdb_versions[GDB_5_3];
			fprintf(stderr, ".gdb_config configuration: %s\n\n", sp->GDB_VERSION_IN);
			return store_gdb_defaults(sp);
		}
		if (strcmp(buf, "6.0") == 0) {
			if (gdb || gdb_version_in || gdb_files || gdb_ofiles) {
				fprintf(stderr, 
				    ".gdb_config[line %d]: mixed supported/test configuration?\n", 
					line);
				bad++;
				break;
			}
			fclose(fp);
			sp = &supported_gdb_versions[GDB_6_0];
			fprintf(stderr, ".gdb_config configuration: %s\n\n", sp->GDB_VERSION_IN);
			return store_gdb_defaults(sp);
		}
		if (strcmp(buf, "6.1") == 0) {
			if (gdb || gdb_version_in || gdb_files || gdb_ofiles) {
				fprintf(stderr, 
				    ".gdb_config[line %d]: mixed supported/test configuration?\n", 
					line);
				bad++;
				break;
			}
			fclose(fp);
			fprintf(stderr, ".gdb_config configuration: 6.1\n\n");
			sp = &supported_gdb_versions[GDB_6_1];
			fprintf(stderr, ".gdb_config configuration: %s\n", sp->GDB_VERSION_IN);
			return store_gdb_defaults(sp);
		}

		/*
		 *  Test case override.
		 *  
		 *  This is the acceptable .gdb_config file format:
		 *
		 *   GDB             "GDB=gdb-6.0"
		 *   GDB_VERSION_IN  "6.0"
		 *   GDB_FILES       "GDB_FILES=${GDB_6.0_FILES}"
		 *   GDB_OFILES      "GDB_OFILES=${GDB_6.0_OFILES}"
	 	 */

                if ((strncmp(buf, "GDB ", 4) == 0) ||
		    (strncmp(buf, "GDB	", 4) == 0) ||
		    (strncmp(buf, "GDB=", 4) == 0))  {
			if (strlen(GDB_override)) {
				fprintf(stderr, 
				    ".gdb_config[line %d]: GDB already configured: \"%s\"\n", 
					line, GDB_override);
				bad++;
				break;
			}
			p1 = index(buf, '\"');
			p2 = rindex(buf, '\"');
			cnt = count_chars(buf, '\"');
			if ((cnt != 2) || !p1 || !p2 || (p1 == p2) || (p2 == (p1+1))) 
				goto malformed;
			*p2 = '\0';
			gdb = p1+1; 
			if (count_chars(gdb, ' ') || count_chars(gdb, '\t'))
				goto malformed;
			strcpy(GDB_override, gdb);
		}
                else if ((strncmp(buf, "GDB_VERSION_IN ", 15) == 0) || 
		    (strncmp(buf, "GDB_VERSION_IN	", 15) == 0) ||
		    (strncmp(buf, "GDB_VERSION_IN=", 15) == 0)) {
			if (strlen(GDB_VERSION_IN_override)) {
				fprintf(stderr, 
				    ".gdb_config[line %d]: GDB_VERSION_IN already configured: \"%s\"\n", 
					line, GDB_VERSION_IN_override);
				bad++;
				break;
			}
			p1 = index(buf, '\"');
			p2 = rindex(buf, '\"');
			cnt = count_chars(buf, '\"');
			if ((cnt != 2) || !p1 || !p2 || (p1 == p2) || (p2 == (p1+1))) 
				goto malformed;
			*(p2) = '\0';
			gdb_version_in = p1+1;
			if (count_chars(gdb_version_in, ' ') || 
			    count_chars(gdb_version_in, '\t'))
				goto malformed;
			strcpy(GDB_VERSION_IN_override, gdb_version_in);
		}
                else if ((strncmp(buf, "GDB_FILES ", 10) == 0) ||
		    (strncmp(buf, "GDB_FILES	", 10) == 0) ||
		    (strncmp(buf, "GDB_FILES=", 10) == 0)) {
			if (strlen(GDB_FILES_override)) {
				fprintf(stderr, 
				    ".gdb_config[line %d]: GDB_FILES already configured: \"%s\"?\n", 
					line, GDB_FILES_override);
				bad++;
				break;
			}
			p1 = index(buf, '\"');
			p2 = rindex(buf, '\"');
			cnt = count_chars(buf, '\"');
			if ((cnt != 2) || !p1 || !p2 || (p1 == p2) || (p2 == (p1+1))) 
				goto malformed;
			*(p2) = '\0';
			gdb_files = p1+1;
			if (count_chars(gdb_files, ' ') || count_chars(gdb_files, '\t'))
				goto malformed;
			strcpy(GDB_FILES_override, gdb_files);
		}
                else if ((strncmp(buf, "GDB_OFILES ", 11) == 0) ||
		    (strncmp(buf, "GDB_OFILES	", 11) == 0) ||
		    (strncmp(buf, "GDB_OFILES=", 11) == 0)) {
			if (strlen(GDB_OFILES_override)) {
				fprintf(stderr, 
				    ".gdb_config[line %d]: GDB_OFILES already configured: \"%s\"\n", 
					line, GDB_OFILES_override);
				bad++;
				break;
			}
			p1 = index(buf, '\"');
			p2 = rindex(buf, '\"');
			cnt = count_chars(buf, '\"');
			if ((cnt != 2) || !p1 || !p2 || (p1 == p2) || (p2 == (p1+1))) 
				goto malformed;
			*(p2) = '\0';
			gdb_ofiles = p1+1;
			if (count_chars(gdb_ofiles, ' ') || count_chars(gdb_ofiles, '\t'))
				goto malformed;
			strcpy(GDB_OFILES_override, gdb_ofiles);
                }
		else {
			if (buf[0] == '#')
				continue;
			goto malformed;
		}
        }
	
	fclose(fp);

	if (bad || !gdb || !gdb_version_in || !gdb_files || !gdb_ofiles) {
		fprintf(stderr, ".gdb_config: rejected -- using default gdb\n\n");
		sp = NULL;
	} else {
		fprintf(stderr, ".gdb_config test configuration:\n");
		fprintf(stderr, "    GDB=\"%s\"\n", GDB_override);
		fprintf(stderr, "    GDB_VERSION_IN=\"%s\"\n", GDB_VERSION_IN_override);
		fprintf(stderr, "    GDB_FILES=\"%s\"\n", GDB_FILES_override);
		fprintf(stderr, "    GDB_OFILES=\"%s\"\n\n", GDB_OFILES_override);
	
		test_gdb_version.GDB = GDB_override;
		test_gdb_version.GDB_VERSION_IN = GDB_VERSION_IN_override;
		test_gdb_version.GDB_FILES = GDB_FILES_override;
		test_gdb_version.GDB_OFILES = GDB_OFILES_override;
		sp = &test_gdb_version;
	}

 	return store_gdb_defaults(sp);

malformed:
	fclose(fp);
        fprintf(stderr, ".gdb_config[line %d]: malformed line:\n%s\n",
        	line, inbuf);
	fprintf(stderr, ".gdb_config: rejected!\n\n");

	return store_gdb_defaults(NULL);
}

int
store_gdb_defaults(struct supported_gdb_version *sp)
{
	if (!sp)
		sp = &supported_gdb_versions[default_gdb];
	else
		fprintf(stderr, "WARNING: \"make clean\" may be required before rebuilding\n\n");

	GDB_X86 = sp->GDB;
	GDB_ALPHA = sp->GDB;
	GDB_PPC = sp->GDB;
	GDB_IA64 = sp->GDB;
	GDB_S390 = sp->GDB;
	GDB_S390X = sp->GDB;
	GDB_PPC64 = sp->GDB;
	GDB_X86_64 = sp->GDB;

	GDB_X86_VERSION_IN = sp->GDB_VERSION_IN;
	GDB_ALPHA_VERSION_IN = sp->GDB_VERSION_IN;
	GDB_PPC_VERSION_IN = sp->GDB_VERSION_IN;
	GDB_IA64_VERSION_IN = sp->GDB_VERSION_IN;
	GDB_S390_VERSION_IN = sp->GDB_VERSION_IN;
	GDB_S390X_VERSION_IN = sp->GDB_VERSION_IN;
	GDB_PPC64_VERSION_IN = sp->GDB_VERSION_IN;
	GDB_X86_64_VERSION_IN = sp->GDB_VERSION_IN;

	GDB_FILES_X86 = sp->GDB_FILES;
	GDB_FILES_ALPHA = sp->GDB_FILES;
	GDB_FILES_PPC = sp->GDB_FILES;
	GDB_FILES_IA64 = sp->GDB_FILES;
	GDB_FILES_S390 = sp->GDB_FILES;
	GDB_FILES_S390X = sp->GDB_FILES;
	GDB_FILES_PPC64 = sp->GDB_FILES;
	GDB_FILES_X86_64 = sp->GDB_FILES;

	GDB_OFILES_X86 = sp->GDB_OFILES;
	GDB_OFILES_ALPHA = sp->GDB_OFILES;
	GDB_OFILES_PPC = sp->GDB_OFILES;
	GDB_OFILES_IA64 = sp->GDB_OFILES;
	GDB_OFILES_S390 = sp->GDB_OFILES;
	GDB_OFILES_S390X = sp->GDB_OFILES;
	GDB_OFILES_PPC64 = sp->GDB_OFILES;
	GDB_OFILES_X86_64 = sp->GDB_OFILES;

	return TRUE;
}
