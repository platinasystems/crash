/* filesys.c - core analysis suite
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
 * BitKeeper ID: @(#)filesys.c 1.14
 *
 * 09/28/00  ---    Transition to CVS version control
 *
 * CVS: $Revision: 1.51 $ $Date: 2002/01/29 22:20:12 $
 */

#include "defs.h"

static void show_mounts(ulong, int);
static int find_booted_kernel(void);
static char **build_searchdirs(int);
static int file_dump(ulong, ulong, ulong, int, int);
static ulong *create_dentry_array(ulong, int *);
static void show_fuser(char *, char *);
static int mount_point(char *);
static int open_file_reference(struct reference *);
static void memory_source_init(void);
static int get_pathname_component(ulong, ulong, int, char *, char *);
static ulong *get_mount_list(int *);
char *inode_type(char *, char *);

#define DENTRY_CACHE (20)
#define INODE_CACHE  (20)
#define FILE_CACHE   (20)

static struct filesys_table {
        char *dentry_cache;
	ulong cached_dentry[DENTRY_CACHE];
	ulong cached_dentry_hits[DENTRY_CACHE];
	int dentry_cache_index;
	ulong dentry_cache_fills;

        char *inode_cache;
        ulong cached_inode[INODE_CACHE];
        ulong cached_inode_hits[INODE_CACHE];
        int inode_cache_index;
        ulong inode_cache_fills;

        char *file_cache;
        ulong cached_file[FILE_CACHE];
        ulong cached_file_hits[FILE_CACHE];
        int file_cache_index;
        ulong file_cache_fills;

} filesys_table = { 0 };


static struct filesys_table *ft = &filesys_table;

#define DUMP_FULL_NAME   1
#define DUMP_INODE_ONLY  2
#define DUMP_DENTRY_ONLY 4

/*
 *  Open the namelist, dumpfile and output devices.
 */
void
fd_init(void)
{
	pc->nfd = pc->kfd = pc->mfd = pc->dfd = -1;

        if ((pc->nullfp = fopen("/dev/null", "w+")) == NULL)
                error(INFO, "cannot open /dev/null (for extraneous output)");

	if (REMOTE()) 
		remote_fd_init();
	else {
		if (pc->namelist) {
			if (!pc->dumpfile && !get_proc_version())
	                	error(INFO, "/proc/version: %s\n", 
					strerror(errno));
		}
		else if (!pc->namelist && !find_booted_kernel())
	                program_usage();
	
		if (!pc->dumpfile) 
			pc->flags |= LIVE_SYSTEM|DEVMEM;
	
		if ((pc->nfd = open(pc->namelist, O_RDONLY)) < 0) 
			error(FATAL, "%s: %s\n", pc->namelist, strerror(errno));
		else {
			close(pc->nfd);
			pc->nfd = -1;
		}
	
	}

	memory_source_init();
}

/*
 *  Do whatever's necessary to handle the memory source.
 */
static void
memory_source_init(void)
{
	if (REMOTE() && !(pc->flags & MEMSRC_LOCAL))
		return;

	if (pc->flags & KERNEL_DEBUG_QUERY)
		return;

        if (ACTIVE()) {
                if ((pc->mfd = open("/dev/mem", O_RDWR)) < 0) {
                        if ((pc->mfd = open("/dev/mem", O_RDONLY)) < 0)
                                error(FATAL, "/dev/mem: %s\n",
                                        strerror(errno));
                } else
                        pc->flags |= MFD_RDWR;

		return;
        } 

	if (pc->dumpfile) {
	        if (!file_exists(pc->dumpfile, NULL))
	        	error(FATAL, "%s: %s\n", pc->dumpfile, 
				strerror(ENOENT));
	
		if (!(pc->flags & (MCLXCD|LKCD|S390D|S390XD))) 
			error(FATAL, "%s: dump format not supported!\n",
				pc->dumpfile);
	
		if (pc->flags & LKCD) {
	        	if ((pc->dfd = open(pc->dumpfile, O_RDONLY)) < 0)
	                	error(FATAL, "%s: %s\n", pc->dumpfile, 
					strerror(errno));
			if (!lkcd_dump_init(fp, pc->dfd))
	                	error(FATAL, "%s: initialization failed\n", 
					pc->dumpfile);
		}

		if (pc->flags & S390D) { 
			if (!s390_dump_init(pc->dumpfile))
				error(FATAL, "%s: initialization failed\n",
                                        pc->dumpfile);
		}

		if (pc->flags & S390XD) {
			if (!s390x_dump_init(pc->dumpfile))
				error(FATAL, "%s: initialization failed\n",
                                        pc->dumpfile);
		}
	}
}


#define CREATE  1
#define DESTROY 0
#define DEFAULT_SEARCHDIRS 4

static char **
build_searchdirs(int create)
{
	int i;
	int cnt;
	DIR *dirp;
        struct dirent *dp;
	char dirbuf[BUFSIZE];
	static char **searchdirs = { 0 };
	static char *default_searchdirs[DEFAULT_SEARCHDIRS+1] = {
        	"/usr/src/linux/",
        	"/boot/",
		"/boot/efi/",
        	"/",
        	NULL
	};


	if (!create) {
		if (searchdirs) {
			for (i = DEFAULT_SEARCHDIRS; searchdirs[i]; i++) 
				free(searchdirs[i]);
			free(searchdirs);
		}
		return NULL;
	}

	cnt = DEFAULT_SEARCHDIRS;   

        if ((dirp = opendir("/usr/src"))) {
                for (dp = readdir(dirp); dp != NULL; dp = readdir(dirp)) 
			cnt++;

		if ((searchdirs = (char **)malloc(cnt * sizeof(char *))) 
		    == NULL) {
			error(INFO, "/usr/src/ directory list malloc: %s\n",
                                strerror(errno));
			closedir(dirp);
			return default_searchdirs;
		} 

		for (i = 0; i < DEFAULT_SEARCHDIRS; i++) 
			searchdirs[i] = default_searchdirs[i];
		cnt = DEFAULT_SEARCHDIRS;

		rewinddir(dirp);

        	for (dp = readdir(dirp); dp != NULL; dp = readdir(dirp)) {
			if (STREQ(dp->d_name, "linux") ||
			    STREQ(dp->d_name, ".") ||
			    STREQ(dp->d_name, ".."))
				continue;

			sprintf(dirbuf, "/usr/src/%s", dp->d_name);
			if (mount_point(dirbuf))
				continue;
			if (!is_directory(dirbuf))
				continue;

			if ((searchdirs[cnt] = (char *)
			    malloc(strlen(dirbuf)+2)) == NULL) {
				error(INFO,
				    "/usr/src/ directory entry malloc: %s\n",
                                	strerror(errno));
				break;
			}
			sprintf(searchdirs[cnt], "%s/", dirbuf); 
			cnt++;
		}
		searchdirs[cnt] = NULL;
		closedir(dirp);
	}

	for (i = 0; searchdirs[i]; i++) {
		if (MCLXDEBUG(1))
			fprintf(fp, "searchdirs[%d]: %s\n", i, searchdirs[i]);
		console("searchdirs[%d]: %s\n", i, searchdirs[i]);
	}

	return searchdirs;
}

/*
 *  If a namelist was not entered, presume we're using the currently-running
 *  kernel.  Read its version string from /proc/version, and then look in
 *  the search directories for a kernel with the same version string embedded
 *  in it.
 */
static int
find_booted_kernel(void)
{
	char kernel[BUFSIZE];
	char command[BUFSIZE];
	char buffer[BUFSIZE];
	char *version;
	char **searchdirs;
	int i;
        DIR *dirp;
        struct dirent *dp;
	FILE *pipe;
	int found;

	fflush(fp);

	if (!file_exists("/proc/version", NULL)) {
		error(INFO, 
		    "/proc/version: %s: cannot determine booted kernel\n",
			strerror(ENOENT));
		return FALSE;
	}

	if (!get_proc_version()) {
                error(INFO, "/proc/version: %s\n", strerror(errno));
                return FALSE;
	}

	version = kt->proc_version;

        if (MCLXDEBUG(1))
                console("\nfind_booted_kernel: search for [%s]\n", version);

        searchdirs = build_searchdirs(CREATE);

	for (i = 0, found = FALSE; !found && searchdirs[i]; i++) { 
	        dirp = opendir(searchdirs[i]);
		if (!dirp)
			continue;
	        for (dp = readdir(dirp); dp != NULL; dp = readdir(dirp)) {
			sprintf(kernel, "%s%s", searchdirs[i], dp->d_name);

			if (mount_point(kernel) ||
			    !file_readable(kernel) || 
                            !is_elf_file(kernel))
				continue;

			sprintf(command, "/usr/bin/strings %s", kernel);
	        	if ((pipe = popen(command, "r")) == NULL) {
	        		error(INFO, "%s: %s\n", 
					kernel, strerror(errno));
				continue;
			}

			if (MCLXDEBUG(1)) 
				fprintf(fp, "find_booted_kernel: check: %s\n", 
					kernel);
			console("find_booted_kernel: check: %s\n", kernel);

			while (fgets(buffer, BUFSIZE-1, pipe)) {
				if (STREQ(buffer, version)) {
					found = TRUE;
					break;
				}
				if (MCLXDEBUG(1) && 
				    strstr(buffer, "Linux version"))
					console(buffer);
			}
			pclose(pipe);
	
			if (found)
				break;
	        }
		closedir(dirp);
	}

	mount_point(DESTROY);
	build_searchdirs(DESTROY);

	if (found) {
                if ((pc->namelist = (char *)malloc
		    (strlen(kernel)+1)) == NULL) 
			error(FATAL, "booted kernel name malloc: %s\n",
				strerror(errno));
                else {
                        strcpy(pc->namelist, kernel);
			if (MCLXDEBUG(1))
				fprintf(fp, "find_booted_kernel: found: %s\n", 
					pc->namelist);
			console("find_booted_kernel: found: %s\n", 
				pc->namelist);
                        return TRUE;
                }
	}

	error(INFO, 
             "cannot find booted kernel -- please enter namelist argument\n\n");
	return FALSE;
}

/*
 *  Determine whether a file is a mount point, without the benefit of stat().
 *  This horrendous kludge is necessary to avoid uninterruptible stat() or 
 *  fstat() calls on nfs mount-points where the remote directory is no longer 
 *  available.
 */
static int
mount_point(char *name)
{
	int i;
	static int mount_points_gathered = -1;
	static char **mount_points;
        char *arglist[MAXARGS];
	char buf[BUFSIZE];
	char cmd[BUFSIZE];
	int argc, found;
        FILE *pipe;

	/*
	 *  The first time through, stash a list of mount points.
	 */

	if (mount_points_gathered < 0) {
		found = mount_points_gathered = 0; 

        	if (file_exists("/proc/mounts", NULL))
			sprintf(cmd, "/bin/cat /proc/mounts");
		else if (file_exists("/etc/mtab", NULL))
			sprintf(cmd, "/bin/cat /etc/mtab");
		else
                	return FALSE;

        	if ((pipe = popen(cmd, "r")) == NULL)
                	return FALSE;

		while (fgets(buf, BUFSIZE, pipe)) {
        		argc = parse_line(buf, arglist);
			if (argc < 2)
				continue;
			found++;
		}
		pclose(pipe);

		if (!(mount_points = (char **)malloc(sizeof(char *) * found)))
			return FALSE;

                if ((pipe = popen(cmd, "r")) == NULL) 
                        return FALSE;

		i = 0;
                while (fgets(buf, BUFSIZE, pipe) && 
		       (mount_points_gathered < found)) {
                        argc = parse_line(buf, arglist);
                        if (argc < 2)
                                continue;
			if ((mount_points[i] = (char *)
			     malloc(strlen(arglist[1])*2))) { 
				strcpy(mount_points[i], arglist[1]);
                        	mount_points_gathered++, i++;
			}
                }
        	pclose(pipe);

		if (MCLXDEBUG(2))
			for (i = 0; i < mount_points_gathered; i++)
				fprintf(fp, "mount_points[%d]: %s (%lx)\n", 
					i, mount_points[i], 
					(ulong)mount_points[i]);
		
	}

	/*
	 *  A null name string means we're done with this routine forever,
	 *  so the malloc'd memory can be freed.
	 */
        if (!name) {   
                for (i = 0; i < mount_points_gathered; i++) 
                        free(mount_points[i]);
                free(mount_points);
                return FALSE;
        }


	for (i = 0; i < mount_points_gathered; i++) {
		if (STREQ(name, mount_points[i]))
			return TRUE;
	}


        return FALSE;
}


/*
 *  If /proc/version exists, get it for verification purposes later.
 */
int
get_proc_version(void)
{
        FILE *pipe;

        if (!file_exists("/proc/version", NULL)) 
                return FALSE;

        if ((pipe = popen("/bin/cat /proc/version", "r")) == NULL) 
                return FALSE;

        if (fread(&kt->proc_version, sizeof(char), 
	    	BUFSIZE-1, pipe) <= 0) 
                return FALSE;
        
        pclose(pipe);

	return TRUE;
}

/*
 *  Determine whether a file exists, using the caller's stat structure if
 *  one was passed in.
 */
int
file_exists(char *file, struct stat *sp)
{
        struct stat sbuf;

        if (stat(file, sp ? sp : &sbuf) == 0)
                return TRUE;

        return FALSE;
}

/*
 *  Determine whether a file exists, and if so, if it's readable.
 */
int 
file_readable(char *file)
{
	long tmp;
	int fd;

	if (!file_exists(file, NULL))
		return FALSE;

	if ((fd = open(file, O_RDONLY)) < 0) 
		return FALSE;

	if (read(fd, &tmp, sizeof(tmp)) != sizeof(tmp)) {
		close(fd);
		return FALSE;
	}
	close(fd);

	return TRUE;
}

/*
 *  Quick file checksummer.
 */
int 
file_checksum(char *file, long *retsum)
{
	int i;
	int fd;
	ssize_t cnt;
	char buf[MIN_PAGE_SIZE];
	long csum;


	if ((fd = open(file, O_RDONLY)) < 0)
		return FALSE;

	csum = 0;
	BZERO(buf, MIN_PAGE_SIZE);
	while ((cnt = read(fd, buf, MIN_PAGE_SIZE)) > 0) {
		for (i = 0; i < cnt; i++)
			csum += buf[i];
		BZERO(buf, MIN_PAGE_SIZE);
	}
	close(fd);

	*retsum = csum;

	return TRUE;
}

int
is_directory(char *file)
{
    struct stat sbuf;
 
    if (!file || !strlen(file))
        return(FALSE);

    if (stat(file, &sbuf) == -1)
        return(FALSE);                         /* This file doesn't exist. */
            
    return((sbuf.st_mode & S_IFMT) == S_IFDIR ? TRUE : FALSE);
}


/*
 *  Determine whether a file exists, and if so, if it's a tty.
 */
int
is_a_tty(char *filename)
{
        int fd;

        if ((fd = open(filename, O_RDONLY)) < 0)
                return FALSE;

        if (isatty(fd)) {
                close(fd);
                return TRUE;
        }

        close(fd);
        return FALSE;
}

/*
 *  Open a tmpfile for command output.  fp is stashed in pc->saved_fp, and
 *  temporarily set to the new FILE pointer.  This allows a command to still
 *  print to the original output while the tmpfile is still open.
 */

#define OPEN_ONLY_ONCE 

#ifdef OPEN_ONLY_ONCE
void
open_tmpfile(void)
{
        if (pc->tmpfile)
                error(FATAL, "recursive temporary file usage\n");

	if (!pc->tmp_fp) {
        	if ((pc->tmp_fp = tmpfile()) == NULL) 
                	error(FATAL, "cannot open temporary file\n");
	}

	fflush(pc->tmpfile);
	ftruncate(fileno(pc->tmp_fp), 0);
	rewind(pc->tmp_fp);

	pc->tmpfile = pc->tmp_fp;
	pc->saved_fp = fp;
	fp = pc->tmpfile;
}
#else
void
open_tmpfile(void)
{
        if (pc->tmpfile)
                error(FATAL, "recursive temporary file usage\n");

        if ((pc->tmpfile = tmpfile()) == NULL) {
                error(FATAL, "cannot open temporary file\n");
        } else {
                pc->saved_fp = fp;
                fp = pc->tmpfile;
        }
}
#endif

/*
 *  Destroy the reference to the tmpfile, and restore fp to the state
 *  it had when open_tmpfile() was called.
 */
#ifdef OPEN_ONLY_ONCE
void
close_tmpfile(void)
{
	if (pc->tmpfile) {
		fflush(pc->tmpfile);
		ftruncate(fileno(pc->tmpfile), 0);
		rewind(pc->tmpfile);
		pc->tmpfile = NULL;
		fp = pc->saved_fp;
	} else 
		error(FATAL, "trying to close an unopened temporary file\n");
}
#else
void
close_tmpfile(void)
{
        if (pc->tmpfile) {
                fp = pc->saved_fp;
                fclose(pc->tmpfile);
                pc->tmpfile = NULL;
        } else
                error(FATAL, "trying to close an unopened temporary file\n");

}
#endif

/*
 *  open_tmpfile2() and close_tmpfile2() do not use a permanent tmpfile, 
 *  and do NOT modify the global fp pointer or pc->saved_fp.  That being the 
 *  case, all wrapped functions must be aware of it, or fp has to manipulated
 *  by the calling function.  The secondary tmpfile should only be used by
 *  common functions that might be called by a higher-level function using
 *  the primary permanent tmpfile.
 */
void 
open_tmpfile2(void)
{
        if (pc->tmpfile2)
                error(FATAL, "recursive secondary temporary file usage\n");
                
        if ((pc->tmpfile2 = tmpfile()) == NULL)
                error(FATAL, "cannot open secondary temporary file\n");
        
        rewind(pc->tmpfile2);
}

void
close_tmpfile2(void)
{
	if (pc->tmpfile2) {
		fflush(pc->tmpfile2);
		fclose(pc->tmpfile2);
        	pc->tmpfile2 = NULL;
	}
}


#define MOUNT_PRINT_INODES  0x1
#define MOUNT_PRINT_FILES   0x2
#define MOUNT_PRINT_ALL (MOUNT_PRINT_INODES|MOUNT_PRINT_FILES)

/*
 *  Display basic information about the currently mounted filesystems.
 *  The -f option lists the open files for the filesystem(s).
 *  The -i option dumps the dirty inodes of the filesystem(s).
 *  If an inode address, vfsmount, superblock, device name or 
 *  directory name is also entered, just show the data for the 
 *  filesystem indicated by the argument.
 */

static char mount_hdr[BUFSIZE] = { 0 };

void
cmd_mount(void)
{
	int i;
	int c, found;
	char *spec_string, *n;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
        char *arglist[MAXARGS*2];
	ulong vfsmount = 0;
	int flags = 0;
	int save_next;

        while ((c = getopt(argcnt, args, "if")) != EOF) {
                switch(c)
		{
		case 'i':
			flags |= MOUNT_PRINT_INODES;
			break;

		case 'f':
			flags |= MOUNT_PRINT_FILES;
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (args[optind]) {
		do {
			spec_string = args[optind];

                	if (STRNEQ(spec_string, "0x") && 
			    hexadecimal(spec_string, 0))
                        	shift_string_left(spec_string, 2);

			open_tmpfile();
			show_mounts(0, MOUNT_PRINT_ALL);

			found = FALSE;
        		rewind(pc->tmpfile);
			save_next = 0;
        		while (fgets(buf1, BUFSIZE, pc->tmpfile)) {
				if (STRNEQ(buf1, mount_hdr)) {
					save_next = 1;
					continue;
				}
				if (save_next) {
					strcpy(buf2, buf1);
					save_next = 0;
				}

                		if (!(c = parse_line(buf1, arglist)))
                        		continue;

				for (i = 0; i < c; i++) {
					if (STREQ(arglist[i], spec_string)) 
						found = TRUE;
				}
				if (found)
					break;
        		}
			close_tmpfile();

			if (found) {
				if (flags) {
					n = strchr(buf2, ' ');
					*n = NULLCHAR;
					vfsmount = htol(buf2, 
						FAULT_ON_ERROR, NULL);
					show_mounts(vfsmount, flags);
				} else {
					fprintf(fp, mount_hdr);
					fprintf(fp, buf2);
				}
			}

		} while (args[++optind]);
	} else
		show_mounts(0, flags);
}

/*
 *  Do the work for cmd_mount();
 */

static void
show_mounts(ulong one_vfsmount, int flags)
{
	ulong one_vfsmount_list;
	long sb_s_files;
	long s_dirty;
	ulong devp, dirp, sbp, dirty, type, name;
	struct list_data list_data, *ld;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	ulong *dentry_list, *dp, *mntlist;
	ulong *vfsmnt;
	char *vfsmount_buf, *super_block_buf;
	ulong dentry, inode, inode_sb, mnt_parent;
	char *dentry_buf, *inode_buf;
	int cnt, i, m, files_header_printed;
	int mount_cnt; 
	static int devlen = 0;
	char mount_files_header[BUFSIZE];

        sprintf(mount_files_header, "%s%s%s%sTYPE%sPATH\n",
                mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "DENTRY"),
                space(MINSPACE),
                mkstring(buf2, VADDR_PRLEN, CENTER|LJUST, "INODE"),
                space(MINSPACE),
		space(MINSPACE));
		
	s_dirty = OFFSET(super_block_s_dirty);

	mntlist = 0;
	ld = &list_data;

	if (one_vfsmount) {
		one_vfsmount_list = one_vfsmount;
		mount_cnt = 1;
		mntlist = &one_vfsmount_list;
	} else 
		mntlist = get_mount_list(&mount_cnt); 

	if (!strlen(mount_hdr)) {
		devlen = strlen("DEVNAME");

        	for (m = 0, vfsmnt = mntlist; m < mount_cnt; m++, vfsmnt++) {
                	readmem(*vfsmnt + OFFSET(vfsmount_mnt_devname),
                        	KVADDR, &devp, sizeof(void *),
                        	"vfsmount mnt_devname", FAULT_ON_ERROR);

                	if (read_string(devp, buf1, BUFSIZE-1)) {
				if (strlen(buf1) > devlen)
					devlen = strlen(buf1);
			}
		}

        	sprintf(mount_hdr, "%s %s %s %s DIRNAME\n",
                	mkstring(buf1, VADDR_PRLEN, CENTER, "VFSMOUNT"),
                	mkstring(buf2, VADDR_PRLEN, CENTER, "SUPERBLK"),
                	mkstring(buf3, strlen("devpts"), LJUST, "TYPE"),
			mkstring(buf4, devlen, LJUST, "DEVNAME"));
	}

	if (flags == 0)
		fprintf(fp, mount_hdr);

	if ((flags & MOUNT_PRINT_FILES) &&
	    (sb_s_files = OFFSET(super_block_s_files)) == INVALID_MEMBER) {
		/*
		 * No open files list in super_block (2.2).  
		 * Use inuse_filps list instead.
		 */
		dentry_list = create_dentry_array(symbol_value("inuse_filps"), 
			&cnt);
	}

	vfsmount_buf = GETBUF(SIZE(vfsmount));
	super_block_buf = GETBUF(SIZE(super_block));

	for (m = 0, vfsmnt = mntlist; m < mount_cnt; m++, vfsmnt++) {
                readmem(*vfsmnt, KVADDR, vfsmount_buf, SIZE(vfsmount),
                    	"vfsmount buffer", FAULT_ON_ERROR);
		
		devp = ULONG(vfsmount_buf +  OFFSET(vfsmount_mnt_devname));

		if (VALID_OFFSET(vfsmount_mnt_dirname)) {
			dirp = ULONG(vfsmount_buf +  
				OFFSET(vfsmount_mnt_dirname)); 
		} else {
			mnt_parent = ULONG(vfsmount_buf + 
				OFFSET(vfsmount_mnt_parent));
			dentry = ULONG(vfsmount_buf +  
				OFFSET(vfsmount_mnt_mountpoint));
		}

		sbp = ULONG(vfsmount_buf + OFFSET(vfsmount_mnt_sb)); 

		if (flags)
			fprintf(fp, mount_hdr);
                fprintf(fp, "%lx %lx ", *vfsmnt, sbp);

                readmem(sbp, KVADDR, super_block_buf, SIZE(super_block),
                        "super_block buffer", FAULT_ON_ERROR);
		type = ULONG(super_block_buf + OFFSET(super_block_s_type)); 
                readmem(type + OFFSET(file_system_type_name),
                        KVADDR, &name, sizeof(void *),
                        "file_system_type name", FAULT_ON_ERROR);

                if (read_string(name, buf1, BUFSIZE-1))
                       fprintf(fp, "%-6s ", buf1);
                else
                       fprintf(fp, "unknown ");

		if (read_string(devp, buf1, BUFSIZE-1)) {
			fprintf(fp, "%s ", mkstring(buf2, devlen, LJUST, buf1));
		} else
			fprintf(fp, "%s ", mkstring(buf2, devlen, LJUST, 
				"(unknown)"));

		if (VALID_OFFSET(vfsmount_mnt_dirname)) {
                	if (read_string(dirp, buf1, BUFSIZE-1))
                        	fprintf(fp, "%-10s\n", buf1);
                	else
                        	fprintf(fp, "%-10s\n", "(unknown)");
		} else {
			get_pathname(dentry, buf1, BUFSIZE, 1, mnt_parent);
                       	fprintf(fp, "%-10s\n", buf1);
		}

		if (flags & MOUNT_PRINT_FILES) {
			if (sb_s_files != -1) {
				/* 
				 * Have list of open files in super_block.
				 */
				dentry_list = 
				    create_dentry_array(sbp+sb_s_files, &cnt);
			}
			files_header_printed = 0;
			for (i=0, dp = dentry_list; i<cnt; i++, dp++) {
				dentry_buf = fill_dentry_cache(*dp);
				inode = ULONG(dentry_buf +
					OFFSET(dentry_d_inode));
				if (!inode)
					continue;
				inode_buf = fill_inode_cache(inode);
				inode_sb = ULONG(inode_buf + 
					OFFSET(inode_i_sb));
				if (inode_sb != sbp)
					continue;
				if (files_header_printed == 0) {
					fprintf(fp, "%s\n",
                                            mkstring(buf2, VADDR_PRLEN,
                                                CENTER, "OPEN FILES"));
					fprintf(fp, mount_files_header);
					files_header_printed = 1;
				}
				file_dump(0, *dp, inode, 0, DUMP_DENTRY_ONLY);
			}
			if (files_header_printed == 0) {
				fprintf(fp, "%s\nNo open files found\n",
					mkstring(buf2, VADDR_PRLEN,
                                            CENTER, "OPEN FILES"));
			} 
		}

		if (flags & MOUNT_PRINT_INODES) {
			dirty = ULONG(super_block_buf + s_dirty); 

			if (dirty != (sbp+s_dirty)) {
				BZERO(ld, sizeof(struct list_data));
                        	ld->flags = VERBOSE;
                        	ld->start = dirty;
                        	ld->end = (sbp+s_dirty);
				ld->header = "DIRTY INODES\n";
				hq_open();
                        	do_list(ld);
				hq_close();
			} else {
				fprintf(fp, 
				    "DIRTY INODES\nNo dirty inodes found\n");
			}
		}

		if (flags && !one_vfsmount)
			fprintf(fp, "\n");

	}

	if (!one_vfsmount)
		FREEBUF(mntlist); 
	FREEBUF(vfsmount_buf);
	FREEBUF(super_block_buf);
}

/*
 *  Allocate and fill a list of the currently-mounted vfsmount pointers.
 */
static ulong *
get_mount_list(int *cntptr)
{
	struct list_data list_data, *ld;
	int mount_cnt;
	ulong *mntlist;
	
        ld = &list_data;
        BZERO(ld, sizeof(struct list_data));
        get_symbol_data("vfsmntlist", sizeof(void *), &ld->start);
        if (VALID_OFFSET(vfsmount_mnt_list)) {
                ld->end = symbol_value("vfsmntlist");
                ld->list_head_offset = OFFSET(vfsmount_mnt_list);
        } else {
                ld->member_offset = OFFSET(vfsmount_mnt_next);
        }
        hq_open();
        mount_cnt = do_list(ld);
        mntlist = (ulong *)GETBUF(mount_cnt * sizeof(ulong));
        mount_cnt = retrieve_list(mntlist, mount_cnt);
        hq_close();

	*cntptr = mount_cnt;
	return mntlist;
}

/*
 *  Given a dentry, display its address, inode, super_block, pathname.
 */
static void
display_dentry_info(ulong dentry)
{
	int m, found;
        char *dentry_buf, *inode_buf, *vfsmount_buf;
        ulong inode, superblock, sb, vfs;
	ulong *mntlist, *vfsmnt;
	char pathname[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	int mount_cnt;

        fprintf(fp, "%s%s%s%s%s%sTYPE%sPATH\n",
                mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "DENTRY"),
                space(MINSPACE),
                mkstring(buf2, VADDR_PRLEN, CENTER|LJUST, "INODE"),
                space(MINSPACE),
                mkstring(buf3, VADDR_PRLEN, CENTER|LJUST, "SUPERBLK"),
                space(MINSPACE),
		space(MINSPACE));

        dentry_buf = fill_dentry_cache(dentry);
        inode = ULONG(dentry_buf + OFFSET(dentry_d_inode));
	pathname[0] = NULLCHAR;

        if (inode) {
                inode_buf = fill_inode_cache(inode);
                superblock = ULONG(inode_buf + OFFSET(inode_i_sb));
	}

	if (!inode || !superblock)
		goto nopath;

        if (VALID_OFFSET(file_f_vfsmnt)) {
		mntlist = get_mount_list(&mount_cnt);
        	vfsmount_buf = GETBUF(SIZE(vfsmount));

        	for (m = found = 0, vfsmnt = mntlist; 
		     m < mount_cnt; m++, vfsmnt++) {
                	readmem(*vfsmnt, KVADDR, vfsmount_buf, SIZE(vfsmount),
                        	"vfsmount buffer", FAULT_ON_ERROR);
                	sb = ULONG(vfsmount_buf + OFFSET(vfsmount_mnt_sb));
			if (sb == superblock) {
                		get_pathname(dentry, pathname, 
					BUFSIZE, 1, *vfsmnt);
				found = TRUE;
			}
		}

		if (!found && symbol_exists("pipe_mnt")) {
			get_symbol_data("pipe_mnt", sizeof(long), &vfs);
                        readmem(vfs, KVADDR, vfsmount_buf, SIZE(vfsmount),
                                "vfsmount buffer", FAULT_ON_ERROR);
                        sb = ULONG(vfsmount_buf + OFFSET(vfsmount_mnt_sb));
                        if (sb == superblock) {
                                get_pathname(dentry, pathname, BUFSIZE, 1, vfs);
                                found = TRUE;
                        }
		}
		if (!found && symbol_exists("sock_mnt")) {
			get_symbol_data("sock_mnt", sizeof(long), &vfs);
                        readmem(vfs, KVADDR, vfsmount_buf, SIZE(vfsmount),
                                "vfsmount buffer", FAULT_ON_ERROR);
                        sb = ULONG(vfsmount_buf + OFFSET(vfsmount_mnt_sb));
                        if (sb == superblock) {
                                get_pathname(dentry, pathname, BUFSIZE, 1, vfs);
                                found = TRUE;
                        }
		}
        } else {
		mntlist = 0;
        	get_pathname(dentry, pathname, BUFSIZE, 1, 0);
	}

	if (mntlist) {
		FREEBUF(mntlist);
		FREEBUF(vfsmount_buf);
	}

nopath:
	fprintf(fp, "%lx%s%lx%s%s%s%s%s%s\n", 
		dentry, space(MINSPACE), 
		inode, space(MINSPACE),
		mkstring(buf1, VADDR_PRLEN, CENTER|LONG_HEX, MKSTR(superblock)),
		space(MINSPACE), 
		inode_type(inode_buf, pathname),
		space(MINSPACE), pathname);
}

/*
 *  Return a 4-character type string of an inode, modifying a previously
 *  gathered pathname if necessary.
 */
char *
inode_type(char *inode_buf, char *pathname)
{
	char *type;
        uint32_t umode32;
        uint16_t umode16;
        uint mode;
        ulong inode_i_op;
        ulong inode_i_fop;
	long i_fop_off;

        mode = umode16 = umode32 = 0;

        switch (SIZE(umode_t))
        {
        case SIZEOF_32BIT:
                umode32 = UINT(inode_buf + OFFSET(inode_i_mode));
		mode = umode32;
                break;

        case SIZEOF_16BIT:
                umode16 = USHORT(inode_buf + OFFSET(inode_i_mode));
		mode = (uint)umode16;
                break;
        }

	type = "UNKN";
	if (S_ISREG(mode))
		type = "REG ";
	if (S_ISLNK(mode))
		type = "LNK ";
	if (S_ISDIR(mode))
		type = "DIR ";
	if (S_ISCHR(mode))
		type = "CHR ";
	if (S_ISBLK(mode))
		type = "BLK ";
	if (S_ISFIFO(mode)) {
		type = "FIFO";
		if (symbol_exists("pipe_inode_operations")) {
			inode_i_op = ULONG(inode_buf + OFFSET(inode_i_op));
			if (inode_i_op == 
			    symbol_value("pipe_inode_operations")) {
				type = "PIPE";
				pathname[0] = NULLCHAR;
			}
		} else {
			if (symbol_exists("rdwr_pipe_fops") && 
			    (i_fop_off = OFFSET(inode_i_fop)) > 0) {
				 inode_i_op = ULONG(inode_buf + i_fop_off);
				 if (inode_i_fop == 
				     symbol_value("rdwr_pipe_fops")) { 
					type = "PIPE";
					pathname[0] = NULLCHAR;
				 }
			}
		}
	}
	if (S_ISSOCK(mode)) {
		type = "SOCK";
		if (STREQ(pathname, "/"))
			pathname[0] = NULLCHAR;
	}

	return type;
}


/*
 *  Walk an open file list and return an array of open dentries.
 */
static ulong *
create_dentry_array(ulong list_addr, int *count)
{ 
	struct list_data list_data, *ld;
	ulong *file, *files_list, *dentry_list;
	ulong dentry, inode;
	char *file_buf, *dentry_buf;
	int cnt, f_count, i;
	int dentry_cnt = 0;

	ld = &list_data;
	BZERO(ld, sizeof(struct list_data));
	readmem(list_addr, KVADDR, &ld->start, sizeof(void *), "file list head",
		FAULT_ON_ERROR);

	if (list_addr == ld->start) {  /* empty list? */
		*count = 0;
		return NULL;
	}

	ld->end = list_addr;
	hq_open();
	cnt = do_list(ld);
	if (cnt == 0) {
		hq_close();
		*count = 0;
		return NULL;
	}
	files_list = (ulong *)GETBUF(cnt * sizeof(ulong));
	cnt = retrieve_list(files_list, cnt);
	hq_close();
	hq_open();

	for (i=0, file = files_list; i<cnt; i++, file++) {
		file_buf = fill_file_cache(*file);

		f_count = INT(file_buf + OFFSET(file_f_count));
		if (!f_count)
			continue;

		dentry = ULONG(file_buf + OFFSET(file_f_dentry));
		if (!dentry)
			continue;

		dentry_buf = fill_dentry_cache(dentry);
		inode = ULONG(dentry_buf + OFFSET(dentry_d_inode));

		if (!inode)
			continue;
		if (hq_enter(dentry))
			dentry_cnt++;
	}
	if (dentry_cnt) {
		dentry_list = (ulong *)GETBUF(dentry_cnt * sizeof(ulong));
		*count = retrieve_list(dentry_list, dentry_cnt);
	} else {
		*count = 0;
		dentry_list = NULL;
	}
	hq_close();
	FREEBUF(files_list);
	return dentry_list;
}

/*
 *  Stash vfs structure offsets
 */
void
vfs_init(void)
{ 
	OFFSET(task_struct_files) = MEMBER_OFFSET("task_struct", "files");
	OFFSET(task_struct_fs) = MEMBER_OFFSET("task_struct", "fs");
	OFFSET(fs_struct_root) = MEMBER_OFFSET("fs_struct", "root");
	OFFSET(fs_struct_pwd) = MEMBER_OFFSET("fs_struct", "pwd");
	OFFSET(fs_struct_rootmnt) = MEMBER_OFFSET("fs_struct", "rootmnt");
	OFFSET(fs_struct_pwdmnt) = MEMBER_OFFSET("fs_struct", "pwdmnt");
	OFFSET(files_struct_max_fds) = MEMBER_OFFSET("files_struct", "max_fds");
	OFFSET(files_struct_max_fdset) = 
		MEMBER_OFFSET("files_struct", "max_fdset");
	OFFSET(files_struct_open_fds) = 
		MEMBER_OFFSET("files_struct", "open_fds");
	OFFSET(files_struct_open_fds_init) = 
		MEMBER_OFFSET("files_struct", "open_fds_init");
	OFFSET(files_struct_fd) = MEMBER_OFFSET("files_struct", "fd");
	OFFSET(file_f_dentry) = MEMBER_OFFSET("file", "f_dentry");
	OFFSET(file_f_vfsmnt) = MEMBER_OFFSET("file", "f_vfsmnt");
	OFFSET(file_f_count) = MEMBER_OFFSET("file", "f_count");
	OFFSET(dentry_d_inode) = MEMBER_OFFSET("dentry", "d_inode");
	OFFSET(dentry_d_parent) = MEMBER_OFFSET("dentry", "d_parent");
	OFFSET(dentry_d_covers) = MEMBER_OFFSET("dentry", "d_covers");
	OFFSET(dentry_d_name) = MEMBER_OFFSET("dentry", "d_name");
	OFFSET(dentry_d_iname) = MEMBER_OFFSET("dentry", "d_iname");
	OFFSET(inode_i_mode) = MEMBER_OFFSET("inode", "i_mode");
	OFFSET(inode_i_op) = MEMBER_OFFSET("inode", "i_op");
	OFFSET(inode_i_sb) = MEMBER_OFFSET("inode", "i_sb");
	OFFSET(inode_u) = MEMBER_OFFSET("inode", "u");
	OFFSET(qstr_name) = MEMBER_OFFSET("qstr", "name");
	OFFSET(qstr_len) = MEMBER_OFFSET("qstr", "len");

	OFFSET(vfsmount_mnt_next) = MEMBER_OFFSET("vfsmount", "mnt_next");
        OFFSET(vfsmount_mnt_devname) = MEMBER_OFFSET("vfsmount", "mnt_devname");
        OFFSET(vfsmount_mnt_dirname) = MEMBER_OFFSET("vfsmount", "mnt_dirname");
        OFFSET(vfsmount_mnt_sb) = MEMBER_OFFSET("vfsmount", "mnt_sb");
        OFFSET(vfsmount_mnt_list) = MEMBER_OFFSET("vfsmount", "mnt_list");
        OFFSET(vfsmount_mnt_parent) = MEMBER_OFFSET("vfsmount", "mnt_parent");
        OFFSET(vfsmount_mnt_mountpoint) = 
		MEMBER_OFFSET("vfsmount", "mnt_mountpoint");

        OFFSET(super_block_s_dirty) = MEMBER_OFFSET("super_block", "s_dirty");
        OFFSET(super_block_s_type) = MEMBER_OFFSET("super_block", "s_type");
        OFFSET(file_system_type_name) = 
		MEMBER_OFFSET("file_system_type", "name");
	OFFSET(super_block_s_files) = MEMBER_OFFSET("super_block", "s_files");
        OFFSET(nlm_file_f_file) = MEMBER_OFFSET("nlm_file", "f_file");
        OFFSET(inode_i_flock) = MEMBER_OFFSET("inode", "i_flock");
        OFFSET(file_lock_fl_owner) = MEMBER_OFFSET("file_lock", "fl_owner");
        OFFSET(nlm_host_h_exportent) = MEMBER_OFFSET("nlm_host", "h_exportent");
        OFFSET(svc_client_cl_ident) = MEMBER_OFFSET("svc_client", "cl_ident");
	OFFSET(inode_i_fop) = MEMBER_OFFSET("inode","i_fop");

	SIZE(umode_t) = STRUCT_SIZE("umode_t");
	SIZE(dentry) = STRUCT_SIZE("dentry");
	SIZE(files_struct) = STRUCT_SIZE("files_struct");
	SIZE(file) = STRUCT_SIZE("file");
	SIZE(inode) = STRUCT_SIZE("inode");
	SIZE(vfsmount) = STRUCT_SIZE("vfsmount");
	SIZE(fs_struct) = STRUCT_SIZE("fs_struct");
	SIZE(super_block) = STRUCT_SIZE("super_block");

	if (!(ft->file_cache = (char *)malloc(SIZE(file)*FILE_CACHE)))
		error(FATAL, "cannot malloc file cache\n");
	if (!(ft->dentry_cache = (char *)malloc(SIZE(dentry)*DENTRY_CACHE)))
		error(FATAL, "cannot malloc dentry cache\n");
	if (!(ft->inode_cache = (char *)malloc(SIZE(inode)*INODE_CACHE)))
		error(FATAL, "cannot malloc inode cache\n");
}

void
dump_filesys_table(int verbose)
{
	int i;
	ulong fhits, dhits, ihits;

	if (!verbose)
		goto show_hit_rates;

        for (i = 0; i < FILE_CACHE; i++)
                fprintf(stderr, "   cached_file[%2d]: %lx (%ld)\n",
                        i, ft->cached_file[i],
                        ft->cached_file_hits[i]);
        fprintf(stderr, "        file_cache: %lx\n", (ulong)ft->file_cache);
        fprintf(stderr, "  file_cache_index: %d\n", ft->file_cache_index);
        fprintf(stderr, "  file_cache_fills: %ld\n", ft->file_cache_fills);

	for (i = 0; i < DENTRY_CACHE; i++)
		fprintf(stderr, "  cached_dentry[%2d]: %lx (%ld)\n", 
			i, ft->cached_dentry[i],
			ft->cached_dentry_hits[i]);
	fprintf(stderr, "      dentry_cache: %lx\n", (ulong)ft->dentry_cache);
	fprintf(stderr, "dentry_cache_index: %d\n", ft->dentry_cache_index);
	fprintf(stderr, "dentry_cache_fills: %ld\n", ft->dentry_cache_fills);

        for (i = 0; i < INODE_CACHE; i++)
                fprintf(stderr, "  cached_inode[%2d]: %lx (%ld)\n",
                        i, ft->cached_inode[i],
                        ft->cached_inode_hits[i]);
        fprintf(stderr, "       inode_cache: %lx\n", (ulong)ft->inode_cache);
        fprintf(stderr, " inode_cache_index: %d\n", ft->inode_cache_index);
        fprintf(stderr, " inode_cache_fills: %ld\n", ft->inode_cache_fills);

show_hit_rates:
        if (ft->file_cache_fills) {
                for (i = fhits = 0; i < FILE_CACHE; i++)
                        fhits += ft->cached_file_hits[i];

                fprintf(stderr, "     file hit rate: %2ld%% (%ld of %ld)\n",
                        (fhits * 100)/ft->file_cache_fills,
                        fhits, ft->file_cache_fills);
	} 

        if (ft->dentry_cache_fills) {
                for (i = dhits = 0; i < DENTRY_CACHE; i++)
                        dhits += ft->cached_dentry_hits[i];

		fprintf(stderr, "   dentry hit rate: %2ld%% (%ld of %ld)\n",
			(dhits * 100)/ft->dentry_cache_fills,
			dhits, ft->dentry_cache_fills);
	}

        if (ft->inode_cache_fills) {
                for (i = ihits = 0; i < INODE_CACHE; i++)
                        ihits += ft->cached_inode_hits[i];

		fprintf(stderr, "    inode hit rate: %2ld%% (%ld of %ld)\n",
                        (ihits * 100)/ft->inode_cache_fills,
                        ihits, ft->inode_cache_fills);
	}
}

/*
 *  This command displays information about the open files of a context.
 *  For each open file descriptor the file descriptor number, a pointer
 *  to the file struct, pointer to the dentry struct, pointer to the inode 
 *  struct, indication of file type and pathname are printed.
 *  The argument can be a task address or a PID number; if no args, the 
 *  current context is used.
 *  If the flag -l is passed, any files held open in the kernel by the
 *  lockd server on behalf of an NFS client are displayed.
 */

#define FILES_LOCKD 1

void
cmd_files(void)
{
	int c;
	ulong flag;
	ulong value;
	struct task_context *tc;
	int subsequent;
	struct reference reference, *ref;
	char *refarg;

        ref = NULL;
	flag = 0;

        while ((c = getopt(argcnt, args, "d:lR:")) != EOF) {
                switch(c)
		{
		case 'l':
			flag |= FILES_LOCKD;
			break;

		case 'R':
			if (ref) {
				error(INFO, "only one -R option allowed\n");
				argerrs++;
			} else {
				ref = &reference;
        			BZERO(ref, sizeof(struct reference));
				ref->str = refarg = optarg;
			}
			break;

		case 'd':
			value = htol(optarg, FAULT_ON_ERROR, NULL);
			display_dentry_info(value);
			return;

		default:
			argerrs++;
			break;
		}
	}

	if ((flag & FILES_LOCKD) && ref) {
		error(INFO, "-R option not applicable to -l option\n");
		argerrs++;
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (!args[optind]) {
		if (flag & FILES_LOCKD) {
			nlm_files_dump();
		} else {
			if (!ref)
				print_task_header(fp, CURRENT_CONTEXT(), 0);
			open_files_dump(CURRENT_TASK(), 0, ref);
		}
		return;
	}

	subsequent = 0;

	while (args[optind]) {

		if (ref && subsequent) {
                        BZERO(ref, sizeof(struct reference));
                        ref->str = refarg;
                }

                switch (str_to_context(args[optind], &value, &tc))
                {
                case STR_PID:
                        for (tc = pid_to_context(value); tc; tc = tc->tc_next) {
                                if (!ref)
                                        print_task_header(fp, tc, subsequent);
                                open_files_dump(tc->task, 0, ref);
                                fprintf(fp, "\n");
                        }
                        break;

                case STR_TASK:
                        if (!ref)
                                print_task_header(fp, tc, subsequent);
                        open_files_dump(tc->task, 0, ref);
                        break;

                case STR_INVALID:
                        error(INFO, "invalid task or pid value: %s\n",
                                args[optind]);
                        break;
                }

		subsequent++;
		optind++;
	}

	if (flag & FILES_LOCKD) {
		fprintf(fp, "\n");
		nlm_files_dump();
	}
}

#define FILES_REF_HEXNUM (0x1)
#define FILES_REF_DECNUM (0x2)
#define FILES_REF_FOUND  (0x4)

#define PRINT_FILE_REFERENCE()                  \
	if (!root_pwd_printed) {                \
        	print_task_header(fp, tc, 0);   \
                fprintf(fp, root_pwd);          \
		root_pwd_printed = TRUE;        \
	}                                       \
	if (!header_printed) {                  \
		fprintf(fp, files_header);      \
                header_printed = TRUE;          \
	}                                       \
	fprintf(fp, buf4);                      \
	ref->cmdflags |= FILES_REF_FOUND;

#define FILENAME_COMPONENT(P,C) \
        ((STREQ((P), "/") && STREQ((C), "/")) || \
	(!STREQ((C), "/") && strstr((P),(C))))  



/*
 *  open_files_dump() does the work for cmd_files().
 */

void
open_files_dump(ulong task, int flags, struct reference *ref)
{
        struct task_context *tc;
	ulong files_struct_addr;
	char *files_struct_buf;
	ulong fs_struct_addr;
	char *dentry_buf, *fs_struct_buf;
	ulong root_dentry, pwd_dentry;
	ulong root_inode, pwd_inode;
	ulong vfsmnt;
	int max_fdset = 0;
	int max_fds = 0;
	ulong open_fds_addr;
	fd_set open_fds;
	ulong fd;
	ulong file;
	ulong value;
	int i, j;
	int header_printed = 0;
	char root_pathname[BUFSIZE];
	char pwd_pathname[BUFSIZE];
	char files_header[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char root_pwd[BUFSIZE];
	int root_pwd_printed = 0;

	BZERO(root_pathname, BUFSIZE);
	BZERO(pwd_pathname, BUFSIZE);
	files_struct_buf = GETBUF(SIZE(files_struct));
	fill_task_struct(task);

	sprintf(files_header, " FD%s%s%s%s%s%s%sTYPE%sPATH\n",
		space(MINSPACE),
		mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "FILE"),
		space(MINSPACE),
		mkstring(buf2, VADDR_PRLEN, CENTER|LJUST, "DENTRY"),
		space(MINSPACE),
		mkstring(buf3, VADDR_PRLEN, CENTER|LJUST, "INODE"),
		space(MINSPACE),
		space(MINSPACE));

	tc = task_to_context(task);

	if (ref) 
		ref->cmdflags = 0;

	fs_struct_addr = ULONG(tt->task_struct + OFFSET(task_struct_fs));

        if (fs_struct_addr) {
		fs_struct_buf = GETBUF(SIZE(fs_struct));
                readmem(fs_struct_addr, KVADDR, fs_struct_buf, SIZE(fs_struct), 
			"fs_struct buffer", FAULT_ON_ERROR);

		root_dentry = ULONG(fs_struct_buf + OFFSET(fs_struct_root));

		if (root_dentry) {
			if (VALID_OFFSET(fs_struct_rootmnt)) {
                		vfsmnt = ULONG(fs_struct_buf +
                        		OFFSET(fs_struct_rootmnt));
				get_pathname(root_dentry, root_pathname, 
					BUFSIZE, 1, vfsmnt);
			} else {
				get_pathname(root_dentry, root_pathname, 
					BUFSIZE, 1, 0);
			}
		}

		pwd_dentry = ULONG(fs_struct_buf + OFFSET(fs_struct_pwd));

		if (pwd_dentry) {
			if (VALID_OFFSET(fs_struct_pwdmnt)) {
                		vfsmnt = ULONG(fs_struct_buf +
                        		OFFSET(fs_struct_pwdmnt));
				get_pathname(pwd_dentry, pwd_pathname, 
					BUFSIZE, 1, vfsmnt);
			} else {
				get_pathname(pwd_dentry, pwd_pathname, 
					BUFSIZE, 1, 0);
			}
		}

		if ((flags & PRINT_INODES) && root_dentry && pwd_dentry) {
			dentry_buf = fill_dentry_cache(root_dentry);
			root_inode = ULONG(dentry_buf + OFFSET(dentry_d_inode));
			dentry_buf = fill_dentry_cache(pwd_dentry);
			pwd_inode = ULONG(dentry_buf + OFFSET(dentry_d_inode));
			fprintf(fp, "ROOT: %lx %s    CWD: %lx %s\n", 
				root_inode, root_pathname, pwd_inode,
				pwd_pathname);
		} else if (ref) {
			sprintf(root_pwd, "ROOT: %s    CWD: %s \n", 
				root_pathname, pwd_pathname);
			if (FILENAME_COMPONENT(root_pathname, ref->str) ||
			    FILENAME_COMPONENT(pwd_pathname, ref->str)) {
				print_task_header(fp, tc, 0);
				fprintf(fp, root_pwd); 
				root_pwd_printed = TRUE;
				ref->cmdflags |= FILES_REF_FOUND;
			}
		} else
			fprintf(fp, "ROOT: %s    CWD: %s\n", 
				root_pathname, pwd_pathname);

		FREEBUF(fs_struct_buf);
	}

	files_struct_addr = ULONG(tt->task_struct + OFFSET(task_struct_files));

        if (files_struct_addr) {
                readmem(files_struct_addr, KVADDR, files_struct_buf, 
			SIZE(files_struct), "files_struct buffer", 
			FAULT_ON_ERROR); 

		max_fdset = INT(files_struct_buf + 
			OFFSET(files_struct_max_fdset));

		max_fds = INT(files_struct_buf + 
                        OFFSET(files_struct_max_fds));
        } 

	if (!files_struct_addr || max_fdset == 0 || max_fds == 0) {
		if (ref) {
			if (ref->cmdflags & FILES_REF_FOUND)
				fprintf(fp, "\n");
		} else
			fprintf(fp, "No open files\n");
		FREEBUF(files_struct_buf);
		return;
	}

        if (ref && IS_A_NUMBER(ref->str)) { 
                if (hexadecimal_only(ref->str, 0)) {
                        ref->hexval = htol(ref->str, FAULT_ON_ERROR, NULL);
                        ref->cmdflags |= FILES_REF_HEXNUM;
                } else {
			value = dtol(ref->str, FAULT_ON_ERROR, NULL);
			if (value <= MAX(max_fdset, max_fds)) {
                              	ref->decval = value;
                               	ref->cmdflags |= FILES_REF_DECNUM;
			} else {
                             	ref->hexval = htol(ref->str, 
					FAULT_ON_ERROR, NULL);
                                ref->cmdflags |= FILES_REF_HEXNUM;
			}
		}
        }

	open_fds_addr = ULONG(files_struct_buf + 
		OFFSET(files_struct_open_fds));

	if (open_fds_addr) {
		if (VALID_OFFSET(files_struct_open_fds_init) && 
		    (open_fds_addr == (files_struct_addr + 
		    OFFSET(files_struct_open_fds_init)))) 
			BCOPY(files_struct_buf + 
			        OFFSET(files_struct_open_fds_init),
				&open_fds, sizeof(fd_set));
		else
			readmem(open_fds_addr, KVADDR, &open_fds, 
				sizeof(fd_set), "files_struct open_fds", 
				FAULT_ON_ERROR);
	} 

	fd = ULONG(files_struct_buf + OFFSET(files_struct_fd));

	if (!open_fds_addr || !fd) {
                if (ref && (ref->cmdflags & FILES_REF_FOUND))
                	fprintf(fp, "\n");
		FREEBUF(files_struct_buf);
		return;
	}

	j = 0;
	for (;;) {
		unsigned long set;
		i = j * __NFDBITS;
		if (i >= max_fdset || i >= max_fds)
			 break;
		set = open_fds.__fds_bits[j++];
		while (set) {
			if (set & 1) {
        			readmem(fd + i*sizeof(struct file *), KVADDR, 
					&file, sizeof(struct file *), 
					"fd file", FAULT_ON_ERROR);

				if (ref && file) {
					open_tmpfile();
                                        if (file_dump(file, 0, 0, i,
                                            DUMP_FULL_NAME)) {
						BZERO(buf4, BUFSIZE);
						rewind(pc->tmpfile);
						fgets(buf4, BUFSIZE, 
							pc->tmpfile);
						close_tmpfile();
						ref->refp = buf4;
						if (open_file_reference(ref)) { 
							PRINT_FILE_REFERENCE();
						}
					} else
						close_tmpfile();
				}
				else if (file) {
					if (!header_printed) {
						fprintf(fp, files_header);
						header_printed = 1;
					}
					file_dump(file, 0, 0, i,
						  DUMP_FULL_NAME);
				}
			}
			i++;
			set >>= 1;
		}
	}

	if (!header_printed && !ref)
		fprintf(fp, "No open files\n");

	if (ref && (ref->cmdflags & FILES_REF_FOUND))
		fprintf(fp, "\n");

	FREEBUF(files_struct_buf);
}

/*
 *  Check an open file string for references.  
 */
static int
open_file_reference(struct reference *ref)
{
	char buf[BUFSIZE];
	char *arglist[MAXARGS];
	int i, fd, argcnt;
	ulong vaddr;

	strcpy(buf, ref->refp);
	if ((argcnt = parse_line(buf, arglist)) < 5)
		return FALSE;

	if (ref->cmdflags & (FILES_REF_HEXNUM|FILES_REF_DECNUM)) {
		fd = dtol(arglist[0], FAULT_ON_ERROR, NULL);
		if (((ref->cmdflags & FILES_REF_HEXNUM) && 
		    (fd == ref->hexval)) || 
                    ((ref->cmdflags & FILES_REF_DECNUM) &&
		    (fd == ref->decval))) {
			return TRUE;
		}

        	for (i = 1; i < 4; i++) {
        		vaddr = htol(arglist[i], FAULT_ON_ERROR, NULL);
        		if (vaddr == ref->hexval) 
        			return TRUE;
        	}
	}

	if (STREQ(ref->str, arglist[4])) {
		return TRUE;
	}

	if ((argcnt == 6) && FILENAME_COMPONENT(arglist[5], ref->str)) {
		return TRUE;
	}
	
	return FALSE;
}

/*
 * nlm_files_dump() prints files held open by lockd server on behalf
 * of NFS clients
 */

#define FILE_NRHASH 32

char nlm_files_header[BUFSIZE] = { 0 };
char *nlm_header = \
"Files open by lockd for client discretionary file locks:\n";

void
nlm_files_dump(void)
{
	int header_printed = 0;
	int i, j, cnt;
	ulong nlmsvc_ops, nlm_files;
	struct syment *nsp;
	ulong nlm_files_array[FILE_NRHASH];
	struct list_data list_data, *ld;
	ulong *file, *files_list;
	ulong dentry, inode, flock, host, client;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];

        if (!strlen(nlm_files_header)) {
                sprintf(nlm_files_header,
                    "CLIENT               %s %s%sTYPE%sPATH\n",
                        mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "NLM_FILE"),
                        mkstring(buf2, VADDR_PRLEN, CENTER|LJUST, "INODE"),
                        space(MINSPACE),
                        space(MINSPACE));
        }

	if (!symbol_exists("nlm_files") || !symbol_exists("nlmsvc_ops")
	    || !symbol_exists("nfsd_nlm_ops")) {
		goto out;
	}
	get_symbol_data("nlmsvc_ops", sizeof(void *), &nlmsvc_ops);
	if (nlmsvc_ops != symbol_value("nfsd_nlm_ops")) {
		goto out;
	}
	if ((nsp = next_symbol("nlm_files", NULL)) == NULL) {
		error(WARNING, "cannot find next symbol after nlm_files\n");
		goto out;
	}
	nlm_files = symbol_value("nlm_files");
	if (((nsp->value - nlm_files) / sizeof(void *)) != FILE_NRHASH ) {
		error(WARNING, "FILE_NRHASH has changed from %d\n", 
		      FILE_NRHASH);
		if (((nsp->value - nlm_files) / sizeof(void *)) < 
		    FILE_NRHASH )
			goto out;
	}

	readmem(nlm_files, KVADDR, nlm_files_array, 
		sizeof(ulong) * FILE_NRHASH, "nlm_files array",
		FAULT_ON_ERROR);
	for (i = 0; i < FILE_NRHASH; i++) {
		if (nlm_files_array[i] == 0) {
			continue;
		}
		ld = &list_data;
		BZERO(ld, sizeof(struct list_data));	
		ld->start = nlm_files_array[i];
		hq_open();
		cnt = do_list(ld);
		files_list = (ulong *)GETBUF(cnt * sizeof(ulong));
		cnt = retrieve_list(files_list, cnt);
		hq_close();
		for (j=0, file = files_list; j<cnt; j++, file++) {
			readmem(*file + OFFSET(nlm_file_f_file) + 
				OFFSET(file_f_dentry), KVADDR, &dentry,
				sizeof(void *), "nlm_file dentry", 
				FAULT_ON_ERROR);
			if (!dentry)
				continue;
			readmem(dentry + OFFSET(dentry_d_inode), KVADDR, 
				&inode, sizeof(void *), "dentry d_inode",
				FAULT_ON_ERROR);
			if (!inode)
				continue;
			readmem(inode + OFFSET(inode_i_flock), KVADDR,
				&flock, sizeof(void *), "inode i_flock",
				FAULT_ON_ERROR);
			if (!flock)
				continue;
			readmem(flock + OFFSET(file_lock_fl_owner), KVADDR,
				&host, sizeof(void *), 
				"file_lock fl_owner", FAULT_ON_ERROR);
			if (!host)
				continue;
			readmem(host + OFFSET(nlm_host_h_exportent), KVADDR,
				&client, sizeof(void *), 
				"nlm_host h_exportent", FAULT_ON_ERROR);
			if (!client)
				continue;
			if (!read_string(client + OFFSET(svc_client_cl_ident), 
			    buf1, BUFSIZE-1))
				continue;
			if (!header_printed) {
				fprintf(fp, nlm_header);
				fprintf(fp, nlm_files_header);
				header_printed = 1;
			}

			fprintf(fp, "%-20s %8lx ", buf1, *file);
			file_dump(*file, dentry, inode, 0, 
				  DUMP_INODE_ONLY | DUMP_FULL_NAME);
		}
	}
out:
	if (!header_printed)
		fprintf(fp, "No lockd server files open for NFS clients\n");
}
	    
/*
 * file_dump() prints info for an open file descriptor
 */

static int
file_dump(ulong file, ulong dentry, ulong inode, int fd, int flags)
{
	ulong vfsmnt;
	char *dentry_buf, *file_buf, *inode_buf, *type;
	char pathname[BUFSIZE];
	char *printpath;

	if (!dentry && file) {
		file_buf = fill_file_cache(file);		
		dentry = ULONG(file_buf + OFFSET(file_f_dentry));
	}

	if (!dentry) 
		return FALSE;

	if (!inode) {
		dentry_buf = fill_dentry_cache(dentry);
		inode = ULONG(dentry_buf + OFFSET(dentry_d_inode));
	}

	if (!inode) 
		return FALSE;

	inode_buf = fill_inode_cache(inode);

	if (flags & DUMP_FULL_NAME) {
		if (VALID_OFFSET(file_f_vfsmnt)) {
			vfsmnt = ULONG(file_buf + OFFSET(file_f_vfsmnt));
			get_pathname(dentry, pathname, BUFSIZE, 1, vfsmnt);
		} else {
			get_pathname(dentry, pathname, BUFSIZE, 1, 0);
		}
	} else
		get_pathname(dentry, pathname, BUFSIZE, 0, 0);

	type = inode_type(inode_buf, pathname);

	if (flags & DUMP_FULL_NAME)
		printpath = pathname;
	else
		printpath = pathname+1;

	if (flags & DUMP_INODE_ONLY) {
		fprintf(fp, "%lx%s%s%s%s\n",
			inode, 
			space(MINSPACE),
			type, 
			space(MINSPACE),
			printpath);
	} else {
		if (flags & DUMP_DENTRY_ONLY) {
			fprintf(fp, "%lx%s%lx%s%s%s%s\n",
				dentry, 
				space(MINSPACE),
				inode, 
				space(MINSPACE),
				type, 
				space(MINSPACE),
				pathname+1);
		} else {
			fprintf(fp, "%3d%s%lx%s%lx%s%lx%s%s%s%s\n",
				fd, 
				space(MINSPACE),
				file, 
				space(MINSPACE),
				dentry, 
				space(MINSPACE),
				inode, 
				space(MINSPACE),
				type, 
				space(MINSPACE),
				pathname);
		}
	}

	return TRUE;
}

/*
 * get_pathname() fills in a pathname string for an ending dentry
 * See __d_path() in the kernel for help fixing problems.
 */
void
get_pathname(ulong dentry, char *pathname, int length, int full, ulong vfsmnt)
{
	char buf[BUFSIZE];
	char tmpname[BUFSIZE];
	ulong tmp_dentry, parent;
	int d_name_len = 0;
	ulong d_name_name;
	ulong tmp_vfsmnt, mnt_parent;
	char *dentry_buf, *vfsmnt_buf;

	BZERO(buf, BUFSIZE);
	BZERO(tmpname, BUFSIZE);
	BZERO(pathname, length);
	vfsmnt_buf = VALID_OFFSET(vfsmount_mnt_mountpoint) ? 
		GETBUF(SIZE(vfsmount)) : NULL;

	parent = dentry;
	tmp_vfsmnt = vfsmnt;

	do {
		tmp_dentry = parent;

		dentry_buf = fill_dentry_cache(tmp_dentry);

		d_name_len = INT(dentry_buf +
			OFFSET(dentry_d_name) + OFFSET(qstr_len));

		if (!d_name_len) 
			break;

		d_name_name = ULONG(dentry_buf + OFFSET(dentry_d_name) 
			+ OFFSET(qstr_name));

		if (!d_name_name)
			break;

		if (!get_pathname_component(tmp_dentry, d_name_name, d_name_len,
		     dentry_buf, buf))
			break;

		if (tmp_dentry != dentry) {
			strncpy(tmpname, pathname, BUFSIZE);
			if (strlen(tmpname) + d_name_len < BUFSIZE) {
				if ((d_name_len > 1 || !STREQ(buf, "/")) &&
				    !STRNEQ(tmpname, "/")) {
					sprintf(pathname, "%s%s%s", buf, 
						"/", tmpname);
				} else {
					sprintf(pathname, 
						"%s%s", buf, tmpname);
				}
			}
		} else {
			strncpy(pathname, buf, BUFSIZE);
		}

		parent = ULONG(dentry_buf + OFFSET(dentry_d_parent)); 
			
		if (tmp_dentry == parent && full) {
			if (VALID_OFFSET(vfsmount_mnt_mountpoint)) {
				if (tmp_vfsmnt) {
					if (strncmp(pathname, "//", 2) == 0)
						shift_string_left(pathname, 1);
                                        readmem(tmp_vfsmnt, KVADDR, vfsmnt_buf,
						SIZE(vfsmount), 
						"vfsmount buffer", 
						FAULT_ON_ERROR);
        				parent = ULONG(vfsmnt_buf + 
					    OFFSET(vfsmount_mnt_mountpoint));
        				mnt_parent = ULONG(vfsmnt_buf + 
					    OFFSET(vfsmount_mnt_parent));
					if (tmp_vfsmnt == mnt_parent)
						break;
					else
						tmp_vfsmnt = mnt_parent;
				}
			} else {
				parent = ULONG(dentry_buf + 
					OFFSET(dentry_d_covers)); 
			}
		}
						
	} while (tmp_dentry != parent && parent);

	if (vfsmnt_buf)
		FREEBUF(vfsmnt_buf);
}

/*
 *  If the pathname component, which may be internal or external to the 
 *  dentry, has string length equal to what's expected, copy it into the
 *  passed-in buffer, and return its length.  If it doesn't match, return 0.
 */
static int
get_pathname_component(ulong dentry, 
		       ulong d_name_name,
		       int d_name_len,
		       char *dentry_buf, 
		       char *pathbuf)
{
	int len = d_name_len;   /* presume success */

        if (d_name_name == (dentry + OFFSET(dentry_d_iname))) {
                if (strlen(dentry_buf + OFFSET(dentry_d_iname)) == d_name_len)
                	strcpy(pathbuf, dentry_buf + OFFSET(dentry_d_iname));
                else
                        len = 0;
        } else if ((read_string(d_name_name, pathbuf, BUFSIZE)) != d_name_len)
                len = 0;

	return d_name_len;
}

/*
 *  Cache the passed-in file structure.
 */
char *
fill_file_cache(ulong file)
{
        int i;
        char *cache;

        ft->file_cache_fills++;

        for (i = 0; i < DENTRY_CACHE; i++) {
                if (ft->cached_file[i] == file) {
                        ft->cached_file_hits[i]++;
                        cache = ft->file_cache + (SIZE(file)*i);
                        return(cache);
                }
        }

        cache = ft->file_cache + (SIZE(file)*ft->file_cache_index);

        readmem(file, KVADDR, cache, SIZE(file),
                "fill_file_cache", FAULT_ON_ERROR);

        ft->cached_file[ft->file_cache_index] = file;

        ft->file_cache_index = (ft->file_cache_index+1) % DENTRY_CACHE;

        return(cache);
}

/*
 *  If active, clear the file references.
 */
void
clear_file_cache(void)
{
        int i;

        if (DUMPFILE())
                return;

        for (i = 0; i < DENTRY_CACHE; i++) {
                ft->cached_file[i] = 0;
                ft->cached_file_hits[i] = 0;
        }

        ft->file_cache_fills = 0;
        ft->file_cache_index = 0;
}



/*
 *  Cache the passed-in dentry structure.
 */
char *
fill_dentry_cache(ulong dentry)
{
	int i;
	char *cache;

	ft->dentry_cache_fills++;

        for (i = 0; i < DENTRY_CACHE; i++) {
                if (ft->cached_dentry[i] == dentry) {
			ft->cached_dentry_hits[i]++;
			cache = ft->dentry_cache + (SIZE(dentry)*i);
			return(cache);
		}
	}

	cache = ft->dentry_cache + (SIZE(dentry)*ft->dentry_cache_index);

        readmem(dentry, KVADDR, cache, SIZE(dentry),
        	"fill_dentry_cache", FAULT_ON_ERROR);

	ft->cached_dentry[ft->dentry_cache_index] = dentry;

	ft->dentry_cache_index = (ft->dentry_cache_index+1) % DENTRY_CACHE;

	return(cache);
}

/*
 *  If active, clear the dentry references.
 */
void
clear_dentry_cache(void)
{
	int i;

	if (DUMPFILE())
		return;

        for (i = 0; i < DENTRY_CACHE; i++) {
                ft->cached_dentry[i] = 0;
        	ft->cached_dentry_hits[i] = 0;
	}

        ft->dentry_cache_fills = 0;
	ft->dentry_cache_index = 0;
}

/*
 *  Cache the passed-in inode structure.
 */
char *
fill_inode_cache(ulong inode)
{
        int i;
        char *cache;

        ft->inode_cache_fills++;

        for (i = 0; i < INODE_CACHE; i++) {
                if (ft->cached_inode[i] == inode) {
                        ft->cached_inode_hits[i]++;
                        cache = ft->inode_cache + (SIZE(inode)*i);
                        return(cache);
                }
        }

        cache = ft->inode_cache + (SIZE(inode)*ft->inode_cache_index);

        readmem(inode, KVADDR, cache, SIZE(inode),
                "fill_inode_cache", FAULT_ON_ERROR);

        ft->cached_inode[ft->inode_cache_index] = inode;

        ft->inode_cache_index = (ft->inode_cache_index+1) % INODE_CACHE;

        return(cache);
}

/*      
 *  If active, clear the inode references.
 */
void
clear_inode_cache(void)
{
        int i; 
 
        if (DUMPFILE())
                return;
 
        for (i = 0; i < DENTRY_CACHE; i++) {
                ft->cached_inode[i] = 0;
                ft->cached_inode_hits[i] = 0;
        }

        ft->inode_cache_fills = 0;
        ft->inode_cache_index = 0;
}


/*
 *  This command displays the tasks using specified files or sockets.
 *  Tasks will be listed that reference the file as the current working
 *  directory, root directory, an open file descriptor, or that mmap the
 *  file.
 *  The argument can be a full pathname without symbolic links, or inode 
 *  address.
 */

void
cmd_fuser(void)
{
	int c;
	int subsequent;
	char *spec_string, *tmp;
	struct foreach_data foreach_data, *fd;
	char task_buf[BUFSIZE];
	char buf[BUFSIZE];
	char uses[20];
	char client[20];
	char fuser_header[BUFSIZE];
	int doing_fds, doing_mmap, doing_lockd, len;
	int fuser_header_printed, lockd_header_printed;

        while ((c = getopt(argcnt, args, "")) != EOF) {
                switch(c)
		{
		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (!args[optind]) {
		cmd_usage(pc->curcmd, SYNOPSIS);
		return;
	}

	sprintf(fuser_header, " PID   %s  COMM             USAGE\n",
		mkstring(buf, VADDR_PRLEN, CENTER, "TASK"));

	subsequent = 0;
	while (args[optind]) {
                spec_string = args[optind];
		if (STRNEQ(spec_string, "0x") && hexadecimal(spec_string, 0))
			shift_string_left(spec_string, 2);
		len = strlen(spec_string);
		fuser_header_printed = 0;
		lockd_header_printed = 0;
		open_tmpfile();
		BZERO(&foreach_data, sizeof(struct foreach_data));
		fd = &foreach_data;
		fd->keyword_array[0] = FOREACH_FILES;
		fd->keyword_array[1] = FOREACH_VM;
		fd->keys = 2;
		fd->flags |= FOREACH_i_FLAG;
		fd->flags |= FOREACH_l_FLAG;
		foreach(fd);
		rewind(pc->tmpfile);
		BZERO(uses, 20);
		while (fgets(buf, BUFSIZE, pc->tmpfile)) {
			if (STRNEQ(buf, "PID:")) {
				if (!STREQ(uses, "")) {
					if (!fuser_header_printed) {
						fprintf(pc->saved_fp,
							fuser_header);
						fuser_header_printed = 1;
					}
					show_fuser(task_buf, uses);
					BZERO(uses, 20);
				}
				BZERO(task_buf, BUFSIZE);
				strcpy(task_buf, buf);
				doing_lockd = doing_fds = doing_mmap = 0;
				continue;
			}
			if (STRNEQ(buf, "ROOT:")) {
				if ((tmp = strstr(buf, spec_string)) &&
				    (tmp[len] == ' ' || tmp[len] == '\n')) {
					if (strstr(tmp, "CWD:")) {
						strcat(uses, "root ");
						if ((tmp = strstr(tmp+len,
						    spec_string)) &&
						    (tmp[len] == ' ' || 
						     tmp[len] == '\n')) {
							strcat(uses, "cwd ");
						}
					} else {
						strcat(uses, "cwd ");
					}
				}
				continue;
			}
			if (strstr(buf, "DENTRY")) {
				doing_fds = 1;
				continue;
			}
			if (strstr(buf, "TOTAL_VM")) {
				doing_fds = 0;
				continue;
			}
			if (strstr(buf, " VMA ")) {
				doing_mmap = 1;
				doing_fds = 0;
				continue;
			}
			if (STREQ(buf, nlm_header) ||
			    STREQ(buf, nlm_files_header)) {
				doing_lockd = 1;
				doing_fds = doing_mmap = 0;
				continue;
			}
			if ((tmp = strstr(buf, spec_string)) &&
			    (tmp[len] == ' ' || tmp[len] == '\n')) {
				if (doing_fds) {
					strcat(uses, "fd ");
					doing_fds = 0;
				}
				if (doing_mmap) {
					strcat(uses, "mmap ");
					doing_mmap = 0;
				}
				if (doing_lockd) {
					if (!lockd_header_printed) {
						fprintf(pc->saved_fp,
							"LOCKD CLIENTS:\n");
						lockd_header_printed = 1;
					}
					BZERO(client, 20);
					memccpy(client, buf, ' ', 20);
					fprintf(pc->saved_fp, "%s\n", client);
				}
			}

		}
		if (!STREQ(uses, "")) {
			if (!fuser_header_printed) {
				fprintf(pc->saved_fp, fuser_header);
				fuser_header_printed = 1;
			}
			show_fuser(task_buf, uses);
			BZERO(uses, 20);
		}
		close_tmpfile();
		optind++;
		if (!fuser_header_printed && !lockd_header_printed) {
			fprintf(fp, "No users of %s found\n", spec_string);
		}
	}
}

static void
show_fuser(char *buf, char *uses)
{
	char pid[10];
	char task[20];
	char command[20];
	char *p;
	int i;

	BZERO(pid, 10);
	BZERO(task, 20);
	BZERO(command, 20);
	p = strstr(buf, "PID: ") + strlen("PID: ");
	i = 0;
	while (*p != ' ' && i < 10) {
		pid[i++] = *p++;
	}
	pid[i] = NULLCHAR;

	p = strstr(buf, "TASK: ") + strlen("TASK: ");
	i = 0;
	while (*p != ' ' && i < 20) {
		task[i++] = *p++;
	}
	task[i] = NULLCHAR;

	p = strstr(buf, "COMMAND: ") + strlen("COMMAND: ");
	strncpy(command, p, 16);
	i = strlen(command) - 1;
	while (i < 16) {
		command[i++] = ' ';
	}
	command[16] = NULLCHAR;
		
	fprintf(pc->saved_fp, "%5s  %s  %s %s\n", 
		pid, task, command, uses);
}


/*
 *  Gather some host memory/swap statistics, passing back whatever the
 *  caller requires.
 */

int
monitor_memory(long *freemem_pages, 
	       long *freeswap_pages, 
	       long *mem_usage,
	       long *swap_usage)
{
	FILE *mp;
	char buf[BUFSIZE];
        char *arglist[MAXARGS];
        int argc, params;
	ulong freemem, memtotal, freeswap, swaptotal;

	if (!file_exists("/proc/meminfo", NULL))
		return FALSE;

	if ((mp = fopen("/proc/meminfo", "r")) == NULL)
		return FALSE;

	params = 0;

	while (fgets(buf, BUFSIZE, mp)) {
		if (strstr(buf, "SwapFree")) {
			params++;
			argc = parse_line(buf, arglist);
			if (decimal(arglist[1], 0)) 
				freeswap = (atol(arglist[1]) * 1024)/PAGESIZE();
		}
		
		if (strstr(buf, "MemFree")) {
			params++;
                        argc = parse_line(buf, arglist);
                        if (decimal(arglist[1], 0)) 
                                freemem = (atol(arglist[1]) * 1024)/PAGESIZE();
                }

                if (strstr(buf, "MemTotal")) {
			params++;
                        argc = parse_line(buf, arglist);
                        if (decimal(arglist[1], 0))
                                memtotal = (atol(arglist[1]) * 1024)/PAGESIZE();
                }

                if (strstr(buf, "SwapTotal")) {
                        params++;
                        argc = parse_line(buf, arglist);
                        if (decimal(arglist[1], 0))
                               swaptotal = (atol(arglist[1]) * 1024)/PAGESIZE();
                }

	}

	fclose(mp);

	if (params != 4)
		return FALSE;

	if (freemem_pages)
		*freemem_pages = freemem;
	if (freeswap_pages)
        	*freeswap_pages = freeswap;
	if (mem_usage)
		*mem_usage = ((memtotal-freemem)*100) / memtotal; 
	if (swap_usage)
		*swap_usage = ((swaptotal-freeswap)*100) / swaptotal;

	return TRUE;
}

/*
 *  Determine whether two filenames reference the same file.
 */
int
same_file(char *f1, char *f2)
{
	struct stat stat1, stat2;

	if ((stat(f1, &stat1) != 0) || (stat(f2, &stat2) != 0))
		return FALSE;

	if ((stat1.st_dev == stat2.st_dev) &&
	    (stat1.st_ino == stat2.st_ino))
		return TRUE;

	return FALSE;
}


