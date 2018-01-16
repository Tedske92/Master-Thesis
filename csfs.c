/*
  Big Brother File System
  Copyright (C) 2012 Joseph J. Pfeiffer, Jr., Ph.D. <pfeiffer@cs.nmsu.edu>

  This program can be distributed under the terms of the GNU GPLv3.
  See the file COPYING.

  This code is derived from function prototypes found /usr/include/fuse/fuse.h
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  His code is licensed under the LGPLv2.
  A copy of that code is included in the file fuse.h
  
  The point of this FUSE filesystem is to provide an introduction to
  FUSE.  It was my first FUSE filesystem as I got to know the
  software; hopefully, the comments in this code will help people who
  follow later to get a gentler introduction.

  This might be called a no-op filesystem:  it doesn't impose
  filesystem semantics on top of any other existing structure.  It
  simply reports the requests that come in, and passes them to an
  underlying filesystem.  The information is saved in a logfile named
  bbfs.log, in the directory from which you run bbfs.

gcc bbfs.c `pkg-config fuse --cflags --libs` -I/usr/include/openssl -lcurl -lmxml -lcrypto -o bbfs
*/

#include "params.h"
#include "client_server.h"
#include "crypto.h"
#include "keyhandling.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <libgen.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <mxml.h>

#ifdef HAVE_SYS_XATTR_H
#include <sys/xattr.h>
#endif

const char *cookie;
const char *token;
const char *response;
const char *keyring;


//  All the paths I see are relative to the root of the mounted
//  filesystem.  In order to get to the underlying filesystem, I need to
//  have the mountpoint.  I'll save it away early on in main(), and then
//  whenever I need a path for something I'll call this to construct
//  it.

static void cs_fullpath(char fpath[PATH_MAX], const char *path)
{
    strcpy(fpath, CS_DATA->rootdir);
    strncat(fpath, path, PATH_MAX); // ridiculously long paths will
				    // break here
}

///////////////////////////////////////////////////////////
//
// Prototypes for all these functions, and the C-style comments,
// come from /usr/include/fuse.h
//
/** Get file attributes.
 *
 * Similar to stat().  The 'st_dev' and 'st_blksize' fields are
 * ignored.  The 'st_ino' field is ignored except if the 'use_ino'
 * mount option is given.
 */
int cs_getattr(const char *path, struct stat *statbuf)
{
    int retstat = 0;
    char fpath[PATH_MAX];
    
    cs_fullpath(fpath, path);
    
    retstat = lstat(fpath, statbuf);
    if (retstat < 0) 
	retstat = -errno;

    return retstat;
    
}

/** Read the target of a symbolic link
 *
 * The buffer should be filled with a null terminated string.  The
 * buffer size argument includes the space for the terminating
 * null character.  If the linkname is too long to fit in the
 * buffer, it should be truncated.  The return value should be 0
 * for success.
 */
// Note the system readlink() will truncate and lose the terminating
// null.  So, the size passed to to the system readlink() must be one
// less than the size passed to cs_readlink()
// cs_readlink() code by Bernardo F Costa (thanks!)
int cs_readlink(const char *path, char *link, size_t size)
{
    int retstat = 0;
    char fpath[PATH_MAX];
    
    cs_fullpath(fpath, path);

    retstat = readlink(fpath, link, size - 1);
    if (retstat >= 0) {
	link[retstat] = '\0';
	retstat = 0;
    }
    
    return retstat;
}

/** Create a file node
 *
 * There is no create() operation, mknod() will be called for
 * creation of all non-directory, non-symlink nodes.
 */
// shouldn't that comment be "if" there is no.... ?



int cs_mknod(const char *path, mode_t mode, dev_t dev)
{
    int retstat = 0;
    const char *ext = malloc(8);
    char *sharefilepath = malloc(32);
    char fpath[PATH_MAX];
    cs_fullpath(fpath, path);
    // On Linux this could just be 'mknod(path, mode, dev)' but this
    // tries to be be more portable by honoring the quote in the Linux
    // mknod man page stating the only portable use of mknod() is to
    // make a fifo, but saying it should never actually be used for
    // that.
    if (S_ISREG(mode)) {
	retstat = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
	if (retstat >= 0)
	    retstat = close(retstat);
    } else
	if (S_ISFIFO(mode))
	    retstat = mkfifo(fpath, mode);
	else
	    retstat = mknod(fpath, mode, dev);
   
    if (retstat < 0) 
	retstat = -errno;

    //create fresh keys
		//get filepath to store in keyring after upload
	//write fileinformation to keyring
	ext = strchr(path, '.');
	printf("mknod: %s\n",ext);
	if(ext == NULL){
		writeKeys(keyring,fpath);
	}else if((strstr(ext, ".Trash-") == NULL) && (strstr(ext,".goutputstream") == NULL) && (strstr(ext, ".sharedinfo") == NULL)){	 
		writeKeys(keyring,fpath);
	
	//or whatever extension if fitting
	}
    return retstat;

}

/** Create a directory */
int cs_mkdir(const char *path, mode_t mode)
{   
    int retstat = 0;
    char fpath[PATH_MAX];
    cs_fullpath(fpath, path);

    retstat = mkdir(fpath, mode);
    if (retstat < 0) 
	retstat = -errno;

    return retstat;
}

/** Remove a file */
int cs_unlink(const char *path)
{
   //gives operation not permitted if fullpath is omitted 
    int retstat = 0;
    char fpath[PATH_MAX];
    
    cs_fullpath(fpath, path);
    retstat = unlink(fpath);
    if (retstat < 0) 
	retstat = -errno;
    
    return retstat;
}

/** Remove a directory */
int cs_rmdir(const char *path)
{
    int retstat = 0;
    char fpath[PATH_MAX];
    
    cs_fullpath(fpath, path); 
    retstat = rmdir(fpath);
    if (retstat < 0) 
	retstat = -errno;

    return retstat;
}

/** Create a symbolic link */
// The parameters here are a little bit confusing, but do correspond
// to the symlink() system call.  The 'path' is where the link points,
// while the 'link' is the link itself.  So we need to leave the path
// unaltered, but insert the link into the mounted directory.
int cs_symlink(const char *path, const char *link)
{
    int retstat = 0;
    char fpath[PATH_MAX];
    char flink[PATH_MAX];

    cs_fullpath(fpath, path);
    cs_fullpath(flink, link);
    retstat = symlink(fpath, flink);
    if (retstat < 0) 
	retstat = -errno;
    
    return retstat;
}

/** Rename a file */
// both path and newpath are fs-relative
int cs_rename(const char *path, const char *newpath)
{
    int retstat = 0;
	const char *ext = malloc(8);
	const char *newext = malloc(8);
    char fpath[PATH_MAX];
    char fnewpath[PATH_MAX];
    
    cs_fullpath(fpath, path);
    cs_fullpath(fnewpath, newpath);

    retstat = rename(fpath, fnewpath);  
    
    if (retstat < 0) 
	retstat = -errno;

	ext = strchr(path,'.');
	newext = strchr(newpath, '.');
	if(ext == NULL){
	keyrename(keyring, fpath, fnewpath);
	}else if((strstr(ext, ".Trash-") == NULL) && (strstr(newext, ".Trash-") == NULL)){
    keyrename(keyring, fpath, fnewpath);
	}
	
    return retstat;
}

/** Create a hard link to a file */
int cs_link(const char *path, const char *newpath)
{
    int retstat = 0;
    char fpath[PATH_MAX], fnewpath[PATH_MAX];
    
    cs_fullpath(fpath, path);
    cs_fullpath(fnewpath, newpath);

    retstat = link(fpath, fnewpath);
    if (retstat < 0) 
	retstat = -errno;
    
    return retstat;
}

/** Change the permission bits of a file */
int cs_chmod(const char *path, mode_t mode)
{
    int retstat = 0;
    char fpath[PATH_MAX];
    
    cs_fullpath(fpath, path);

    retstat = chmod(fpath, mode);
    if (retstat < 0) 
	retstat = -errno;
    
    return retstat;
}

/** Change the owner and group of a file */
int cs_chown(const char *path, uid_t uid, gid_t gid)
  
{
    int retstat = 0;
    char fpath[PATH_MAX];
    
    cs_fullpath(fpath, path);

    retstat = chown(fpath, uid, gid);
    if (retstat < 0) 
	retstat = -errno;
    
    return retstat;
}

/** Change the size of a file */
int cs_truncate(const char *path, off_t newsize)
{
    int retstat = 0;
    char fpath[PATH_MAX];
    
    cs_fullpath(fpath, path);

    retstat = truncate(fpath, newsize);
    if (retstat < 0) 
	retstat = -errno;
    
    return retstat;
}

/** Change the access and/or modification times of a file */
/* note -- I'll want to change this as soon as 2.6 is in debian testing */
int cs_utime(const char *path, struct utimbuf *ubuf)
{
    int retstat = 0;
    char fpath[PATH_MAX];
    
    cs_fullpath(fpath, path);
    
    retstat = utime(fpath, ubuf);
    if (retstat < 0) 
	retstat = -errno;
    
    return retstat;
}

/** File open operation
 *
 * No creation, or truncation flags (O_CREAT, O_EXCL, O_TRUNC)
 * will be passed to open().  Open should check if the operation
 * is permitted for the given flags.  Optionally open may also
 * return an arbitrary filehandle in the fuse_file_info structure,
 * which will be passed to all file operations.
 *
 * Changed in version 2.2
 */
int cs_open(const char *path, struct fuse_file_info *fi)
{
    int retstat = 0;
    int fd;
    char fpath[PATH_MAX];
    
    cs_fullpath(fpath, path);

    // if the open call succeeds, my retstat is the file descriptor,
    // else it's -errno.  I'm making sure that in that case the saved
    // file descriptor is exactly -1.
    fd = open(fpath, fi->flags);
    if (fd < 0)
	retstat = -errno;
	
    fi->fh = fd;

    return retstat;
}

/** Read data from an open file
 *
 * Read should return exactly the number of bytes requested except
 * on EOF or error, otherwise the rest of the data will be
 * substituted with zeroes.  An exception to this is when the
 * 'direct_io' mount option is specified, in which case the return
 * value of the read system call will reflect the return value of
 * this operation.
 *
 * Changed in version 2.2
 */
// I don't fully understand the documentation above -- it doesn't
// match the documentation for the read() system call which says it
// can return with anything up to the amount of data requested. nor
// with the fusexmp code which returns the amount of data also
// returned by read.
int cs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{	
	//maybe get newest revision?
	char fpath[PATH_MAX];
    cs_fullpath(fpath, path);
	
	//getCorrectRevision(
    
    // no need to get fpath on this one, since I work from fi->fh not the path

    return pread(fi->fh, buf, size, offset);
}

/** Write data to an open file
 *
 * Write should return exactly the number of bytes requested
 * except on error.  An exception to this is when the 'direct_io'
 * mount option is specified (see read operation).
 *
 * Changed in version 2.2
 */
// As  with read(), the documentation above is inconsistent with the
// documentation for the write() system call.
int cs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    char fpath[PATH_MAX];
    char *ext;
    char *servername;
    cs_fullpath(fpath, path);
    int retstat = 0;
    //upload new version of this file
    // no need to get fpath on this one, since I work from fi->fh not the path
    retstat = pwrite(fi->fh, buf, size, offset);
    if (retstat < 0) 
	retstat = -errno;

    return retstat;
}

/** Get file system statistics
 *
 * The 'f_frsize', 'f_favail', 'f_fsid' and 'f_flag' fields are ignored
 *
 * Replaced 'struct statfs' parameter with 'struct statvfs' in
 * version 2.5
 */
int cs_statfs(const char *path, struct statvfs *statv)
{
    int retstat = 0;
    char fpath[PATH_MAX];
    
    cs_fullpath(fpath, path);
    
    // get stats for underlying filesystem
    retstat = statvfs(fpath, statv);

    if (retstat < 0) 
	retstat = -errno;

    return retstat;
}

/** Possibly flush cached data
 *
 * BIG NOTE: This is not equivalent to fsync().  It's not a
 * request to sync dirty data.
 *
 * Flush is called on each close() of a file descriptor.  So if a
 * filesystem wants to return write errors in close() and the file
 * has cached dirty data, this is a good place to write back data
 * and return any errors.  Since many applications ignore close()
 * errors this is not always useful.
 *
 * NOTE: The flush() method may be called more than once for each
 * open().  This happens if more than one file descriptor refers
 * to an opened file due to dup(), dup2() or fork() calls.  It is
 * not possible to determine if a flush is final, so each flush
 * should be treated equally.  Multiple write-flush sequences are
 * relatively rare, so this shouldn't be a problem.
 *
 * Filesystems shouldn't assume that flush will always be called
 * after some writes, or that if will be called at all.
 *
 * Changed in version 2.2
 */
// this is a no-op in BBFS.  It just logs the call and returns success
int cs_flush(const char *path, struct fuse_file_info *fi)
{
    // no need to get fpath on this one, since I work from fi->fh not the path
	
    return 0;
}

/** Release an open file
 *
 * Release is called when there are no more references to an open
 * file: all file descriptors are closed and all memory mappings
 * are unmapped.
 *
 * For every open() call there will be exactly one release() call
 * with the same flags and file descriptor.  It is possible to
 * have a file opened more than once, in which case only the last
 * release will mean, that no more reads/writes will happen on the
 * file.  The return value of release is ignored.
 *
 * Changed in version 2.2
 */
int cs_release(const char *path, struct fuse_file_info *fi)
{
    int retstat = 0;
    char *ext;
    char *servername;
    char *sharefilepath = malloc(32);
    char fpath[PATH_MAX];
    cs_fullpath(fpath, path);
    // We need to close the file.  Had we allocated any resources
    // (buffers etc) we'd need to free them here as well.
    retstat = close(fi->fh);
    if (retstat < 0) 
		retstat = -errno;
	
	ext = strchr(path,'.');
	if(ext != NULL){
	if((strstr(ext, ".Trash-") == NULL) && (strstr(ext,".goutputstream") == NULL) && (strstr(ext, ".ring") == NULL) && (strstr(ext,".gitignore") == NULL) && (strstr(ext, ".~lock") == NULL) && (strstr(ext, ".share") == NULL)){
	
		struct cryptoKEYS keys = readKeys(keyring, fpath);
		encryptFile(fpath, keys.symmK, keys.IV);

		servername = readServerName(keyring,path,0);
		//check if servername exists
		if(servername == NULL){
			servername = readServerName(keyring,fpath,1);
			char *digest = hashFile(fpath);			
			unsigned char *signature = signFile(keys.privateK,digest);
			upload("/tmp/cryptfile.bin", servername, cookie, token, signature);
			setServerPath(keyring, fpath, ext);
		}
		else{
			char *digest = hashFile(fpath);			
			unsigned char *signature = signFile(keys.privateK,digest);
			upload("/tmp/cryptfile.bin", servername, cookie, token, signature);
		}
	
		sharefilepath = strtok(fpath,"\\");
		if(strstr(path, "_SHAREKEY.xml") != NULL){
			writeSharedKey(sharefilepath, keyring);
		}

	}	
	}
	return retstat;

}

/** Synchronize file contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data.
 *
 * Changed in version 2.2
 */
int cs_fsync(const char *path, int datasync, struct fuse_file_info *fi)
{
    int retstat = 0;
    
    // some unix-like systems (notably freebsd) don't have a datasync call
#ifdef HAVE_FDATASYNC
    if (datasync)
        retstat = fdatasync(fi->fh);
    else
#endif	
	retstat = fsync(fi->fh);

    if (retstat < 0) 
	retstat = -errno;
    
    return retstat;

}

#ifdef HAVE_SYS_XATTR_H
/** Set extended attributes */
int cs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
    int retstat = 0;
    char fpath[PATH_MAX];
    
    cs_fullpath(fpath, path);
    retstat = lsetxattr(fpath, name, value, size, flags);
    if (retstat < 0) 
	retstat = -errno;

    return retstat;
}

/** Get extended attributes */
int cs_getxattr(const char *path, const char *name, char *value, size_t size)
{
    int retstat = 0;
    char fpath[PATH_MAX];
    
    cs_fullpath(fpath, path);

    retstat = lgetxattr(fpath, name, value, size);

    if (retstat < 0) 
	retstat = -errno;
    
    return retstat;
}

/** List extended attributes */
int cs_listxattr(const char *path, char *list, size_t size)
{
    int retstat = 0;
    char fpath[PATH_MAX];
    char *ptr;
    
	    );
    cs_fullpath(fpath, path);

    retstat = llistxattr(fpath, list, size);
    
    if (retstat < 0) 
	retstat = -errno;
    
    return retstat;
}

/** Remove extended attributes */
int cs_removexattr(const char *path, const char *name)
{
    char fpath[PATH_MAX];
    
    cs_fullpath(fpath, path);

    retstat = lremoveexattr(fpath, name);

    if (retstat < 0) 
	retstat = -errno;

    return retstat;
}
#endif

/** Open directory
 *
 * This method should check if the open operation is permitted for
 * this  directory
 *
 * Introduced in version 2.3
 */
int cs_opendir(const char *path, struct fuse_file_info *fi)
{
    DIR *dp;
    int retstat = 0;
    char fpath[PATH_MAX];
    
    cs_fullpath(fpath, path);

    // since opendir returns a pointer, takes some custom handling of
    // return status.
    dp = opendir(fpath);
    if(dp == NULL)
         retstat = -errno;

    fi->fh = (intptr_t) dp;
    
    return retstat;
}

/** Read directory
 *
 * This supersedes the old getdir() interface.  New applications
 * should use this.
 *
 * The filesystem may choose between two modes of operation:
 *
 * 1) The readdir implementation ignores the offset parameter, and
 * passes zero to the filler function's offset.  The filler
 * function will not return '1' (unless an error happens), so the
 * whole directory is read in a single readdir operation.  This
 * works just like the old getdir() method.
 *
 * 2) The readdir implementation keeps track of the offsets of the
 * directory entries.  It uses the offset parameter and always
 * passes non-zero offset to the filler function.  When the buffer
 * is full (or an error happens) the filler function will return
 * '1'.
 *
 * Introduced in version 2.3
 */

int cs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
	       struct fuse_file_info *fi)
{
    int retstat = 0;
    DIR *dp;
    struct dirent *de;
    
    // once again, no need for fullpath -- but note that I need to cast fi->fh
    dp = (DIR *) (uintptr_t) fi->fh;

    // Every directory contains at least two entries: . and ..  If my
    // first call to the system readdir() returns NULL I've got an
    // error; near as I can tell, that's the only condition under
    // which I can get an error from readdir()
    de = readdir(dp);
    if (de == 0) {
        retstat = -errno;
	return retstat;
    }

    // This will copy the entire directory into the buffer.  The loop exits
    // when either the system readdir() returns NULL, or filler()
    // returns something non-zero.  The first case just means I've
    // read the whole directory; the second means the buffer is full.
    do {
	if (filler(buf, de->d_name, NULL, 0) != 0) {
	    return -ENOMEM;
	}
    } while ((de = readdir(dp)) != NULL);
    
    
    return retstat;
}

/** Release directory
 *
 * Introduced in version 2.3
 */
int cs_releasedir(const char *path, struct fuse_file_info *fi)
{
    int retstat = 0;
    
    closedir((DIR *) (uintptr_t) fi->fh);
    
    return retstat;
}

/** Synchronize directory contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data
 *
 * Introduced in version 2.3
 */
// when exactly is this called?  when a user calls fsync and it
// happens to be a directory? ??? >>> I need to implement this...
int cs_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi)
{
    int retstat = 0;
    
    return retstat;
}

/**
 * Initialize filesystem
 *
 * The return value will passed in the private_data field of
 * fuse_context to all file operations and as a parameter to the
 * destroy() method.
 *
 * Introduced in version 2.3
 * Changed in version 2.6
 */
// Undocumented but extraordinarily useful fact:  the fuse_context is
// set up before this function is called, and
// fuse_get_context()->private_data returns the user_data passed to
// fuse_main().  Really seems like either it should be a third
// parameter coming in here, or else the fact should be documented
// (and this might as well return void, as it did in older versions of
// FUSE).
void *cs_init(struct fuse_conn_info *conn)
{
    
    (void)conn;
   
    fuse_get_context();
    return CS_DATA;
}

/**
 * Clean up filesystem
 *
 * Called on filesystem exit.
 *
 * Introduced in version 2.3
 */

/**
 * Check file access permissions
 *
 * This will be called for the access() system call.  If the
 * 'default_permissions' mount option is given, this method is not
 * called.
 *
 * This method is not called under Linux kernel versions 2.4.x
 *
 * Introduced in version 2.5
 */
int cs_access(const char *path, int mask)
{
    int retstat = 0;
    char fpath[PATH_MAX];
   
    cs_fullpath(fpath, path);

   // printf("Path: %s\n", fpath);
    
    retstat = access(fpath, mask);

    if (retstat < 0) 
	retstat = -errno;
    
    return retstat;
}

/**
 * Create and open a file
 *
 * If the file does not exist, first create it with the specified
 * mode, and then open it.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the mknod() and open() methods
 * will be called instead.
 *
 * Introduced in version 2.5
 */
// Not implemented.  I had a version that used creat() to create and
// open the file, which it turned out opened the file write-only.

/**
 * Change the size of an open file
 *
 * This method is called instead of the truncate() method if the
 * truncation was invoked from an ftruncate() system call.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the truncate() method will be
 * called instead.
 *
 * Introduced in version 2.5
 */
int cs_ftruncate(const char *path, off_t offset, struct fuse_file_info *fi)
{
    int retstat = 0;
    
    retstat = ftruncate(fi->fh, offset);

    if (retstat < 0) 
	retstat = -errno;
    
    return retstat;
}

/**
 * Get attributes from an open file
 *
 * This method is called instead of the getattr() method if the
 * file information is available.
 *
 * Currently this is only called after the create() method if that
 * is implemented (see above).  Later it may be called for
 * invocations of fstat() too.
 *
 * Introduced in version 2.5
 */
int cs_fgetattr(const char *path, struct stat *statbuf, struct fuse_file_info *fi)
{
    int retstat = 0;
    
    // On FreeBSD, trying to do anything with the mountpoint ends up
    // opening it, and then using the FD for an fgetattr.  So in the
    // special case of a path of "/", I need to do a getattr on the
    // underlying root directory instead of doing the fgetattr().
    if (!strcmp(path, "/"))
	return cs_getattr(path, statbuf);
    
    retstat = fstat(fi->fh, statbuf);

    if (retstat < 0) 
	retstat = -errno;
    
    return retstat;
}

struct fuse_operations cs_oper = {
  .getattr = cs_getattr,
  .readlink = cs_readlink,
  .mknod = cs_mknod,
  .mkdir = cs_mkdir,
  .unlink = cs_unlink,
  .rmdir = cs_rmdir,
  .symlink = cs_symlink,
  .rename = cs_rename,
  .link = cs_link,
  .chmod = cs_chmod,
  .chown = cs_chown,
  .truncate = cs_truncate,
  .utime = cs_utime,
  .open = cs_open,
  .read = cs_read,
  .write = cs_write,
  .statfs = cs_statfs,
  .flush = cs_flush,
  .release = cs_release,
  .fsync = cs_fsync,
  
#ifdef HAVE_SYS_XATTR_H
  .setxattr = cs_setxattr,
  .getxattr = cs_getxattr,
  .listxattr = cs_listxattr,
  .removexattr = cs_removexattr,
#endif
  
  .opendir = cs_opendir,
  .readdir = cs_readdir,
  .releasedir = cs_releasedir,
  .fsyncdir = cs_fsyncdir,
  .init = cs_init,
  .access = cs_access,
  .ftruncate = cs_ftruncate,
  .fgetattr = cs_fgetattr
};

void cs_usage()
{
    fprintf(stderr, "usage:  bbfs [FUSE and mount options] rootDir mountPoint\n");
    abort();
}

int main(int argc, char *argv[])
{   
    //set session information
    cookie = getSession();
    token = getEditToken(cookie);

    umask(0);
    int fuse_stat;
    struct cs_state *cs_data;

    // bbfs doesn't do any access checking on its own (the comment
    // blocks in fuse.h mention some of the functions that need
    // accesses checked -- but note there are other functions, like
    // chown(), that also need checking!).  Since running bbfs as root
    // will therefore open Metrodome-sized holes in the system
    // security, we'll check if root is trying to mount the filesystem
    // and refuse if it is.  The somewhat smaller hole of an ordinary
    // user doing it with the allow_other flag is still there because
    // I don't want to parse the options string.
    if ((getuid() == 0) || (geteuid() == 0)) {
	fprintf(stderr, "Running BBFS as root opens unnacceptable security holes\n");
	return 1;
    }

    // See which version of fuse we're running
    fprintf(stderr, "Fuse library version %d.%d\n", FUSE_MAJOR_VERSION, FUSE_MINOR_VERSION);
    
    // Perform some sanity checking on the command line:  make sure
    // there are enough arguments, and that neither of the last two
    // start with a hyphen (this will break if you actually have a
    // rootpoint or mountpoint whose name starts with a hyphen, but so
    // will a zillion other programs)
    if ((argc < 3) || (argv[argc-2][0] == '-') || (argv[argc-1][0] == '-'))
	cs_usage();

    cs_data = malloc(sizeof(struct cs_state));
    if (cs_data == NULL) {
	perror("main calloc");
	abort();
    }

    // Pull the rootdir out of the argument list and save it in my
    // internal data
    cs_data->rootdir = realpath(argv[argc-2], NULL);
    argv[argc-2] = argv[argc-1];
    argv[argc-1] = NULL;
    argc--;
    
    char *root = (char *) malloc(32);
    strcpy(root,cs_data->rootdir);
    keyring = strcat(root,"/key.ring");
	if( access( keyring, F_OK ) == -1 ) {
		initkeyring(keyring);
	}
	
    	initFileSystem(keyring, keyring, cs_data->rootdir);
	//load shared keyrings

    // turn over control to fuse
    fprintf(stderr, "about to call fuse_main\n");
    fuse_stat = fuse_main(argc, argv, &cs_oper, cs_data);
    fprintf(stderr, "fuse_main returned %d\n", fuse_stat);
    
    return fuse_stat;
}
