/*
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) Panasas Inc., 2011
 * Author: Jim Lieb jlieb@panasas.com
 *
 * contributeur : Philippe DENIEL   philippe.deniel@cea.fr
 *                Thomas LEIBOVICI  thomas.leibovici@cea.fr
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * ------------- 
 */

/* handle.c
 * VFS object (file|dir) handle object
 */

#include "fsal.h"
#include <libgen.h>             /* used for 'dirname' */
#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include <mntent.h>
#include "nlm_list.h"
#include "fsal_internal.h"
#include "fsal_convert.h"
#include "FSAL/fsal_commonlib.h"
#include "vfs_methods.h"

/* Handle object shared methods vector
 */

static struct fsal_obj_ops obj_ops;

/* helpers
 */

/* alloc_handle
 * allocate and fill in a handle
 * this uses malloc/free for the time being.
 */

static struct vfs_fsal_obj_handle *alloc_handle(struct file_handle *fh,
						fsal_nodetype_t type,
						struct fsal_export *exp_hdl)
{
	struct vfs_fsal_obj_handle *hdl;
	pthread_mutexattr_t attrs;
	int retval;

	hdl = malloc(sizeof(struct vfs_fsal_obj_handle) +
		     sizeof(struct file_handle) +
		     fh->handle_bytes);
	if(hdl == NULL)
		return NULL;
	memset(hdl, 0, (sizeof(struct vfs_fsal_obj_handle) +
			sizeof(struct file_handle) +
			fh->handle_bytes));
	hdl->fd = -1;  /* no open on this yet */
	hdl->obj_handle.export = exp_hdl;
	hdl->obj_handle.refs = 1;  /* we start out with a reference */
	hdl->obj_handle.ops = &obj_ops;
	init_glist(&hdl->obj_handle.handles);
	pthread_mutexattr_settype(&attrs, PTHREAD_MUTEX_ADAPTIVE_NP);
	pthread_mutex_init(&hdl->obj_handle.lock, &attrs);

	/* lock myself before attaching to the export.
	 * keep myself locked until done with creating myself.
	 */

	pthread_mutex_lock(&hdl->obj_handle.lock);
	retval = fsal_attach_handle(exp_hdl, &hdl->obj_handle.handles);
	if(retval != 0)
		goto errout; /* seriously bad */
	hdl->handle = (struct file_handle *)&hdl[1];
	memcpy(hdl->handle, fh,
	       sizeof(struct file_handle) + fh->handle_bytes);
	return hdl;

errout:
	hdl->obj_handle.ops = NULL;
	pthread_mutex_unlock(&hdl->obj_handle.lock);
	pthread_mutex_destroy(&hdl->obj_handle.lock);
	free(hdl);  /* elvis has left the building */
	return NULL;
}

/* private helpers from export
 */

int vfs_get_root_fd(struct fsal_export *exp_hdl);

/* handle methods
 */

/* lookup
 * deprecated NULL parent && NULL path implies root handle
 */

static fsal_status_t lookup(struct fsal_obj_handle *parent,
			    const char *path,
			    struct fsal_obj_handle **handle)
{
	struct vfs_fsal_obj_handle *parent_hdl, *hdl;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	int retval, dirfd, fd;
	int mount_fd;
	int mnt_id = 0;
	struct stat stat;
	struct file_handle *fh
		= alloca(sizeof(struct file_handle) + MAX_HANDLE_SZ);

	if( !path)
		ReturnCode(ERR_FSAL_FAULT, 0);
	mount_fd = vfs_get_root_fd(parent->export);
	parent_hdl = container_of(parent, struct vfs_fsal_obj_handle, obj_handle);
	if( !parent->ops->handle_is(parent, FSAL_TYPE_DIR)) {
		LogCrit(COMPONENT_FSAL,
			"Parent handle is not a directory. hdl = 0x%p",
			parent);
		ReturnCode(ERR_FSAL_NOTDIR, 0);
	}
	dirfd = open_by_handle_at(mount_fd, parent_hdl->handle, O_PATH|O_NOACCESS);
	if(dirfd < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		goto errout;
	}
	retval = name_to_handle_at(dirfd, path, fh, &mnt_id, AT_SYMLINK_FOLLOW);
	if(retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(dirfd);
		goto errout;
	}
	close(dirfd);
	fd = open_by_handle_at(mount_fd, fh, O_PATH|O_NOACCESS);
	if(fd < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		goto errout;
	}
	retval = fstat(fd, &stat);
	if(retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(fd);
		goto errout;
	}
	/* allocate an obj_handle and fill it up */
	hdl = alloc_handle(fh, posix2fsal_type(stat.st_mode), parent->export);
	if(hdl != NULL) {
		*handle = &hdl->obj_handle;
	} else {
		fsal_error = ERR_FSAL_NOMEM;
		*handle = NULL; /* poison it */
		goto errout;
	}
	ReturnCode(ERR_FSAL_NO_ERROR, 0);
	
errout:
	ReturnCode(fsal_error, retval);	
}

/* create
 * create a regular file and set its attributes
 */

static fsal_status_t create(struct fsal_obj_handle *dir_hdl,
			    fsal_name_t *name,
			    fsal_attrib_list_t *attrib,
			    struct fsal_obj_handle **handle)
{
	struct vfs_fsal_obj_handle *myself, *hdl;
	int mnt_id = 0;
	int fd, mount_fd, dir_fd;
	struct stat stat;
	mode_t unix_mode;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	int retval = 0;
	uid_t user;
	gid_t group;
	struct file_handle *fh
		= alloca(sizeof(struct file_handle) + MAX_HANDLE_SZ);

	*handle = NULL; /* poison it */
	if( !dir_hdl->ops->handle_is(dir_hdl, FSAL_TYPE_DIR)) {
		LogCrit(COMPONENT_FSAL,
			"Parent handle is not a directory. hdl = 0x%p",
			dir_hdl);
		ReturnCode(ERR_FSAL_NOTDIR, 0);
	}
	myself = container_of(dir_hdl, struct vfs_fsal_obj_handle, obj_handle);
	mount_fd = vfs_get_root_fd(dir_hdl->export);
	user = attrib->owner;
	group = attrib->group;
	unix_mode = fsal2unix_mode(attrib->mode)
		& ~dir_hdl->export->ops->fs_umask(dir_hdl->export);
	dir_fd = open_by_handle_at(mount_fd, myself->handle, O_PATH|O_NOACCESS);
	if(dir_fd < 0) {
		if(errno == ENOENT)
			fsal_error = ERR_FSAL_STALE;
		else
			fsal_error = posix2fsal_error(errno);
		retval = errno;
		goto errout;
	}
	retval = fstat(dir_fd, &stat);
	if(retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(dir_fd);
		goto errout;
	}
	if(stat.st_mode & S_ISGID)
		group = -1; /*setgid bit on dir propagates dir group owner */

	/* create it with no access because we are root when we do this */
	fd = openat(dir_fd, name->name, O_CREAT|O_WRONLY|O_TRUNC|O_EXCL, 0000);
	if(fd < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(dir_fd);
		goto errout;
	}
	close(dir_fd); /* done with parent */

	retval = fchown(fd, user, group);
	if(retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(fd);
		goto errout;
	}

	/* now that it is owned properly, set to an accessible mode */
	retval = fchmod(fd, unix_mode);
	if(retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(fd);
		goto errout;
	}
	retval = name_to_handle_at(fd, "", fh, &mnt_id, AT_EMPTY_PATH);
	if(retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(fd);
		goto errout;
	}
	close(fd);
	/* allocate an obj_handle and fill it up */
	hdl = alloc_handle(fh, FSAL_TYPE_FILE, dir_hdl->export);
	if(hdl != NULL) {
		*handle = &hdl->obj_handle;
	} else {
		fsal_error = ERR_FSAL_NOMEM;
		goto errout;
	}
	ReturnCode(ERR_FSAL_NO_ERROR, 0);
	
errout:
	ReturnCode(fsal_error, retval);	
}

static fsal_status_t makedir(struct fsal_obj_handle *dir_hdl,
			     fsal_name_t *name,
			     fsal_attrib_list_t *attrib,
			     struct fsal_obj_handle **handle)
{
	struct vfs_fsal_obj_handle *myself, *hdl;
	int mnt_id = 0;
	int fd, mount_fd, dir_fd;
	struct stat stat;
	mode_t unix_mode;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	int retval = 0;
	uid_t user;
	gid_t group;
	struct file_handle *fh
		= alloca(sizeof(struct file_handle) + MAX_HANDLE_SZ);

	*handle = NULL; /* poison it */
	if( !dir_hdl->ops->handle_is(dir_hdl, FSAL_TYPE_DIR)) {
		LogCrit(COMPONENT_FSAL,
			"Parent handle is not a directory. hdl = 0x%p",
			dir_hdl);
		ReturnCode(ERR_FSAL_NOTDIR, 0);
	}
	myself = container_of(dir_hdl, struct vfs_fsal_obj_handle, obj_handle);
	mount_fd = vfs_get_root_fd(dir_hdl->export);
	user = attrib->owner;
	group = attrib->group;
	unix_mode = fsal2unix_mode(attrib->mode)
		& ~dir_hdl->export->ops->fs_umask(dir_hdl->export);
	dir_fd = open_by_handle_at(mount_fd, myself->handle, O_PATH|O_NOACCESS);
	if(dir_fd < 0) {
		if(errno == ENOENT)
			fsal_error = ERR_FSAL_STALE;
		else
			fsal_error = posix2fsal_error(errno);
		retval = errno;
		goto errout;
	}
	retval = fstat(dir_fd, &stat);
	if(retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(dir_fd);
		goto errout;
	}
	if(stat.st_mode & S_ISGID)
		group = -1; /*setgid bit on dir propagates dir group owner */

	/* create it with no access because we are root when we do this */
	retval = mkdirat(dir_fd, name->name, 0000);
	if(retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(dir_fd);
		goto errout;
	}
	fd = openat(dir_fd, name->name, O_RDONLY | O_DIRECTORY);
	if(fd < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(dir_fd);
		goto errout;
	}
	close(dir_fd); /* done with the parent */

	retval = fchown(fd, user, group);
	if(retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(fd);
		goto errout;
	}

	/* now that it is owned properly, set accessible mode */
	retval = fchmod(fd, unix_mode);
	if(retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(fd);
		goto errout;
	}
	retval = name_to_handle_at(fd, "", fh, &mnt_id, AT_EMPTY_PATH);
	if(retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(fd);
		goto errout;
	}
	close(fd);
	/* allocate an obj_handle and fill it up */
	hdl = alloc_handle(fh, FSAL_TYPE_DIR, dir_hdl->export);
	if(hdl != NULL) {
		*handle = &hdl->obj_handle;
	} else {
		fsal_error = ERR_FSAL_NOMEM;
		goto errout;
	}
	ReturnCode(ERR_FSAL_NO_ERROR, 0);
	
errout:
	ReturnCode(fsal_error, retval);	
}

static fsal_status_t makenode(struct fsal_obj_handle *dir_hdl,
			      fsal_name_t *name,
			      fsal_nodetype_t nodetype,  /* IN */
			      fsal_dev_t *dev,  /* IN */
			      fsal_attrib_list_t *attrib,
			      struct fsal_obj_handle **handle)
{
	struct vfs_fsal_obj_handle *myself, *hdl;
	int mnt_id = 0;
	int fd, mount_fd, dir_fd;
	struct stat stat;
	mode_t unix_mode;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	int retval = 0;
	uid_t user;
	gid_t group;
	dev_t unix_dev = 0;
	struct file_handle *fh
		= alloca(sizeof(struct file_handle) + MAX_HANDLE_SZ);

	*handle = NULL; /* poison it */
	if( !dir_hdl->ops->handle_is(dir_hdl, FSAL_TYPE_DIR)) {
		LogCrit(COMPONENT_FSAL,
			"Parent handle is not a directory. hdl = 0x%p",
			dir_hdl);
		ReturnCode(ERR_FSAL_NOTDIR, 0);
	}
	myself = container_of(dir_hdl, struct vfs_fsal_obj_handle, obj_handle);
	mount_fd = vfs_get_root_fd(dir_hdl->export);
	user = attrib->owner;
	group = attrib->group;
	unix_mode = fsal2unix_mode(attrib->mode)
		& ~dir_hdl->export->ops->fs_umask(dir_hdl->export);
	switch (nodetype) {
	case FSAL_TYPE_BLK:
		if( !dev) {
			fsal_error = ERR_FSAL_FAULT;
			goto errout;
		}
		unix_mode |= S_IFBLK;
		unix_dev = makedev(dev->major, dev->minor);
		break;
	case FSAL_TYPE_CHR:
		if( !dev) {
			fsal_error = ERR_FSAL_FAULT;
			goto errout;
		}
		unix_mode |= S_IFCHR;
		unix_dev = makedev(dev->major, dev->minor);
		break;
	case FSAL_TYPE_SOCK:
		unix_mode |= S_IFSOCK;
		break;
	case FSAL_TYPE_FIFO:
		unix_mode |= S_IFIFO;
		break;
	default:
		LogMajor(COMPONENT_FSAL,
			 "Invalid node type in FSAL_mknode: %d",
			 nodetype);
		fsal_error = ERR_FSAL_INVAL;
		goto errout;
	}
	dir_fd = open_by_handle_at(mount_fd, myself->handle, O_PATH|O_NOACCESS);
	if(dir_fd < 0) {
		if(errno == ENOENT)
			fsal_error = ERR_FSAL_STALE;
		else
			fsal_error = posix2fsal_error(errno);
		retval = errno;
		goto errout;
	}
	retval = fstat(dir_fd, &stat);
	if(retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(dir_fd);
		goto errout;
	}
	if(stat.st_mode & S_ISGID)
		group = -1; /*setgid bit on dir propagates dir group owner */

	/* create it with no access because we are root when we do this */
	fd = mknodat(dir_fd, name->name, 0000, unix_dev);
	if(fd < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(dir_fd);
		goto errout;
	}
	close(dir_fd); /* done with parent */

	retval = fchown(fd, user, group);
	if(retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(fd);
		goto errout;
	}

	/* now that it is owned properly, set accessible mode */
	retval = fchmod(fd, unix_mode);
	if(retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(fd);
		goto errout;
	}
	retval = name_to_handle_at(fd, "", fh, &mnt_id, AT_EMPTY_PATH);
	if(retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(fd);
		goto errout;
	}
	close(fd);
	/* allocate an obj_handle and fill it up */
	hdl = alloc_handle(fh, nodetype, dir_hdl->export);
	if(hdl != NULL) {
		*handle = &hdl->obj_handle;
	} else {
		fsal_error = ERR_FSAL_NOMEM;
		goto errout;
	}
	ReturnCode(ERR_FSAL_NO_ERROR, 0);
	
errout:
	ReturnCode(fsal_error, retval);	
}

static fsal_status_t makesymlink(struct fsal_obj_handle *dir_hdl,
				 fsal_name_t *name,
				 fsal_path_t *link_path,
				 fsal_attrib_list_t *attrib,
				 struct fsal_obj_handle **handle)
{
	struct vfs_fsal_obj_handle *myself, *hdl;
	int mnt_id = 0;
	int fd, mount_fd, dir_fd;
	struct stat stat;
	mode_t unix_mode;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	int retval = 0;
	uid_t user;
	gid_t group;
	struct file_handle *fh
		= alloca(sizeof(struct file_handle) + MAX_HANDLE_SZ);

	*handle = NULL; /* poison it */
	if( !dir_hdl->ops->handle_is(dir_hdl, FSAL_TYPE_DIR)) {
		LogCrit(COMPONENT_FSAL,
			"Parent handle is not a directory. hdl = 0x%p",
			dir_hdl);
		ReturnCode(ERR_FSAL_NOTDIR, 0);
	}
	myself = container_of(dir_hdl, struct vfs_fsal_obj_handle, obj_handle);
	mount_fd = vfs_get_root_fd(dir_hdl->export);
	user = attrib->owner;
	group = attrib->group;
	unix_mode = fsal2unix_mode(attrib->mode)
		& ~dir_hdl->export->ops->fs_umask(dir_hdl->export);
	dir_fd = open_by_handle_at(mount_fd, myself->handle, O_PATH|O_NOACCESS);
	if(dir_fd < 0) {
		if(errno == ENOENT)
			fsal_error = ERR_FSAL_STALE;
		else
			fsal_error = posix2fsal_error(errno);
		retval = errno;
		goto errout;
	}
	retval = fstat(dir_fd, &stat);
	if(retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(dir_fd);
		goto errout;
	}
	if(stat.st_mode & S_ISGID)
		group = -1; /*setgid bit on dir propagates dir group owner */

	/* create it with no access because we are root when we do this */
	retval = symlinkat(link_path->path, dir_fd, name->name);
	if(retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(dir_fd);
		goto errout;
	}
	retval = fchownat(dir_fd, name->name, user, group, AT_SYMLINK_NOFOLLOW);
	if(retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(fd);
		goto errout;
	}
	fd = openat(dir_fd, name->name, O_RDONLY);
	if(fd < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(dir_fd);
		goto errout;
	}
	close(dir_fd); /* done with parent */

	/* now that it is owned properly, set accessible mode */
	retval = fchmod(fd, unix_mode);
	if(retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(fd);
		goto errout;
	}
	retval = name_to_handle_at(fd, "", fh, &mnt_id, AT_EMPTY_PATH);
	if(retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(fd);
		goto errout;
	}
	close(fd);
	/* allocate an obj_handle and fill it up */
	hdl = alloc_handle(fh, FSAL_TYPE_DIR, dir_hdl->export);
	if(hdl != NULL) {
		*handle = &hdl->obj_handle;
	} else {
		fsal_error = ERR_FSAL_NOMEM;
		*handle = NULL; /* poison it */
		goto errout;
	}
	ReturnCode(ERR_FSAL_NO_ERROR, 0);
	
errout:
	ReturnCode(fsal_error, retval);	
}

static fsal_status_t readsymlink(struct fsal_obj_handle *obj_hdl,
				 char *link_content,
				 uint32_t max_len)
{
	struct vfs_fsal_obj_handle *myself;
	int fd, mntfd;
	int retval = 0;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	fsal_status_t status;

	myself = container_of(obj_hdl, struct vfs_fsal_obj_handle, obj_handle);
	mntfd = vfs_get_root_fd(obj_hdl->export);
	fd = open_by_handle_at(mntfd, myself->handle, (O_PATH|O_NOACCESS));
	if(fd < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		goto out;
	}
        retval = readlinkat(fd, "", link_content, max_len);
	if(retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(fd);
		goto out;
	}
        close(fd);
	
out:
	ReturnCode(fsal_error, retval);	
}

static fsal_status_t linkfile(struct fsal_obj_handle *obj_hdl,
			      struct fsal_obj_handle *destdir_hdl,
			      fsal_name_t *name)
{
	struct vfs_fsal_obj_handle *myself, *destdir;
	int srcfd, destdirfd, mntfd;
	int retval = 0;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	fsal_status_t status;
	char procpath[FSAL_MAX_PATH_LEN];
	char linkpath[FSAL_MAX_PATH_LEN];

	if( !obj_hdl->export->ops->fs_supports(obj_hdl->export, link_support)) {
		fsal_error = ERR_FSAL_NOTSUPP;
		goto out;
	}
	myself = container_of(obj_hdl, struct vfs_fsal_obj_handle, obj_handle);
	mntfd = vfs_get_root_fd(obj_hdl->export);
	srcfd = open_by_handle_at(mntfd, myself->handle, (O_PATH|O_NOACCESS));
	if(srcfd < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		goto out;
	}
	destdir = container_of(destdir_hdl, struct vfs_fsal_obj_handle, obj_handle);
	destdirfd = open_by_handle_at(mntfd, destdir->handle, (O_PATH|O_NOACCESS));
	if(destdirfd < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(srcfd);
		goto out;
	}
	snprintf(procpath, FSAL_MAX_PATH_LEN, "/proc/%u/fd/%u", getpid(), srcfd);
	retval = readlink(procpath, linkpath, FSAL_MAX_PATH_LEN);
	if(reval == -1) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		goto cleanup;
	} else if(retval == FSAL_MAX_PATH_LEN) { /* unlikely overflow */
		fsal_error = posix2fsal_error(EOVERFLOW);
		retval = EOVERFLOW;
		goto cleanup;
	}
	retval = linkat(0, linkpath, destdirfd, name->name, 0);
	if(reval == -1) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
	}

cleanup:
	close(srcfd);
	close(destfd);
out:
	ReturnCode(fsal_error, retval);	
}

#define BUF_SIZE 1024
/**
 * read_dirents
 * read the directory and call through the callback function for
 * each entry.
 * @param dir_hdl [IN] the directory to read
 * @param entry_cnt [IN] limit of entries. 0 implies no limit
 * @param whence [IN] where to start (next)
 * @param dir_state [IN] pass thru of state to callback
 * @param cb [IN] callback function
 * @param eof [OUT] eof marker TRUE == end of dir
 */

static fsal_status_t read_dirents(struct fsal_obj_handle *dir_hdl,
				  uint32_t entry_cnt,
				  struct fsal_cookie *whence,
				  void *dir_state,
				  fsal_status_t (*cb)(
					  const char *name;
					  struct fsal_obj_handle *dir_hdl,
					  void *dir_state,
					  struct fsal_cookie *cookie),
				  fsal_boolean_t *eof)
{
	struct vfs_fsal_obj_handle *myself *entry;
	int dirfd, mntfd;
	struct stat stat;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	fsal_status_t status;
	int retval = 0;
	off_t seekloc = 0;
	int bpos, cnt, nread;
	unsigned char dtype;
	struct linux_dirent *dentry;
	struct fsal_cookie *entry_cookie;
	char buf[BUF_SIZE];

	if(whence != NULL) {
		if(whence->size != sizeof(off_t)) {
			fsal_error = posix2fsal_error(EINVAL);
			retval = errno;
			goto out;
		}
		memcpy(seekloc, whence->cookie, sizeof(off_t));
	}
	entry_cookie = alloca(sizeof(struct fsal_cookie) + sizeof(off_t));
	myself = container_of(dir_hdl, struct vfs_fsal_obj_handle, obj_handle);
	mntfd = vfs_get_root_fd(dir_hdl->export);
	dirfd = open_by_handle_at(mntfd, myself->handle, (O_RDONLY|_DIRECTORY));
	if(dirfd < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		goto out;
	}
	seekloc = lseek(dirfd, seekloc, SEEK_SET);
	if(seekloc < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		goto done;
	}
	cnt = 0;
	do {
		nread = syscall(SYS_getdents, dirfd, buf, BUF_SIZE);
		if(nread < 0) {
			fsal_error = posix2fsal_error(errno);
			retval = errno;
			goto done;
		}
		if(nread == 0)
			break;
		for(bpos = 0; bpos < nread;) {
			dentry = (struct linux_dirent *)(buf + bpos);
			if(strcmp(dentry->name, ".") == 0 ||
			   strcmp(dentry->name, "..") == 0)
				continue; /* must skip '.' and '..' */
			d_type = *(buf + bpos + dentry->d_reclen - 1);
			entry_cookie->size = sizeof(off_t);
			memcpy(entry_cookie->cookie, &dentry->d_off, sizeof(off_t));

			/* callback to cache inode */
			status = cb(dentry->name, dir_hdl,
				    dir_state, &entry_cookie);
			if(FSAL_IS_ERROR(status)) {
				fsal_error = status.major;
				retval = status.minor;
				goto done;
			}
			cnt++;
			if(entry_cnt > 0 && cnt >= entry_cnt)
				goto done;
		}
	} while(nread > 0);

done:
	close(dirfd);
	*eof = nread == 0 ? TRUE : FALSE;
	
out:
	ReturnCode(fsal_error, retval);	
}


static fsal_status_t renamefile(struct fsal_obj_handle *olddir_hdl,
				fsal_name_t *old_name,
				struct fsal_obj_handle *newdir_hdl,
				fsal_name_t *new_name)
{
	struct vfs_fsal_obj_handle *olddir, *newdir;
	int oldfd, newfd, mntfd;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	int retval = 0;

	olddir = container_of(olddir_hdl, struct vfs_fsal_obj_handle, obj_handle);
	mntfd = vfs_get_root_fd(obj_hdl->export);
	oldfd = open_by_handle_at(mntfd, olddir->handle, (O_PATH|O_NOACCESS));
	if(oldfd < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		goto out;
	}
	newdir = container_of(newdir_hdl, struct vfs_fsal_obj_handle, obj_handle);
	newfd = open_by_handle_at(mntfd, newdir->handle, (O_PATH|O_NOACCESS));
	if(newfd < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(oldfd);
		goto out;
	}
	retval = renameat(oldfd, old_name->name, newfd, new_name->name);
	if(retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
	}
	close(oldfd);
	close(newfd);
out:
	ReturnCode(fsal_error, retval);	
}

/* FIXME:  attributes are now merged into fsal_obj_handle.  This
 * spreads everywhere these methods are used.
 */

static fsal_status_t getattrs(struct fsal_obj_handle *obj_hdl,
			      fsal_attrib_list_t *obj_attr)
{
	struct vfs_fsal_obj_handle *myself;
	int fd, mntfd;
	struct stat stat;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	fsal_status_t st;
	int retval = 0;

	myself = container_of(obj_hdl, struct vfs_fsal_obj_handle, obj_handle);
	mntfd = vfs_get_root_fd(obj_hdl->export);
	fd = open_by_handle_at(mntfd, myself->handle, (O_PATH|O_NOACCESS));
	if(fd < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		goto out;
	}
	retval = fstat(fd, &stat);
	if(retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(fd);
		goto out;
	}
	close(fd);
	/* convert attributes */
	st = posix2fsal_attributes(&stat, obj_attr);
	if(FSAL_IS_ERROR(st)) {
		FSAL_CLEAR_MASK(obj_attr->asked_attributes);
		FSAL_SET_MASK(obj_attr->asked_attributes,
			      FSAL_ATTR_RDATTR_ERR);
		return st;
	}
	
out:
	ReturnCode(fsal_error, retval);	
}

static fsal_status_t setattrs(struct fsal_obj_handle *obj_hdl,
			      fsal_attrib_list_t *attrib_set)
{
	struct vfs_fsal_obj_handle *myself;
	int fd, mntfd;
	struct stat stat;
	fsal_attrib_list_t attrs = *attrib_set;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	int retval = 0;

	/* apply umask, if mode attribute is to be changed */
	if(FSAL_TEST_MASK(attrs.asked_attributes, FSAL_ATTR_MODE)) {
		attrs.mode
			&= ~obj_hdl->export->ops->fs_umask(obj_hdl->export);
	}
	myself = container_of(obj_hdl, struct vfs_fsal_obj_handle, obj_handle);
	mntfd = vfs_get_root_fd(obj_hdl->export);
	fd = open_by_handle_at(mntfd, myself->handle, (O_PATH|O_NOACCESS));
	if(fd < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		goto out;
	}
	retval = fstat(fd, &stat);
	if(retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(fd);
		goto out;
	}
	/** CHMOD **/
	if(FSAL_TEST_MASK(attrs.asked_attributes, FSAL_ATTR_MODE)) {
		/* The POSIX chmod call doesn't affect the symlink object, but
		 * the entry it points to. So we must ignore it.
		 */
		if(!S_ISLNK(stat.st_mode)) {
			retval = fchmod(fd, fsal2unix_mode(attrs.mode));
			if(retval != 0) {
				retval = errno;
				close(fd);
				fsal_error = posix2fsal_error(retval);
				goto out;
			}
		}
	}

	/**  CHOWN  **/
	if(FSAL_TEST_MASK(attrs.asked_attributes, FSAL_ATTR_OWNER | FSAL_ATTR_GROUP)) {
		/*      LogFullDebug(COMPONENT_FSAL, "Performing chown(%s, %d,%d)",
                        fsalpath.path, FSAL_TEST_MASK(attrs.asked_attributes,
                                                      FSAL_ATTR_OWNER) ? (int)attrs.owner
                        : -1, FSAL_TEST_MASK(attrs.asked_attributes,
			FSAL_ATTR_GROUP) ? (int)attrs.group : -1);*/

		retval = fchown(fd,
				FSAL_TEST_MASK(attrs.asked_attributes,
					       FSAL_ATTR_OWNER) ? (int)attrs.owner : -1,
				FSAL_TEST_MASK(attrs.asked_attributes,
					       FSAL_ATTR_GROUP) ? (int)attrs.group : -1);
		if(retval) {
			fsal_error = posix2fsal_error(errno);
			retval = errno;
			close(fd);
			goto out;
		}
	}

	/**  UTIME  **/
	if(FSAL_TEST_MASK(attrs.asked_attributes, FSAL_ATTR_ATIME | FSAL_ATTR_MTIME)) {
		struct timeval timebuf[2];

		/* Atime */
		timebuf[0].tv_sec =
			(FSAL_TEST_MASK(attrs.asked_attributes, FSAL_ATTR_ATIME) ?
			 (time_t) attrs.atime.seconds : stat.st_atime);
		timebuf[0].tv_usec = 0;

		/* Mtime */
		timebuf[1].tv_sec =
			(FSAL_TEST_MASK(attrs.asked_attributes, FSAL_ATTR_MTIME) ?
			 (time_t) attrs.mtime.seconds : stat.st_mtime);
		timebuf[1].tv_usec = 0;
		retval = futimes(fd, timebuf);
		if(retval) {
			fsal_error = posix2fsal_error(errno);
			retval = errno;
			close(fd);
			goto out;
		}
	}
	close(fd); /* consolidate goto out to here... */
	
out:
	ReturnCode(fsal_error, retval);	
}

/* handle_is
 * test the type of this handle
 */

static fsal_boolean_t handle_is(struct fsal_obj_handle *obj_hdl,
				fsal_nodetype_t type)
{
	return obj_hdl->type == type;
}

/* compare
 * compare two handles.
 * return 0 for equal, -1 for anything else
 */
/* NOTE: this api may have to be changed to instead of comparing
 * two fsal_obj_handles, a somewhat silly idea when you think about it,
 * to comparing the handle to a "buffer" containing the protocol handle
 * this is used to validate hits into hash buckets.
 */
static fsal_boolean_t compare(struct fsal_obj_handle *obj_hdl,
			      struct fsal_obj_handle *other_hdl)
{
	struct vfs_fsal_obj_handle *myself, *other;

	if( !other_hdl)
		return FALSE;
	myself = container_of(obj_hdl, struct vfs_fsal_obj_handle, obj_handle);
	other = container_of(other_hdl, struct vfs_fsal_obj_handle, obj_handle);
	if((obj_hdl->type != other_hdl->type) ||
	   (myself->handle->handle_type != other->handle->handle_type) ||
	   (myself->handle->handle_bytes != other->handle->handle_bytes))
		return FALSE;
	return memcmp(myself->handle->f_handle,
		      other->handle->f_handle,
		      myself->handle->handle_bytes) ? FALSE : TRUE;
}

/* handle_to_hashidx
 * Generate a table hash for this handle
 */

static unsigned int handle_to_hashidx(struct fsal_obj_handle *obj_hdl,
				      unsigned int cookie,
				      unsigned int alphabet_len,
				      unsigned int index_size)
{
	struct vfs_fsal_obj_handle *myself;
	unsigned int cpt = 0;
	unsigned int sum = 0;
	unsigned int extract = 0;
	unsigned int mod;

	myself = container_of(obj_hdl, struct vfs_fsal_obj_handle, obj_handle);
	mod = myself->handle->handle_bytes % sizeof(unsigned int);
	sum = cookie;
	for(cpt = 0;
	    cpt < myself->handle->handle_bytes - mod;
	    cpt += sizeof(unsigned int)) {
		memcpy(&extract,
		       &(myself->handle->f_handle[cpt]),
		       sizeof(unsigned int));
		sum = (3 * sum + 5 * extract + 1999) % index_size;
	}
	if(mod) {     /* odd number of bytes, byte at at time */
		extract = 0;
		for(cpt = myself->handle->handle_bytes - mod;
		    cpt < myself->handle->handle_bytes; cpt++ ) {
			/* shift of 1 byte */
			extract <<= 8;
			extract |= (unsigned int)myself->handle->f_handle[cpt];
		}
		sum = (3 * sum + 5 * extract + 1999) % index_size;
	}
	return sum;
}

/* handle_to_rbtidx
 * return a red-black tree hash for the handle
 */

static unsigned int handle_to_rbtidx(struct fsal_obj_handle *obj_hdl,
				     unsigned int cookie)
{
	struct vfs_fsal_obj_handle *myself;
	unsigned int h = 0;
	unsigned int cpt = 0;
	unsigned int extract = 0;
	unsigned int mod;

	myself = container_of(obj_hdl, struct vfs_fsal_obj_handle, obj_handle);
	h = cookie;
	mod = myself->handle->handle_bytes % sizeof(unsigned int);
	for(cpt = 0;
	    cpt < myself->handle->handle_bytes - mod;
	    cpt += sizeof(unsigned int)) {
		memcpy(&extract,
		       &(myself->handle->f_handle[cpt]),
		       sizeof(unsigned int));
		h = (857 * h ^ extract) % 715827883;
	}
	if(mod) {
		extract = 0;
		for(cpt = myself->handle->handle_bytes - mod;
		    cpt < myself->handle->handle_bytes;
		    cpt++) {
			/* shift of 1 byte */
			extract <<= 8;
			extract |= (unsigned int)myself->handle->f_handle[cpt];
		}
		h = (857 * h ^ extract) % 715827883;
	}
	return h;
}

/* file_truncate
 * truncate a file to the size specified.
 * size should really be off_t...
 */

static fsal_status_t file_truncate(struct fsal_obj_handle *obj_hdl,
				   fsal_size_t length)
{
	struct vfs_fsal_obj_handle *myself;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	int mnt_id = 0;
	int fd, mount_fd;
	int retval = 0;

	myself = container_of(obj_hdl, struct vfs_fsal_obj_handle, obj_handle);
	mount_fd = vfs_get_root_fd(obj_hdl->export);
	fd = open_by_handle_at(mount_fd, myself->handle, O_PATH|O_RDWR);
	if(fd < 0) {
		if(errno == ENOENT)
			fsal_error = ERR_FSAL_STALE;
		else
			fsal_error = posix2fsal_error(errno);
		retval = errno;
		goto errout;
	}
	retval = ftruncate(fd, length);
	if(retval) {
		retval = errno;
		fsal_error = posix2fsal_error(retval);
		goto errout;
	}
	
errout:
	ReturnCode(fsal_error, retval);	
}

/* file_unlink
 * unlink the named file in the directory
 */

static fsal_status_t file_unlink(struct fsal_obj_handle *dir_hdl,
				 fsal_name_t *name)
{
	struct vfs_fsal_obj_handle *myself;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	struct stat stat;
	int mnt_id = 0;
	int fd, mount_fd;
	int retval = 0;

	myself = container_of(dir_hdl, struct vfs_fsal_obj_handle, obj_handle);
	mount_fd = vfs_get_root_fd(dir_hdl->export);
	fd = open_by_handle_at(mount_fd, myself->handle, O_PATH|O_RDWR);
	if(fd < 0) {
		if(errno == ENOENT)
			fsal_error = ERR_FSAL_STALE;
		else
			fsal_error = posix2fsal_error(errno);
		retval = errno;
		goto errout;
	}
	retval = fstatat(fd, name->name, &stat, AT_SYMLINK_NOFOLLOW);
	if(retval < 0) {
		if(errno == ENOENT)
			fsal_error = ERR_FSAL_STALE;
		else
			fsal_error = posix2fsal_error(errno);
		retval = errno;
		goto errout;
	}
	retval = unlinkat(fd, name->name,
			  (S_ISDIR(stat.st_mode)) ? AT_REMOVEDIR : 0);
	if(retval < 0) {
		if(errno == ENOENT)
			fsal_error = ERR_FSAL_STALE;
		else
			fsal_error = posix2fsal_error(errno);
		retval = errno;
		goto errout;
	}
	
errout:
	ReturnCode(fsal_error, retval);	
}


/* handle_digest
 * fill in the opaque f/s file handle part.
 * we zero the buffer to length first.  This MAY already be done above
 * at which point, remove memset here because the caller is zeroing
 * the whole struct.
 */

static fsal_status_t handle_digest(struct fsal_obj_handle *obj_hdl,
				   fsal_digesttype_t output_type,
				   caddr_t out_buff)
{
	uint32_t ino32;
	uint64_t ino64;
	struct vfs_fsal_obj_handle *myself;
	struct file_handle *fh;
	size_t handle_size;

	myself = container_of(obj_hdl, struct vfs_fsal_obj_handle, obj_handle);
	fh = myself->handle;
	handle_size = sizeof(struct file_handle) + fh->handle_bytes;

	switch(output_type) {
	case FSAL_DIGEST_NFSV2:
		if(handle_size > FSAL_DIGEST_SIZE_HDLV2)
			ReturnCode(ERR_FSAL_TOOSMALL, 0);
		memset(out_buff, 0, FSAL_DIGEST_SIZE_HDLV2);
		memcpy(out_buff, fh, handle_size);
		break;
	case FSAL_DIGEST_NFSV3:
		if(handle_size > FSAL_DIGEST_SIZE_HDLV3)
			ReturnCode(ERR_FSAL_TOOSMALL, 0);
		memset(out_buff, 0, FSAL_DIGEST_SIZE_HDLV3);
		memcpy(out_buff, fh, handle_size) ;
		break;
	case FSAL_DIGEST_NFSV4:
		if(handle_size > FSAL_DIGEST_SIZE_HDLV4)
			ReturnCode(ERR_FSAL_TOOSMALL, 0);
		memset(out_buff, 0, FSAL_DIGEST_SIZE_HDLV4);
		memcpy(out_buff, fh, handle_size) ;
		break;
	case FSAL_DIGEST_FILEID2:
		memset(out_buff, 0, FSAL_DIGEST_SIZE_FILEID2);
		memcpy(out_buff, fh->f_handle, FSAL_DIGEST_SIZE_FILEID2);
		break;
	case FSAL_DIGEST_FILEID3:
		memset(out_buff, 0, FSAL_DIGEST_SIZE_FILEID3);
		memcpy(&ino32, fh->f_handle, sizeof(ino32));
		ino64 = ino32;
		memcpy(out_buff, &ino64, FSAL_DIGEST_SIZE_FILEID3);
		break;
	case FSAL_DIGEST_FILEID4:
		memset(out_buff, 0, FSAL_DIGEST_SIZE_FILEID4);
		memcpy(&ino32, fh->f_handle, sizeof(ino32));
		ino64 = ino32;
		memcpy(out_buff, &ino64, FSAL_DIGEST_SIZE_FILEID4);
		break;
	default:
		ReturnCode(ERR_FSAL_SERVERFAULT, 0);
	}
	ReturnCode(ERR_FSAL_NO_ERROR, 0);
}

/*
 * release
 * release our export first so they know we are gone
 */

static fsal_status_t release(struct fsal_obj_handle *obj_hdl)
{
	struct fsal_export *exp = obj_hdl->export;
	struct vfs_fsal_obj_handle *myself;
	int retval = 0;

	pthread_mutex_lock(&obj_hdl->lock);
	if(obj_hdl->refs != 0) {
		pthread_mutex_unlock(&obj_hdl->lock);
		retval = obj_hdl->refs > 0 ? EBUSY : EINVAL;
		LogCrit(COMPONENT_FSAL,
			"Tried to release busy handle, hdl = 0x%p->refs = %d",
			obj_hdl, obj_hdl->refs);
		ReturnCode(posix2fsal_error(retval), retval);
	}
	fsal_detach_handle(exp, &obj_hdl->handles);
	pthread_mutex_unlock(&obj_hdl->lock);
	myself = container_of(obj_hdl, struct vfs_fsal_obj_handle, obj_handle);
	pthread_mutex_destroy(&obj_hdl->lock);
	myself->obj_handle.ops = NULL; /*poison myself */
	myself->obj_handle.export = NULL;
	free(myself);
	ReturnCode(ERR_FSAL_NO_ERROR, 0);
}

static struct fsal_obj_ops obj_ops = {
	.get = fsal_handle_get,
	.put = fsal_handle_put,
	.release = release,
	.lookup = lookup,
	.readdir = read_dirents,
	.create = create,
	.mkdir = makedir,
	.mknode = makenode,
	.symlink = makesymlink,
	.readlink = readsymlink,
	.test_access = fsal_test_access,
	.getattrs = getattrs,
	.setattrs = setattrs,
	.link = linkfile,
	.rename = renamefile,
	.unlink = file_unlink,
	.truncate = file_truncate,
	.open = vfs_open,
	.open_by_name = vfs_open_by_name,
	.read = vfs_read,
	.write = vfs_write,
	.commit = vfs_commit,
	.lock_op = vfs_lock_op,
	.close = vfs_close,
	.rcp = vfs_rcp,
	.rcp_by_name = vfs_rcp_by_name,
	.handle_is = handle_is,
	.compare = compare,
	.handle_to_hashidx = handle_to_hashidx,
	.handle_to_rbtidx = handle_to_rbtidx,
	.handle_digest = handle_digest,
};

/* export methods that create object handles
 */

/* lookup_path
 * modeled on old api except we don't stuff attributes.
 * KISS
 */

fsal_status_t vfs_lookup_path(struct fsal_export *exp_hdl,
			      fsal_path_t *path,
			      struct fsal_obj_handle **handle)
{
	int fd;
	int mnt_id = 0;
	struct stat stat;
	struct vfs_fsal_obj_handle *hdl;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	int retval = 0;
	struct file_handle *fh
		= alloca(sizeof(struct file_handle) + MAX_HANDLE_SZ);

	if(path->path[0] != '/') {
		fsal_error = ERR_FSAL_INVAL;
		goto errout;
	}
	fd = open(path->path, O_RDONLY, 0600);
	if(fd < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		goto errout;
	}
	retval = fstat(fd, &stat);
	if(fd < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		goto errout;
	}
	retval = name_to_handle_at(fd, "", fh, &mnt_id, AT_EMPTY_PATH);
	if(retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(fd);
		goto errout;
	}
	close(fd);
	/* allocate an obj_handle and fill it up */
	hdl = alloc_handle(fh, posix2fsal_type(stat.st_mode), exp_hdl);
	if(hdl != NULL) {
		*handle = &hdl->obj_handle;
	} else {
		fsal_error = ERR_FSAL_NOMEM;
		*handle = NULL; /* poison it */
		goto errout;
	}
	ReturnCode(ERR_FSAL_NO_ERROR, 0);
	
errout:
	ReturnCode(fsal_error, retval);	
}

/* create_handle
 * Does what original FSAL_ExpandHandle did (sort of)
 * returns a ref counted handle to be later used in cache_inode etc.
 * NOTE! you must release this thing when done with it!
 */

fsal_status_t vfs_create_handle(struct fsal_export *exp_hdl,
			       fsal_digesttype_t in_type,
			       caddr_t in_buff,
			       struct fsal_obj_handle **handle)
{
	struct vfs_fsal_obj_handle *hdl;
	size_t handle_size;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	int retval = 0;
	int fd;
	int mount_fd = vfs_get_root_fd(exp_hdl);

	struct stat stat;
	struct file_handle  *fh
		= alloca(sizeof(struct file_handle) + MAX_HANDLE_SZ);

	*handle = NULL; /* poison it first */
	if(in_buff == NULL)
		ReturnCode(ERR_FSAL_FAULT, 0);
	handle_size = sizeof(struct file_handle) + MAX_HANDLE_SZ;
	memset(fh, 0, handle_size);
	switch (in_type) {
	case FSAL_DIGEST_NFSV2:  /* NFSV2 handle digest */
		if(handle_size < FSAL_DIGEST_SIZE_HDLV2) {
			fsal_error = ERR_FSAL_TOOSMALL;
			goto errout;
		}
		memcpy(fh, in_buff, FSAL_DIGEST_SIZE_HDLV2);
		break;
	case FSAL_DIGEST_NFSV3:  /* NFSV3 handle digest */
		if(handle_size < FSAL_DIGEST_SIZE_HDLV3) {
			fsal_error = ERR_FSAL_TOOSMALL;
			goto errout;
		}
		memcpy(fh, in_buff, FSAL_DIGEST_SIZE_HDLV3);
		break;
	case FSAL_DIGEST_NFSV4:  /* NFSV4 handle digest */
		if(handle_size < FSAL_DIGEST_SIZE_HDLV4) {
			fsal_error = ERR_FSAL_TOOSMALL;
			goto errout;
		}
		memcpy(fh, in_buff, FSAL_DIGEST_SIZE_HDLV4);
		break;
	default:
		fsal_error = ERR_FSAL_SERVERFAULT;
		goto errout;
	}
	fd = open_by_handle_at(mount_fd, fh, O_PATH|O_NOACCESS);
	if(fd < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		goto errout;
	}
	retval = fstat(fd, &stat);
	if(retval < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		close(fd);
		goto errout;
	}
	close(fd);
	hdl = alloc_handle(fh, posix2fsal_type(stat.st_mode), exp_hdl);
	if(hdl == NULL) {
		fsal_error = ERR_FSAL_NOMEM;
		goto errout;
	}
	*handle = &hdl->obj_handle;
	
errout:
	ReturnCode(fsal_error, retval);	
}

