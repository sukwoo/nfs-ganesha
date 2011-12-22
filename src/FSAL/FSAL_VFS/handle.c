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

/*
 * VFS internal object handle
 * handle is a pointer because
 *  a) the last element of file_handle is a char[] meaning variable len...
 *  b) we cannot depend on it *always* being last or being the only
 *     variable sized struct here...  a pointer is safer.
 */

struct vfs_fsal_obj_handle {
	struct fsal_obj_handle obj_handle;
	struct file_handle *handle;
};

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

/* setattrs  INCOMPLETE
 * set file attributes.  Do getattr and access testing before you get here.
 * original only checked mode, not acls! 
 * unresolved: global fs permissions i.e. cansettime???
 *             attributes and credentials checking.
 */

static fsal_status_t setattrs(struct fsal_obj_handle *obj_hdl,
			  fsal_attrib_list_t *attrib_set)
{
	struct vfs_fsal_obj_handle *myself;
	int fd;
	struct stat stat;
	fsal_attrib_list_t attrs = *attrib_set;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	int retval = 0;

/* FIXME: now that I know how do do export caps testing, shouldn't this logic
 * be in the core?
 */
	/* Is it allowed to change times ? */
	if( !obj_hdl->export->ops->fs_supports(obj_hdl->export,
					       cansettime)) {
		if(attrs.asked_attributes
		   & (FSAL_ATTR_ATIME |
		      FSAL_ATTR_CREATION |
		      FSAL_ATTR_CTIME |
		      FSAL_ATTR_MTIME)) {
			/* handled as an unsettable attribute. */
			Return(ERR_FSAL_INVAL, 0, INDEX_FSAL_setattrs);
		}
	}

	/* apply umask, if mode attribute is to be changed */
	if(FSAL_TEST_MASK(attrs.asked_attributes, FSAL_ATTR_MODE)) {
		attrs.mode
			&= ~obj_hdl->export->ops->fs_umask(obj_hdl->export);
	}
	myself = container_of(obj_hdl, struct vfs_fsal_obj_handle, obj_handle);
	int mntfd = vfs_get_root_fd(obj_hdl->export);
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
#if 0
			/* NOTE: access check should be done before we get here.  verify
			 * in the core.  maybe break this up. core is setting these asked
			 * attrs. do the access check there before asking... */
			/* For modifying mode, user must be root or the owner */
			if((vfs_context->credential.user != 0)
			   && (vfs_context->credential.user != stat.st_uid))
			{
				LogFullDebug(COMPONENT_FSAL,
					     "Permission denied for CHMOD opeartion: current owner=%d, credential=%d",
					     buffstat.st_uid, vfs_context->credential.user);
				close(fd);
				Return(ERR_FSAL_PERM, 0, INDEX_FSAL_setattrs);
			}
#endif
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
#if 0
/* FIXME: access checking should move to core.
 * disable compile for now
 */
	/* Only root can change uid and A normal user must be in the group he wants to set */
	if(FSAL_TEST_MASK(attrs.asked_attributes, FSAL_ATTR_OWNER))
	{

		/* For modifying owner, user must be root or current owner==wanted==client */
		if((vfs_context->credential.user != 0) &&
		   ((vfs_context->credential.user != buffstat.st_uid) ||
		    (vfs_context->credential.user != attrs.owner)))
		{
			LogFullDebug(COMPONENT_FSAL,
				     "Permission denied for CHOWN opeartion: current owner=%d, credential=%d, new owner=%d",
				     buffstat.st_uid, vfs_context->credential.user, attrs.owner);
			close(fd);
			Return(ERR_FSAL_PERM, 0, INDEX_FSAL_setattrs);
		}
	}
#endif /* if 0 */
#if 0
/* FIXME: access checking here too...
 */
	if(FSAL_TEST_MASK(attrs.asked_attributes, FSAL_ATTR_GROUP)) {
		/* For modifying group, user must be root or current owner */
		if((vfs_context->credential.user != 0)
		   && (vfs_context->credential.user != buffstat.st_uid))
		{
			close(fd);
			Return(ERR_FSAL_PERM, 0, INDEX_FSAL_setattrs);
		}
		int in_grp = 0;
		/* set in_grp */
		if(vfs_context->credential.group == attrs.group)
			in_grp = 1;
		else
			for(i = 0; i < vfs_context->credential.nbgroups; i++)
			{
				if((in_grp = (attrs.group == vfs_context->credential.alt_groups[i])))
					break;
			}

		/* it must also be in target group */
		if(vfs_context->credential.user != 0 && !in_grp)
		{
			LogFullDebug(COMPONENT_FSAL,
				     "Permission denied for CHOWN operation: current group=%d, credential=%d, new group=%d",
				     buffstat.st_gid, vfs_context->credential.group, attrs.group);
			close(fd);
			Return(ERR_FSAL_PERM, 0, INDEX_FSAL_setattrs);
		}
	}

#endif /* if 0 */
	if(FSAL_TEST_MASK(attrs.asked_attributes, FSAL_ATTR_OWNER | FSAL_ATTR_GROUP)) {
		/*      LogFullDebug(COMPONENT_FSAL, "Performing chown(%s, %d,%d)",
                        fsalpath.path, FSAL_TEST_MASK(attrs.asked_attributes,
                                                      FSAL_ATTR_OWNER) ? (int)attrs.owner
                        : -1, FSAL_TEST_MASK(attrs.asked_attributes,
			FSAL_ATTR_GROUP) ? (int)attrs.group : -1);*/

		TakeTokenFSCall();
		retval = fchown(fd,
				FSAL_TEST_MASK(attrs.asked_attributes,
					       FSAL_ATTR_OWNER) ? (int)attrs.owner : -1,
				FSAL_TEST_MASK(attrs.asked_attributes,
					       FSAL_ATTR_GROUP) ? (int)attrs.group : -1);
		ReleaseTokenFSCall();
		if(retval) {
			fsal_error = posix2fsal_error(errno);
			retval = errno;
			close(fd);
			goto out;
		}
	}

	/**  UTIME  **/
#if 0
/* FIXME: another access check to move
 */
	/* user must be the owner or have read access to modify 'atime' */
	if(FSAL_TEST_MASK(attrs.asked_attributes, FSAL_ATTR_ATIME)
	   && (vfs_context->credential.user != 0)
	   && (vfs_context->credential.user != buffstat.st_uid)
	   && ((status = fsal_check_access(p_context, FSAL_R_OK, &buffstat, NULL)).major
	       != ERR_FSAL_NO_ERROR))
	{
		close(fd);
		ReturnStatus(status, INDEX_FSAL_setattrs);
	}
	/* user must be the owner or have write access to modify 'mtime' */
	if(FSAL_TEST_MASK(attrs.asked_attributes, FSAL_ATTR_MTIME)
	   && (vfs_context->credential.user != 0)
	   && (vfs_context->credential.user != buffstat.st_uid)
	   && ((status = fsal_check_access(p_context, FSAL_W_OK, &buffstat, NULL)).major
	       != ERR_FSAL_NO_ERROR))
	{
		close(fd);
		ReturnStatus(status, INDEX_FSAL_setattrs);
	}
#endif /* #if 0 */

	if(FSAL_TEST_MASK(attrs.asked_attributes, FSAL_ATTR_ATIME | FSAL_ATTR_MTIME)) {
		struct timeval timebuf[2];

		/* Atime */
		timebuf[0].tv_sec =
			(FSAL_TEST_MASK(attrs.asked_attributes, FSAL_ATTR_ATIME) ? (time_t) attrs.
			 atime.seconds : stat.st_atime);
		timebuf[0].tv_usec = 0;

		/* Mtime */
		timebuf[1].tv_sec =
			(FSAL_TEST_MASK(attrs.asked_attributes, FSAL_ATTR_MTIME) ? (time_t) attrs.
			 mtime.seconds : stat.st_mtime);
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
	.create = create,
	.mkdir = makedir,
	.mknode = makenode,
	.symlink = makesymlink,
	.getattrs = getattrs,
	.setattrs = setattrs,
	.handle_is = handle_is,
	.compare = compare,
	.handle_to_hashidx = handle_to_hashidx,
	.handle_to_rbtidx = handle_to_rbtidx,
	.handle_digest = handle_digest,
	.get = fsal_handle_get,
	.put = fsal_handle_put,
	.release = release,
};

/* export methods that create object handles
 */

/* lookup
 * deprecated NULL parent && NULL path implies root handle
 */

fsal_status_t vfs_lookup(struct fsal_export *exp_hdl,
			 struct fsal_obj_handle *parent,
			 fsal_path_t *path,
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

	if( !path || !parent)
		ReturnCode(ERR_FSAL_FAULT, 0);
	mount_fd = vfs_get_root_fd(exp_hdl);
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
	retval = name_to_handle_at(dirfd, path->path, fh, &mnt_id, AT_SYMLINK_FOLLOW);
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

