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

/* file.c
 * File I/O methods for VFS module
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fsal.h"
#include "fsal_internal.h"
#include "FSAL/access_check.h"
#include "fsal_convert.h"
#include <unistd.h>
#include <fcntl.h>


fsal_status_t vfs_open(struct fsal_obj_handle *obj_hdl,
		       fsal_openflags_t openflags)
{
	struct vfs_fsal_obj_handle *myself;
	int fd, mntfd;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	int retval = 0;

	myself = container_of(obj_hdl, struct vfs_fsal_obj_handle, obj_handle);
	if(myself->fd >= 0) {
		if(openflags == myself->openflags) { /* make smarter */
			close(myself->fd);
			myself->fd = -1;
		}
	}
	mntfd = vfs_get_root_fd(obj_hdl->export);
	fd = open_by_handle_at(mntfd, myself->handle, (O_RDWR));
	if(fd < 0) {
		fsal_error = posix2fsal_error(errno);
		retval = errno;
		goto out;
	}
	myself->fd = fd;
	myself->openflags = openflags;

out:
	ReturnCode(fsal_error, retval);	
}

/* vfs_open_by_name
 * NOTE: we may have a problem here.  This is not really a handle call
 * the fd we get is for a file in this dir, of which we don't have a handle
 * yet.  There is also no way to to test_access from above...
 */

fsal_status_t vfs_open_by_name(struct fsal_obj_handle *dir_hdl,
			       const char *filename,
			       fsal_openflags_t openflags)
{
	struct vfs_fsal_obj_handle *myself;
	int fd, mntfd;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	int retval = 0;

	myself = container_of(obj_hdl, struct vfs_fsal_obj_handle, obj_handle);
out:
	ReturnCode(fsal_error, retval);	
}

fsal_status_t vfs_read(struct fsal_obj_handle *obj_hdl,
		       fsal_seek_t * seek_descriptor,
		       fsal_size_t buffer_size,
		       caddr_t buffer,
		       fsal_size_t * read_amount,
		       fsal_boolean_t * end_of_file)
{
	struct vfs_fsal_obj_handle *myself;
	int fd, mntfd;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	int retval = 0;

	myself = container_of(obj_hdl, struct vfs_fsal_obj_handle, obj_handle);
out:
	ReturnCode(fsal_error, retval);	
}

fsal_status_t vfs_write(struct fsal_obj_handle *obj_hdl,
			fsal_seek_t * seek_descriptor,
			fsal_size_t buffer_size,
			caddr_t buffer,
			fsal_size_t * write_amount)
{
	struct vfs_fsal_obj_handle *myself;
	int fd, mntfd;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	int retval = 0;

	myself = container_of(obj_hdl, struct vfs_fsal_obj_handle, obj_handle);
out:
	ReturnCode(fsal_error, retval);	
}

fsal_status_t vfs_commit(struct fsal_obj_handle *obj_hdl, /* sync */
			 off_t offset,
			 size_t len)
{
	struct vfs_fsal_obj_handle *myself;
	int fd, mntfd;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	int retval = 0;

	myself = container_of(obj_hdl, struct vfs_fsal_obj_handle, obj_handle);
out:
	ReturnCode(fsal_error, retval);	
}

fsal_status_t vfs_lock_op(struct fsal_obj_handle *obj_hdl,
			  void * p_owner,
			  fsal_lock_op_t lock_op,
			  fsal_lock_param_t   request_lock,
			  fsal_lock_param_t * conflicting_lock)
{
	struct vfs_fsal_obj_handle *myself;
	int fd, mntfd;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	int retval = 0;

	myself = container_of(obj_hdl, struct vfs_fsal_obj_handle, obj_handle);
out:
	ReturnCode(fsal_error, retval);	
}

fsal_status_t vfs_close(struct fsal_obj_handle *obj_hdl)
{
	struct vfs_fsal_obj_handle *myself;
	int fd, mntfd;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	int retval = 0;

	myself = container_of(obj_hdl, struct vfs_fsal_obj_handle, obj_handle);
out:
	ReturnCode(fsal_error, retval);	
}

fsal_status_t vfs_rcp(struct fsal_obj_handle *obj_hdl,
		      const char *local_path,
		      fsal_rcpflag_t transfer_opt)
{
	struct vfs_fsal_obj_handle *myself;
	int fd, mntfd;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	int retval = 0;

	myself = container_of(obj_hdl, struct vfs_fsal_obj_handle, obj_handle);
out:
	ReturnCode(fsal_error, retval);	
}

fsal_status_t vfs_rcp_by_name(struct fsal_obj_handle *obj_hdl,
			      const char *filename,
			      const char *local_path,
			      fsal_rcpflag_t transfer_opt)
{
	struct vfs_fsal_obj_handle *myself;
	int fd, mntfd;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	int retval = 0;

	myself = container_of(obj_hdl, struct vfs_fsal_obj_handle, obj_handle);
out:
	ReturnCode(fsal_error, retval);	
}

