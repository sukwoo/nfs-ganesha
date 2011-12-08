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

/* Legacy FSAL ops
 * Maps FSAL methods to the original FSAL interface
 * Needed by un-converted FSALs.  Eventually deprecated
 */

#include "fsal.h"
#include "FSAL/fsal_init.h"

/* export functions
 */

fsal_status_t legacy_lookup(struct fsal_export *exp_hdl,
			    struct fsal_obj_handle *parent,
			    fsal_path_t *path,
			    struct fsal_obj_handle **handle)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_lookup_path(struct fsal_export *exp_hdl,
				 fsal_path_t *path,
				 struct fsal_obj_handle **handle)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_lookup_junction(struct fsal_export *exp_hdl,
				     struct fsal_obj_handle *junction,
				     struct fsal_obj_handle **handle)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_get_fs_dynamic_info(struct fsal_export *exp_hdl,
					 fsal_dynamicfsinfo_t *infop)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_get_fs_static_info(struct fsal_export *exp_hdl,
					fsal_staticfsinfo_t *infop)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_get_quota(struct fsal_export *exp_hdl,
				   fsal_path_t * pfsal_path,
				   int quota_type,
				   fsal_uid_t fsal_uid,
				   fsal_quota_t * pquota)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_set_quota(struct fsal_export *exp_hdl,
				   fsal_path_t * pfsal_path,
				   int quota_type,
				   fsal_uid_t fsal_uid,
				   fsal_quota_t * pquota,
				   fsal_quota_t * presquota)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

/* object handle related stuff
 */

fsal_status_t legacy_access(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

/* test_* candidates for removal */
fsal_status_t legacy_test_access(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_test_rename_access(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_test_unlink_access(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_test_create_access(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_test_link_access(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_test_setattr_access(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_create(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_mkdir(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_truncate(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_getattrs(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_getattrs_descriptor(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_setattrs(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_getextattrs(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_link(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_opendir(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_open(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_open_by_name(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_open_by_fileid(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_readlink(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_symlink(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_rename(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_unlink(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_mknode(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_list_ext_attrs(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_getextattr_id_by_name(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_getextattr_value_by_name(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_getextattr_value_by_id(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_setextattr_value(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_setextattr_value_by_id(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_getextattr_attrs(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_remove_extattr_by_id(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_remove_extattr_by_name(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_compare(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_handle_to_hashidx(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}
fsal_status_t legacy_handle_to_rbtidx(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_handle_to_hashboth(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_handle_digest(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_handle_expand(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_release(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_rcp(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_rcp_by_name(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_rcp_by_fileid(struct fsal_obj_handle *obj_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}


/* directory ops
 */

fsal_status_t legacy_readdir(struct fsal_dirobj *dirobj, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_closedir(struct fsal_dirobj *dirobj, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

/* file ops
 */

fsal_status_t legacy_read(struct fsal_fileobj *file_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_write(struct fsal_fileobj *file_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_sync(struct fsal_fileobj *file_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_close(struct fsal_fileobj *file_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_close_by_fileid(struct fsal_fileobj *file_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_lock(struct fsal_fileobj *file_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t legacy_get_fileno(struct fsal_fileobj *file_hdl, ...)
{
	ReturnCode(ERR_FSAL_NOTSUPP, 0);
}
