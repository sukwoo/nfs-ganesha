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

/* main.c
 * Module core functions
 */

#include "fsal.h"
#include <libgen.h>             /* used for 'dirname' */
#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include "nlm_list.h"
#include "fsal_internal.h"
#include "FSAL/fsal_init.h"

/* VFS FSAL module private storage
 */

struct vfs_fsal_module {	
	struct fsal_module fsal;
	struct fsal_staticfsinfo_t fs_info;
	fsal_init_info_t fsal_info;
	fs_common_initinfo_t common_info;
	 /* vfsfs_specific_initinfo_t specific_info;  placeholder */
};

/* I keep a static pointer to my instance
 * needed for ctor/dtor ops
 */
struct fsal_module *myself;
const char myname[] = "VFS";

/* filesystem info for VFS */
static fsal_staticfsinfo_t default_posix_info = {
	.maxfilesize = 0xFFFFFFFFFFFFFFFFLL, /* (64bits) */
	.maxlink = _POSIX_LINK_MAX,
	.maxnamelen = FSAL_MAX_NAME_LEN,
	.maxpathlen = FSAL_MAX_PATH_LEN,
	.no_trunc = TRUE,
	.chown_restricted = TRUE,
	.case_insensitive = FALSE,
	.case_preserving = TRUE,
	.fh_expire_type = FSAL_EXPTYPE_PERSISTENT,
	.link_support = TRUE,
	.symlink_support = TRUE,
	.lock_support = TRUE,
	.lock_support_owner = FALSE,
	.lock_support_async_block = FALSE,
	.named_attr = TRUE,
	.unique_handles = TRUE,
	.lease_time = {10, 0},
	.acl_support = FSAL_ACLSUPPORT_ALLOW,
	.cansettime = TRUE,
	.homogenous = TRUE,
	.supported_attrs = VFS_SUPPORTED_ATTRIBUTES,
	.maxread = 0,
	.maxwrite = 0,
	.umask = 0,
	.auth_exportpath_xdev = FALSE,
	.xattr_access_rights = 0400 /* root=RW, owner=R */
};

/* private helper for export object
 */

struct fsal_staticfsinfo_t *vfs_staticinfo(struct fsal_module *hdl)
{
	struct vfs_fsal_module *myself;

	myself = container_of(hdl, struct vfs_fsal_module, fsal);
	return &myself->fs_info;
}

/* opaque memory management helpers
 * needed for legacy only.
 */
struct fsal_export *alloc_export()
{
	return NULL;
}


static void free_export(struct fsal_export *exp_hdl)
{
}


static struct fsal_obj_handle *alloc_obj_handle()
{
	return NULL;
}


static fsal_handle_t *obj_to_fsal_handle(struct fsal_obj_handle *obj_hdl)
{
	return NULL;
}


static void free_obj_handle(struct fsal_obj_handle *obj_hdl)
{
}


static struct fsal_dirobj *alloc_dirobj()
{
	return NULL;
}


/* dir obj to dir something TBD */

static void free_dirobj(struct fsal_dirobj *dir_hdl)
{
}


static struct fsal_fileobj *alloc_fileobj()
{
	return NULL;
}


static fsal_file_t *fileobj_to_file(struct fsal_fileobj *file_hdl)
{
	return NULL;
}


static void free_fileobj(struct fsal_fileobj * file_hdl)
{
}

static struct fsal_alloc_ops alloc_ops = {
	.alloc_export = alloc_export,
	.free_export = free_export,
	.alloc_obj_handle = alloc_obj_handle,
	.obj_to_fsal_handle = obj_to_fsal_handle,
	.free_obj_handle = free_obj_handle,
	.alloc_dirobj = alloc_dirobj,
/* dir obj to dir something TBD */
	.free_dirobj = free_dirobj,
	.alloc_fileobj = alloc_fileobj,
	.fileobj_to_file = fileobj_to_file,
	.free_fileobj = free_fileobj
};

/* legacy API methods. To be deprecated
 */
#include "FSAL/common_methods.h"
#include "fsal_internal.h"

static fsal_functions_t vfs_functions = {
  .fsal_access = VFSFSAL_access,
  .fsal_getattrs = VFSFSAL_getattrs,
  .fsal_getattrs_descriptor = VFSFSAL_getattrs_descriptor,
  .fsal_setattrs = VFSFSAL_setattrs,
  .fsal_buildexportcontext = VFSFSAL_BuildExportContext,
  .fsal_cleanupexportcontext = COMMON_CleanUpExportContext_noerror,
  .fsal_initclientcontext = COMMON_InitClientContext,
  .fsal_getclientcontext = COMMON_GetClientContext,
  .fsal_create = VFSFSAL_create,
  .fsal_mkdir = VFSFSAL_mkdir,
  .fsal_link = VFSFSAL_link,
  .fsal_mknode = VFSFSAL_mknode,
  .fsal_opendir = VFSFSAL_opendir,
  .fsal_readdir = VFSFSAL_readdir,
  .fsal_closedir = VFSFSAL_closedir,
  .fsal_open_by_name = VFSFSAL_open_by_name,
  .fsal_open = VFSFSAL_open,
  .fsal_read = VFSFSAL_read,
  .fsal_write = VFSFSAL_write,
  .fsal_sync = VFSFSAL_sync,
  .fsal_close = VFSFSAL_close,
  .fsal_open_by_fileid = COMMON_open_by_fileid,
  .fsal_close_by_fileid = COMMON_close_by_fileid,
  .fsal_dynamic_fsinfo = VFSFSAL_dynamic_fsinfo,
  .fsal_terminate = COMMON_terminate_noerror,
  .fsal_test_access = VFSFSAL_test_access,
  .fsal_setattr_access = COMMON_setattr_access_notsupp,
  .fsal_rename_access = COMMON_rename_access,
  .fsal_create_access = COMMON_create_access,
  .fsal_unlink_access = COMMON_unlink_access,
  .fsal_link_access = COMMON_link_access,
  .fsal_merge_attrs = COMMON_merge_attrs,
  .fsal_lookup = VFSFSAL_lookup,
  .fsal_lookuppath = VFSFSAL_lookupPath,
  .fsal_lookupjunction = VFSFSAL_lookupJunction,
  .fsal_lock_op = VFSFSAL_lock_op,
  .fsal_cleanobjectresources = COMMON_CleanObjectResources,
  .fsal_set_quota = COMMON_set_quota_noquota,
  .fsal_get_quota = COMMON_get_quota_noquota,
  .fsal_rcp = VFSFSAL_rcp,
  .fsal_rcp_by_fileid = COMMON_rcp_by_fileid,
  .fsal_rename = VFSFSAL_rename,
  .fsal_get_stats = VFSFSAL_get_stats,
  .fsal_readlink = VFSFSAL_readlink,
  .fsal_symlink = VFSFSAL_symlink,
  .fsal_handlecmp = VFSFSAL_handlecmp,
  .fsal_handle_to_hashindex = VFSFSAL_Handle_to_HashIndex,
  .fsal_handle_to_rbtindex = VFSFSAL_Handle_to_RBTIndex,
  .fsal_handle_to_hash_both = NULL, 
  .fsal_digesthandle = VFSFSAL_DigestHandle,
  .fsal_expandhandle = VFSFSAL_ExpandHandle,
  .fsal_setdefault_fs_specific_parameter = VFSFSAL_SetDefault_FS_specific_parameter,
  .fsal_load_fs_specific_parameter_from_conf =
      VFSFSAL_load_FS_specific_parameter_from_conf,
  .fsal_truncate = VFSFSAL_truncate,
  .fsal_unlink = VFSFSAL_unlink,
  .fsal_getfsname = VFSFSAL_GetFSName,
  .fsal_getxattrattrs = VFSFSAL_GetXAttrAttrs,
  .fsal_listxattrs = VFSFSAL_ListXAttrs,
  .fsal_getxattrvaluebyid = VFSFSAL_GetXAttrValueById,
  .fsal_getxattridbyname = VFSFSAL_GetXAttrIdByName,
  .fsal_getxattrvaluebyname = VFSFSAL_GetXAttrValueByName,
  .fsal_setxattrvalue = VFSFSAL_SetXAttrValue,
  .fsal_setxattrvaluebyid = VFSFSAL_SetXAttrValueById,
  .fsal_removexattrbyid = VFSFSAL_RemoveXAttrById,
  .fsal_removexattrbyname = VFSFSAL_RemoveXAttrByName,
  .fsal_getextattrs = COMMON_getextattrs_notsupp,
  .fsal_getfileno = VFSFSAL_GetFileno
};

/* Module methods
 */

/* init_config
 * must be called with a reference taken (via lookup_fsal)
 */

static fsal_status_t init_config(struct fsal_module *fsal_hdl,
				 config_file_t config_struct)
{
	struct vfs_fsal_module *vfs_me
		= container_of(fsal_hdl, struct vfs_fsal_module, fsal);
	fsal_status_t fsal_status;

	fsal_status = load_FSAL_parameters_from_conf(config_struct,
						     &vfs_me->fsal_info);
	if(FSAL_IS_ERROR(fsal_status))
		return fsal_status;
	fsal_status = load_FS_common_parameters_from_conf(config_struct,
							  &vfs_me->common_info);
	if(FSAL_IS_ERROR(fsal_status))
		return fsal_status;
	/* if we have fsal specific params, do them here
	 * fsal_hdl->name is used to find the block containing the
	 * params.
	 */

	/* Analyzing fs_common_info struct */

	if((vfs_me->common_info.behaviors.maxfilesize != FSAL_INIT_FS_DEFAULT) ||
	   (vfs_me->common_info.behaviors.maxlink != FSAL_INIT_FS_DEFAULT) ||
	   (vfs_me->common_info.behaviors.maxnamelen != FSAL_INIT_FS_DEFAULT) ||
	   (vfs_me->common_info.behaviors.maxpathlen != FSAL_INIT_FS_DEFAULT) ||
	   (vfs_me->common_info.behaviors.no_trunc != FSAL_INIT_FS_DEFAULT) ||
	   (vfs_me->common_info.behaviors.case_insensitive != FSAL_INIT_FS_DEFAULT) ||
	   (vfs_me->common_info.behaviors.case_preserving != FSAL_INIT_FS_DEFAULT) ||
	   (vfs_me->common_info.behaviors.named_attr != FSAL_INIT_FS_DEFAULT) ||
	   (vfs_me->common_info.behaviors.lease_time != FSAL_INIT_FS_DEFAULT) ||
	   (vfs_me->common_info.behaviors.supported_attrs != FSAL_INIT_FS_DEFAULT) ||
	   (vfs_me->common_info.behaviors.homogenous != FSAL_INIT_FS_DEFAULT))
		ReturnCode(ERR_FSAL_NOTSUPP, 0);

	vfs_me->fs_info = default_posix_info; /* get a copy of the defaults */

	SET_BOOLEAN_PARAM(vfs_me->fs_info, &vfs_me->common_info, symlink_support);
	SET_BOOLEAN_PARAM(vfs_me->fs_info, &vfs_me->common_info, link_support);
	SET_BOOLEAN_PARAM(vfs_me->fs_info, &vfs_me->common_info, lock_support);
	SET_BOOLEAN_PARAM(vfs_me->fs_info, &vfs_me->common_info, lock_support_owner);
	SET_BOOLEAN_PARAM(vfs_me->fs_info, &vfs_me->common_info, lock_support_async_block);
	SET_BOOLEAN_PARAM(vfs_me->fs_info, &vfs_me->common_info, cansettime);
	SET_INTEGER_PARAM(vfs_me->fs_info, &vfs_me->common_info, maxread);
	SET_INTEGER_PARAM(vfs_me->fs_info, &vfs_me->common_info, maxwrite);
	SET_BITMAP_PARAM(vfs_me->fs_info, &vfs_me->common_info, umask);
	SET_BOOLEAN_PARAM(vfs_me->fs_info, &vfs_me->common_info, auth_exportpath_xdev);
	SET_BITMAP_PARAM(vfs_me->fs_info, &vfs_me->common_info, xattr_access_rights);

	display_fsinfo(&vfs_me->fs_info);
	LogFullDebug(COMPONENT_FSAL,
		     "Supported attributes constant = 0x%llX.",
		     VFS_SUPPORTED_ATTRIBUTES);
	LogFullDebug(COMPONENT_FSAL,
		     "Supported attributes default = 0x%llX.",
		     default_posix_info.supported_attrs);
	LogDebug(COMPONENT_FSAL,
		 "FSAL INIT: Supported attributes mask = 0x%llX.",
		 vfs_me->fs_info.supported_attrs);
	ReturnCode(ERR_FSAL_NO_ERROR, 0);
}

static void dump_config(struct fsal_module *fsal_hdl, int log_fd)
{
}


/* Internal VFS method linkage to export object
 */

fsal_status_t vfs_create_export(struct fsal_module *fsal_hdl,
				fsal_path_t *export_path,
				char *fs_options,
				struct fsal_export **export);

/* Module initialization.
 * Called by dlopen() to register the module
 * keep a private pointer to me in myself
 */

MODULE_INIT void vfs_init(void) {
	int retval;
	struct vfs_fsal_module *vfs_me;
	struct fsal_module *myself;

	vfs_me = malloc(sizeof(struct vfs_fsal_module)+sizeof(struct fsal_ops));
	if(vfs_me== NULL) {
		LogCrit(COMPONENT_FSAL,
			 "vfs_init: VFS module cannot allocate space for itself");
		return;
	}
	memset(vfs_me, 0, sizeof(struct vfs_fsal_module)+sizeof(struct fsal_ops));
	myself = &vfs_me->fsal;
	myself->ops = (struct fsal_ops *) &vfs_me[1];
	retval = register_fsal(myself, myname);
	if(retval != 0) {
		free(vfs_me);
		myself = NULL;
		return;
	}
	myself->ops->init_config = init_config;
	myself->ops->dump_config = dump_config;
	myself->ops->create_export = vfs_create_export;
	myself->alloc_ops = &alloc_ops;
	myself->legacy_ops = &vfs_functions;
	init_fsal_parameters(&vfs_me->fsal_info, &vfs_me->common_info);
}

MODULE_FINI void vfs_unload(void) {
	struct vfs_fsal_module *vfs_me;
	int retval;

	retval = unregister_fsal(myself);
	if(retval == 0 && myself != NULL) {
		vfs_me = container_of(myself, struct vfs_fsal_module, fsal);
		/* free my resources */
		free(vfs_me);
		myself = NULL;
	}
}
