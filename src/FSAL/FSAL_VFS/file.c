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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fsal.h"
#include "fsal_internal.h"
#include "FSAL/access_check.h"
#include "fsal_convert.h"
#include <unistd.h>
#include <fcntl.h>

/* getattrs
 * originated as VFSFSAL_getattrs_descriptor
 */

static fsal_status_t getattrs_descriptor(struct fsal_file_obj *obj_hdl,
					 fsal_attrib_list_t *obj_attr)
{
	fsal_status_t st;
	struct stat64 buffstat;
	int rc, errsv;
	struct vfs_fsal_file_obj *myself;

#if 0
/* rubbish at this point.  just saving logic
 */
  /* sanity checks.
   * note : object_attributes is mandatory in VFSFSAL_getattrs.
   */
  if(!p_file_descriptor || !p_filehandle || !p_context || !p_object_attributes)
    Return(ERR_FSAL_FAULT, 0, INDEX_FSAL_getattrs_descriptor);

  TakeTokenFSCall();
  rc = fstat64(((vfsfsal_file_t *)p_file_descriptor)->fd, &buffstat);
  errsv = errno;
  ReleaseTokenFSCall();

  if(rc == -1)
    Return(posix2fsal_error(errsv), errsv, INDEX_FSAL_getattrs_descriptor);

  /* convert attributes */
  st = posixstat64_2_fsal_attributes(&buffstat, p_object_attributes);
  if(FSAL_IS_ERROR(st))
    {
      FSAL_CLEAR_MASK(p_object_attributes->asked_attributes);
      FSAL_SET_MASK(p_object_attributes->asked_attributes, FSAL_ATTR_RDATTR_ERR);
      ReturnStatus(st, INDEX_FSAL_getattrs_descriptor);
    }
#endif /* #if 0 */
  Return(ERR_FSAL_NO_ERROR, 0, INDEX_FSAL_getattrs_descriptor);
}
