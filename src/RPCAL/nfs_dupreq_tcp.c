/*
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright CEA/DAM/DIF  (2008)
 * contributeur : Philippe DENIEL   philippe.deniel@cea.fr
 *                Thomas LEIBOVICI  thomas.leibovici@cea.fr
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
 * ---------------------------------------
 */

/**
 * \file    nfs_tools.c
 * \author  $Author: deniel $
 * \date    $Date: 2006/01/20 07:39:22 $
 * \version $Revision: 1.14 $
 * \brief   Some tools very usefull in the nfs protocol implementation.
 *
 * nfs_tools.c : Some tools very usefull in the nfs protocol implementation
 *
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef _SOLARIS
#include "solaris_port.h"
#endif

#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>              /* for having isalnum */
#include <stdlib.h>             /* for having atoi */
#include <dirent.h>             /* for having MAXNAMLEN */
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/file.h>           /* for having FNDELAY */
#include <pwd.h>
#include <grp.h>

#include "rpcal.h"
#include "LRU_List.h"
#include "HashData.h"
#include "HashTable.h"
#include "log_macros.h"
#include "nfs_core.h"
#include "nfs23.h"
#include "nfs4.h"
#include "fsal.h"
#include "stuff_alloc.h"
#include "nfs_tools.h"
#include "nfs_exports.h"
#include "nfs_file_handle.h"
#include "nfs_dupreq.h"

extern nfs_function_desc_t nfs2_func_desc[];
extern nfs_function_desc_t nfs3_func_desc[];
extern nfs_function_desc_t nfs4_func_desc[];
extern nfs_function_desc_t mnt1_func_desc[];
extern nfs_function_desc_t mnt3_func_desc[];
#ifdef _USE_NLM
extern nfs_function_desc_t nlm4_func_desc[];
#endif                          /* _USE_NLM */
#ifdef _USE_QUOTA
extern nfs_function_desc_t rquota1_func_desc[];
extern nfs_function_desc_t rquota2_func_desc[];
#endif                          /* _USE_QUOTA */

int nfs_dupreq_tcp_delete(long xid, struct svc_req *ptr_req, SVCXPRT *xprt,
                          struct prealloc_pool *dupreq_pool)
{
  return DUPREQ_SUCCESS ;
}

nfs_res_t nfs_dupreq_tcp_get(long xid, struct svc_req *ptr_req, SVCXPRT *xprt, int *pstatus)
{
  nfs_res_t res_nfs ;

  return res_nfs;
}             

int nfs_dupreq_tcp_add_not_finished(long xid,
                                struct svc_req *ptr_req,
                                SVCXPRT *xprt,
                                struct prealloc_pool *dupreq_pool,
                                nfs_res_t *res_nfs)
{
  return DUPREQ_SUCCESS ;
}          

int nfs_dupreq_tcp_finish(long xid,
                      struct svc_req *ptr_req,
                      SVCXPRT *xprt,
                      nfs_res_t * p_res_nfs,
                      LRU_list_t * lru_dupreq)
{

  return DUPREQ_SUCCESS;
}                               /* nfs_dupreq_finish */

int nfs_dupreq_gc_tcp_function(LRU_entry_t * pentry, void *addparam)
{
  return LRU_LIST_DO_NOT_SET_INVALID;
}                               /* nfs_dupreq_gc_udp_function */

