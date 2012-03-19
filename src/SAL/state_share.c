/*
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright CEA/DAM/DIF  (2008)
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
 * ---------------------------------------
 */

/**
 * \file    state_share.c
 * \author  $Author: deniel $
 * \date    $Date$
 * \version $Revision$
 * \brief   This file contains functions used in share reservation management.
 *
 * state_share.c : This file contains functions used in share reservation management.
 *
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef _SOLARIS
#include "solaris_port.h"
#endif                          /* _SOLARIS */

#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <time.h>
#include <pthread.h>
#include <string.h>
#include <assert.h>

#include "LRU_List.h"
#include "HashData.h"
#include "HashTable.h"
#include "fsal.h"
#include "nfs_core.h"
#include "nfs4.h"
#include "sal_functions.h"
#include "stuff_alloc.h"
#ifdef _USE_NLM
#include "nlm_util.h"
#endif

state_status_t do_share_op(cache_entry_t        * pentry,
                           fsal_op_context_t    * pcontext,
                           state_owner_t        * powner,
                           fsal_share_param_t   * pshare,
                           cache_inode_client_t * pclient)
{
  fsal_status_t fsal_status;
  state_status_t status = STATE_SUCCESS;
  fsal_staticfsinfo_t * pstatic = pcontext->export_context->fe_static_fs_info;

  /* Quick exit if share reservation is not supported by FSAL */
  if(!pstatic->share_support)
    return STATE_SUCCESS;

  fsal_status = FSAL_share_op(cache_inode_fd(pentry),
                              &pentry->handle,
                              pcontext,
                              pstatic->share_support_owner ? powner : NULL,
                              *pshare);

  status = state_error_convert(fsal_status);

  LogFullDebug(COMPONENT_STATE,
               "FSAL_share_op returned %s",
               state_err_str(status));

  return status;
}

/* This is called when new share state is added. */
state_status_t state_share_add(cache_entry_t         * pentry,
                               fsal_op_context_t     * pcontext,
                               state_owner_t         * powner,
                               state_t               * pstate,
                               cache_inode_client_t  * pclient,
                               state_status_t        * pstatus)
{
  state_status_t status = STATE_SUCCESS;
  unsigned int            pentry_share_access = 0;
  unsigned int            pentry_share_deny = 0;
  unsigned int            new_share_access = 0;
  unsigned int            new_share_deny = 0;
  fsal_share_param_t      share_param;

  P_w(&pentry->lock);

  /* Get this file's union of share state. */
  pentry_share_access =
    pentry->object.file.share_state.share_access;
  pentry_share_deny =
    pentry->object.file.share_state.share_deny;

  /* New share state. */
  new_share_access = pstate->state_data.share.share_access;
  new_share_deny = pstate->state_data.share.share_deny;

  /* Check if new share state has conflicts. */
  if((pentry_share_access & new_share_deny) ||
     (pentry_share_deny & new_share_access))
    {
      V_w(&pentry->lock);
      LogFullDebug(COMPONENT_STATE, "Share conflicts detected during add");
      *pstatus = STATE_STATE_CONFLICT;
      return *pstatus;
    }

  /* Calculate the union of share states. */
  pentry_share_access |= new_share_access;
  pentry_share_deny |= new_share_deny;

  /* If this file's share bits are different from the supposed value, update
   * it.
   */
  if((pentry_share_access != pentry->object.file.share_state.share_access) ||
     (pentry_share_deny != pentry->object.file.share_state.share_deny))
    {
      /* Try to push to FSAL. */
      share_param.share_access = pentry_share_access;
      share_param.share_deny = pentry_share_deny;

      status = do_share_op(pentry, pcontext, powner, &share_param, pclient);
      if(status != STATE_SUCCESS)
        {
          V_w(&pentry->lock);
          LogFullDebug(COMPONENT_STATE, "do_share_op failed");
          *pstatus = status;
          return *pstatus;
        }
    }

  LogFullDebug(COMPONENT_STATE, "pstate %p: added share_access %u, "
               "share_deny %u",
               pstate, new_share_access, new_share_deny);

  /* Update previously seen share state. */
  state_share_set_prev(pstate, &(pstate->state_data));

  /* Update the union of share state. */
  pentry->object.file.share_state.share_access = pentry_share_access;
  pentry->object.file.share_state.share_deny = pentry_share_deny;
  LogFullDebug(COMPONENT_STATE, "pentry %p: union of share_access %u, "
               "share_deny %u",
               pentry,
               pentry->object.file.share_state.share_access,
               pentry->object.file.share_state.share_deny);

  V_w(&pentry->lock);

  return status;
}

/* This is called when a share state is removed. */
state_status_t state_share_remove(cache_entry_t         * pentry,
                                  fsal_op_context_t     * pcontext,
                                  state_owner_t         * powner,
                                  state_t               * pstate,
                                  cache_inode_client_t  * pclient,
                                  state_status_t        * pstatus)
{
  state_status_t status = STATE_SUCCESS;
  unsigned int            pentry_share_access = 0;
  unsigned int            pentry_share_deny = 0;
  state_t               * pstate_iterate;
  struct glist_head     * glist;
  fsal_share_param_t      share_param;

  P_w(&pentry->lock);

  /* Check if state list is already cleaned up either by reaper
   * thread or file close operation. */
  if(glist_empty(&pentry->object.file.state_list))
    {
      V_w(&pentry->lock);
      LogFullDebug(COMPONENT_STATE, "state_list already cleaned up");
      *pstatus = STATE_SUCCESS;
      return *pstatus;
    }
  else
    LogFullDebug(COMPONENT_STATE, "state_list is not empty");

  /* Calculate the union of share bits without state to be removed. */
  LogFullDebug(COMPONENT_STATE, "pentry %p: iterating states", pentry);
  glist_for_each(glist, &pentry->object.file.state_list)
    {
      pstate_iterate = glist_entry(glist, state_t, state_list);

      LogFullDebug(COMPONENT_STATE, "  pstate %p", pstate_iterate);
      assert(pstate_iterate);

      if(pstate_iterate->state_type != STATE_TYPE_SHARE)
        continue;

      /* Exclude the given state. */
      if(pstate_iterate == pstate)
        continue;

      LogFullDebug(COMPONENT_STATE, "  pstate %p: share_access %u, "
                   "share_deny %u",
                   pstate_iterate,
                   pstate_iterate->state_data.share.share_access,
                   pstate_iterate->state_data.share.share_deny);

      pentry_share_access |= pstate_iterate->state_data.share.share_access;
      pentry_share_deny |= pstate_iterate->state_data.share.share_deny;
    }

  /* If this file's share bits are different from the supposed value, update
   * it.
   */
  if((pentry_share_access != pentry->object.file.share_state.share_access) ||
     (pentry_share_deny != pentry->object.file.share_state.share_deny))
    {
      /* Try to push to FSAL. */
      share_param.share_access = pentry_share_access;
      share_param.share_deny = pentry_share_deny;

      status = do_share_op(pentry, pcontext, powner, &share_param, pclient);
      if(status != STATE_SUCCESS)
        {
          V_w(&pentry->lock);
          LogFullDebug(COMPONENT_STATE, "do_share_op failed");
          *pstatus = status;
          return *pstatus;
        }
    }

  LogFullDebug(COMPONENT_STATE, "pstate %p: removed share_access %u, "
               "share_deny %u",
               pstate,
               pstate->state_data.share.share_access,
               pstate->state_data.share.share_deny);

  /* Update the union of share state. */
  pentry->object.file.share_state.share_access = pentry_share_access;
  pentry->object.file.share_state.share_deny = pentry_share_deny;
  LogFullDebug(COMPONENT_STATE, "pentry %p: union of share_access %u, "
               "share_deny %u",
               pentry,
               pentry->object.file.share_state.share_access,
               pentry->object.file.share_state.share_deny);

  V_w(&pentry->lock);

  return status;
}

/* This is called when share state is upgraded during open. */
state_status_t state_share_upgrade(cache_entry_t         * pentry,
                                   fsal_op_context_t     * pcontext,
                                   state_data_t          * pstate_data,
                                   state_owner_t         * powner,
                                   state_t               * pstate,
                                   cache_inode_client_t  * pclient,
                                   state_status_t        * pstatus)
{
  state_status_t status = STATE_SUCCESS;
  unsigned int pentry_share_access = 0, pentry_share_deny = 0;
  unsigned int new_share_access = 0, new_share_deny = 0;
  unsigned int cur_share_access = 0, cur_share_deny = 0;
  fsal_share_param_t share_param;

  P_w(&pentry->lock);

  /* Get this file's union of share state. */
  pentry_share_access =
    pentry->object.file.share_state.share_access;
  pentry_share_deny =
    pentry->object.file.share_state.share_deny;

  /* New share state. */
  new_share_access = pstate_data->share.share_access;
  new_share_deny = pstate_data->share.share_deny;

  /* Current share state. */
  cur_share_access = pstate->state_data.share.share_access;
  cur_share_deny = pstate->state_data.share.share_deny;

  /* Check if new share state is valid. */
  if(((new_share_access & cur_share_access) == new_share_access) &&
     ((new_share_deny & cur_share_deny) == new_share_deny))
    {
      V_w(&pentry->lock);
      LogFullDebug(COMPONENT_STATE, "Invalid share state for upgrade: "
                   "cur_share_access %u, cur_share_deny %u, "
                   "new_share_access %u, new_share_deny %u",
                   cur_share_access, cur_share_deny,
                   new_share_access, new_share_deny);
	  *pstatus = STATE_INVALID_ARGUMENT;
	  return *pstatus;
    }

  /* Check if new share state has conflicts. */
  if((pentry_share_access & new_share_deny) ||
     (pentry_share_deny & new_share_access))
    {
      V_w(&pentry->lock);
      LogFullDebug(COMPONENT_STATE, "Share conflicts detected during upgrade");
      *pstatus = STATE_STATE_CONFLICT;
      return *pstatus;
    }

  /* Calculate the union of share states. */
  pentry_share_access |= new_share_access;
  pentry_share_deny |= new_share_deny;

  /* If this file's share bits are different from the supposed value, update
   * it.
   */
  if((pentry_share_access != pentry->object.file.share_state.share_access) ||
     (pentry_share_deny != pentry->object.file.share_state.share_deny))
    {
      /* Try to push to FSAL. */
      share_param.share_access = pentry_share_access;
      share_param.share_deny = pentry_share_deny;

      status = do_share_op(pentry, pcontext, powner, &share_param, pclient);
      if(status != STATE_SUCCESS)
        {
          V_w(&pentry->lock);
          LogFullDebug(COMPONENT_STATE, "do_share_op failed");
          *pstatus = status;
          return *pstatus;
        }
    }

  /* Update share state. */
  pstate->state_data.share.share_access = new_share_access;
  pstate->state_data.share.share_deny = new_share_deny;
  LogFullDebug(COMPONENT_STATE, "pstate %p: upgraded share_access %u, share_deny %u",
               pstate,
               pstate->state_data.share.share_access,
               pstate->state_data.share.share_deny);

  /* Update previously seen share state. */
  state_share_set_prev(pstate, pstate_data);

  /* Update the union of share state. */
  pentry->object.file.share_state.share_access = pentry_share_access;
  pentry->object.file.share_state.share_deny = pentry_share_deny;
  LogFullDebug(COMPONENT_STATE, "pentry %p: union of share_access %u, share_deny %u",
               pentry,
               pentry->object.file.share_state.share_access,
               pentry->object.file.share_state.share_deny);

  V_w(&pentry->lock);

  return status;
}

/* This is called when share is downgraded via open_downgrade op. */
state_status_t state_share_downgrade(cache_entry_t         * pentry,
                                     fsal_op_context_t     * pcontext,
                                     state_data_t          * pstate_data,
                                     state_owner_t         * powner,
                                     state_t               * pstate,
                                     cache_inode_client_t  * pclient,
                                     state_status_t        * pstatus)
{
  state_status_t status = STATE_SUCCESS;
  unsigned int            pentry_share_access = 0;
  unsigned int            pentry_share_deny = 0;
  state_t               * pstate_iterate;
  struct glist_head     * glist;
  fsal_share_param_t      share_param;

  P_w(&pentry->lock);

  /* Calculate the union of share bits with downgraded state. */
  LogFullDebug(COMPONENT_STATE, "pentry %p: iterating states", pentry);
  glist_for_each(glist, &pentry->object.file.state_list)
    {
      pstate_iterate = glist_entry(glist, state_t, state_list);

      if(pstate_iterate->state_type != STATE_TYPE_SHARE)
        continue;

      if(pstate_iterate == pstate)
        {
          /* Use downgrade share state. */
          LogFullDebug(COMPONENT_STATE, "  downgrade pstate %p: share_access %u, "
                       "share_deny %u",
                       pstate,
                       pstate_data->share.share_access,
                       pstate_data->share.share_deny);

          pentry_share_access |= pstate_data->share.share_access;
          pentry_share_deny |= pstate_data->share.share_deny;
        }
      else
        {
          LogFullDebug(COMPONENT_STATE, "  pstate %p: share_access %u, "
                       "share_deny %u",
                       pstate_iterate,
                       pstate_iterate->state_data.share.share_access,
                       pstate_iterate->state_data.share.share_deny);

          pentry_share_access |= pstate_iterate->state_data.share.share_access;
          pentry_share_deny |= pstate_iterate->state_data.share.share_deny;
        }
    }

  /* If this file's share bits are different from the supposed value, update
   * it.
   */
  if((pentry_share_access != pentry->object.file.share_state.share_access) ||
     (pentry_share_deny != pentry->object.file.share_state.share_deny))
    {
      /* Try to push to FSAL. */
      share_param.share_access = pentry_share_access;
      share_param.share_deny = pentry_share_deny;

      status = do_share_op(pentry, pcontext, powner, &share_param, pclient);
      if(status != STATE_SUCCESS)
        {
          V_w(&pentry->lock);
          LogFullDebug(COMPONENT_STATE, "do_share_op failed");
          *pstatus = status;
          return *pstatus;
        }
    }

  /* Update share state. */
  pstate->state_data.share.share_access = pstate_data->share.share_access;
  pstate->state_data.share.share_deny   = pstate_data->share.share_deny;
  LogFullDebug(COMPONENT_STATE, "pstate %p: downgraded share_access %u, "
               "share_deny %u",
               pstate,
               pstate->state_data.share.share_access,
               pstate->state_data.share.share_deny);

  /* Update the union of share state. */
  pentry->object.file.share_state.share_access = pentry_share_access;
  pentry->object.file.share_state.share_deny = pentry_share_deny;
  LogFullDebug(COMPONENT_STATE, "pentry %p: union of share_access %u, share_deny %u",
               pentry,
               pentry->object.file.share_state.share_access,
               pentry->object.file.share_state.share_deny);

  V_w(&pentry->lock);

  return status;
}

/* Update the bitmap of previously seen share access and deny bits for the
 * given state.
 */
state_status_t state_share_set_prev(state_t      * pstate,
                                    state_data_t * pstate_data)
{
  state_status_t status = STATE_SUCCESS;

  pstate->state_data.share.share_access_prev |=
    (1 << pstate_data->share.share_access);

  pstate->state_data.share.share_deny_prev |=
    (1 << pstate_data->share.share_deny);

  return status;
}

/* Check if the given state has seen the given share access and deny bits
 * before. This is needed when we check validity of open downgrade.
 */
state_status_t state_share_get_prev(state_t      * pstate,
                                    state_data_t * pstate_data)
{
  state_status_t status = STATE_SUCCESS;

  if((pstate->state_data.share.share_access_prev &
     (1 << pstate_data->share.share_access)) == 0)
    return STATE_STATE_ERROR;

  if((pstate->state_data.share.share_deny_prev &
     (1 << pstate_data->share.share_deny)) == 0)
    return STATE_STATE_ERROR;

  return status;
}

/* Check if the given share access and deny bits have conflict with the
 * union of share states of the given file.
 */
state_status_t state_share_check_conflict(cache_entry_t  * pentry,
                                          state_data_t   * pstate_data,
                                          state_status_t * pstatus)
{
  state_status_t status = STATE_SUCCESS;

  P_r(&pentry->lock);

  if((pentry->object.file.share_state.share_access & pstate_data->share.share_deny) ||
     (pentry->object.file.share_state.share_deny & pstate_data->share.share_access))
    {
      V_r(&pentry->lock);
      *pstatus = STATE_STATE_CONFLICT;
      return *pstatus;
    }

  V_r(&pentry->lock);
  return status;
}
