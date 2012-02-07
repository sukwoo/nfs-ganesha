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
 * \file    nfs_rpc_tcp_socket_manager_thread.c
 * \author  $Author: deniel $
 * \date    $Date: 2006/02/23 12:33:05 $
 * \version $Revision: 1.96 $
 * \brief   The file that contain the 'rpc_tcp_socket_manager_thread' routine for the nfsd.
 *
 * nfs_rpc_dispatcher.c : The file that contain the 'rpc_tcp_socket_manager_thread.c' routine for the nfsd (and all
 * the related stuff).
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef _SOLARIS
#include "solaris_port.h"
#endif

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/file.h>           /* for having FNDELAY */
#include <sys/select.h>
#include "HashData.h"
#include "HashTable.h"
#include "rpc.h"
#include "log_macros.h"
#include "stuff_alloc.h"
#include "nfs23.h"
#include "nfs4.h"
#include "mount.h"
#include "nfs_core.h"
#include "cache_inode.h"
#include "cache_content.h"
#include "nfs_exports.h"
#include "nfs_creds.h"
#include "nfs_proto_functions.h"
#include "nfs_dupreq.h"
#include "nfs_file_handle.h"
#include "nfs_stat.h"
#include "SemN.h"
#include "atomic_counter.h" 

/**
 * rpc_tcp_socket_manager_thread: manages a TCP socket connected to a client.
 *
 * this thread will manage a connection related to a specific TCP client.
 *
 * @param IndexArg contains the socket number to be managed by this thread
 *
 * @return Pointer to the result (but this function will mostly loop forever).
 *
 */
void *rpc_tcp_socket_manager_thread(void *Arg)
{
#ifndef _NO_BUDDY_SYSTEM
  int rc = 0;
#endif
  long int tcp_sock = (long int)Arg;
  static char my_name[MAXNAMLEN];
  fridge_entry_t * pfe = NULL;
  process_status_t status;
  hash_table_t * ht_sock = NULL ;
  unsigned int passcount = 0 ;
   
  snprintf(my_name, MAXNAMLEN, "tcp_sock_mgr#fd=%ld", tcp_sock);
  SetNameFunction(my_name);

#ifndef _NO_BUDDY_SYSTEM
  if((rc = BuddyInit(&nfs_param.buddy_param_tcp_mgr)) != BUDDY_SUCCESS)
    {
      /* Failed init */
      #ifdef _DEBUG_MEMLEAKS
      {
        FILE *output = fopen("/tmp/buddymem", "w");
        if (output != NULL)
          BuddyDumpAll(output);
      }
      #endif
      LogFatal(COMPONENT_DISPATCH, "Memory manager could not be initialized");
    }
#endif

  /* Calling dispatcher main loop */
  LogDebug(COMPONENT_DISPATCH,
           "Starting with pthread id #%p",
           (caddr_t) pthread_self());

  /* Init the hash table for TCP DRC associated with this connection */
  if((ht_sock = HashTable_Init(nfs_param.dupreq_tcp_param.hash_param)) == NULL)
    {
      LogCrit(COMPONENT_DUPREQ,
              "Cannot init the duplicate request hash table for socket %lu", tcp_sock);
      return NULL;
    }
  TCP_DRC_HashTables[tcp_sock] = ht_sock ; 

  /* Init the atomic counter */
  atomic_counter_init( &TCP_DRC_acount[tcp_sock] ) ;

  for(;;)
    {
      if(Xports[tcp_sock] == NULL)
        {
          /* But do we control sock? */
          LogMajor(COMPONENT_DISPATCH,
                   "Incoherency found in Xports array! Exiting...");
          Fatal();
        }

      /*
       * UDP RPCs are quite simple: everything comes to the same socket, so several SVCXPRT
       * can be defined, one per tbuf to handle the stuff
       * TCP RPCs are more complex:
       *   - a unique SVCXPRT exists that deals with initial tcp rendez vous. It does the accept
       *     with the client, but recv no message from the client. But SVC_RECV on it creates
       *     a new SVCXPRT dedicated to the client. This specific SVXPRT is bound on TCPSocket
       *
       * while receiving something on the Svc_fdset, I must know if this is a UDP request,
       * an initial TCP request or a TCP socket from an already connected client.
       * This is how to distinguish the cases:
       * UDP connections are bound to socket NFS_UDPSocket
       * TCP initial connections are bound to socket NFS_TCPSocket
       * all the other cases are requests from already connected TCP Clients
       */

      LogFullDebug(COMPONENT_DISPATCH,
                   "A NFS TCP request from an already connected client");

      status = process_rpc_request(Xports[tcp_sock]);

      if(status == PROCESS_LOST_CONN)
        {
          /* We lost our connection */
         LogDebug(COMPONENT_DISPATCH,
                  "Freezing thread %p",
                  (caddr_t)pthread_self());

          if( ( pfe = fridgethr_freeze( ) ) == NULL )
            {

                  break;
            }

          tcp_sock = (long int )pfe->arg;
          LogDebug(COMPONENT_DISPATCH,
                   "Now working on sock=%d after going out of the fridge",
                   (int)tcp_sock);
          snprintf(my_name, MAXNAMLEN, "tcp_sock_mgr#fd=%ld", tcp_sock);
          SetNameFunction(my_name);

          continue;
        }

      if( passcount++ > DUPREQ_TCP_GC_PERIOD )
        {
          nfs_tcp_dupreq_gc( tcp_sock ) ;
          passcount = 0 ;
        }
    }

  /* Fridge expiration, the thread and exit */
  LogDebug(COMPONENT_DISPATCH,
           "TCP connection manager has expired in the fridge, stopping");
           
  printf( "TCP connection manager has expired in the fridge, stopping\n");

  /* No more tcp dupreq hash table */
  if( HashTable_Destroy(  ht_sock, NULL ) == HASHTABLE_SUCCESS )
   LogDebug( COMPONENT_DISPATCH, "Ok cleaning TCP dupreq hash table for socket %ld", tcp_sock ) ;
  else
   LogMajor( COMPONENT_DISPATCH, "Failure while cleaning RCP dupreq hash table for dead tcp_scok_mgr#fd=%ld", tcp_sock ) ;

#ifndef _NO_BUDDY_SYSTEM
  /* Free stuff allocated by BuddyMalloc before thread exists */
  if((rc = BuddyDestroy()) != BUDDY_SUCCESS)
    LogCrit(COMPONENT_DISPATCH,
            "Error %d from BuddyDestroy",
            (int)rc);
#endif                          /*  _NO_BUDDY_SYSTEM */

  return NULL;
}                               /* rpc_tcp_socket_manager_thread */
