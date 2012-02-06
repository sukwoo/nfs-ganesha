/**
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
 *
 * nfs_session_id.c : The management of the session id cache.
 *
 * $Header$
 *
 * $Log$
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
#include <pthread.h>
#include "atomic_counter.h"

void atomic_counter_init( atomic_counter_t * pac )
{
  if( pac == NULL ) return -1 ;

  pthread_mutex_init( &pac->lock, NULL ) ;
  pac->count = 0LL ;
} /* atomic_counter_init */

uint64_t atomic_counter_get( atomic_counter_t * pac )
{
  uint64_t val64 ;

  pthread_mutex_lock( &pac->lock ) ;
  val64 = pac->count ;
  pthread_mutex_unlock( &pac->lock ) ;

  return val64 ;
} /* atomic_count_get */

void atomic_counter_increment( atomic_counter_t * pac )
{
  pthread_mutex_lock( &pac->lock ) ;
  pac->count += 1 ;
  pthread_mutex_unlock( &pac->lock ) ;
} /* atomic_counter_increment */

uint64_t atomic_counter_get_and_increment( atomic_counter_t * pac )
{
  uint64_t val64 ;

  pthread_mutex_lock( &pac->lock ) ;
  val64 = pac->count ;
  pac->count += 1 ;
  pthread_mutex_unlock( &pac->lock ) ;

  return val64 ;
} /* atomic_counter_get_and_increment */


