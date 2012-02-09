/*
 *
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
 * \file    atomic_counter.h
 * \author  $Author: leibovic $
 * \date    $Date: 2006/02/22 12:02:39 $
 * \version $Revision: 1.43 $
 * \brief   Prototypes for the atomic counter
 *
 * atomic_counter.h : Prototypes for the different threads in the nfs core.
 *
 */

#ifndef _ATOMIC_COUNTER_H
#define _ATOMIC_COUNTER_H

#include <pthread.h>
#include <sys/types.h>
#include <sys/param.h>
#include <time.h>
#include <sys/time.h>

typedef struct atomic_counter__

{
  pthread_mutex_t lock ;
  uint64_t        count ;
} atomic_counter_t ;


void atomic_counter_init( atomic_counter_t * pac ) ;
uint64_t atomic_counter_get( atomic_counter_t * pac ) ;
void atomic_counter_increment( atomic_counter_t * pac ) ;
uint64_t atomic_counter_get_and_increment( atomic_counter_t * pac ) ;


#endif                          /* _ATOMIC_COUNTER_H */
