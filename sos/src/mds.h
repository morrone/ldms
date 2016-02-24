/*
 * Copyright (c) 2012 Open Grid Computing, Inc. All rights reserved.
 * Copyright (c) 2012 Sandia Corporation. All rights reserved.
 * Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive
 * license for use of this work by or on behalf of the U.S. Government.
 * Export of this program may require a license from the United States
 * Government.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the BSD-type
 * license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *      Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *      Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 *      Neither the name of Sandia nor the names of any contributors may
 *      be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 *      Neither the name of Open Grid Computing nor the names of any
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
 *
 *      Modified source versions must be plainly marked as such, and
 *      must not be misrepresented as being the original software.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef __MDS_H
#define __MDS_H

#include <stdint.h>
#include "sos.h"

SOS_OBJ_BEGIN(ovis_metric_class, "OvisMetric")
	SOS_OBJ_ATTR_WITH_KEY("tv_sec", SOS_TYPE_UINT32),
	SOS_OBJ_ATTR("tv_usec", SOS_TYPE_UINT32),
	SOS_OBJ_ATTR_WITH_KEY("metric_id", SOS_TYPE_UINT64),
	SOS_OBJ_ATTR("value", SOS_TYPE_UINT64)
SOS_OBJ_END(4);

#define MDS_TV_SEC	0
#define MDS_TV_USEC	1
#define MDS_COMP_ID	2
#define MDS_VALUE	3

typedef struct ovis_record_ss {
	uint32_t sec;
	uint32_t usec;
	uint64_t comp_id;
	uint64_t value;
} ovis_record_s;

typedef ovis_record_s *ovis_record_t;

#define OBJ2OVISREC_S(_s, _o, _r) do { \
	SOS_OBJ_ATTR_GET(_r.sec, _s, 0, _o); \
	SOS_OBJ_ATTR_GET(_r.usec, _s, 1, _o); \
	SOS_OBJ_ATTR_GET(_r.comp_id, _s, 2, _o); \
	SOS_OBJ_ATTR_GET(_r.value, _s, 3, _o); \
} while (0);

#define OBJ2OVISREC_T(_s, _o, _r) do { \
	SOS_OBJ_ATTR_GET(_r->sec, _s, 0, _o); \
	SOS_OBJ_ATTR_GET(_r->usec, _s, 1, _o); \
	SOS_OBJ_ATTR_GET(_r->comp_id, _s, 2, _o); \
	SOS_OBJ_ATTR_GET(_r->value, _s, 3, _o); \
} while (0);

inline
void ovis_rec_store(sos_t sos, ovis_record_t rec)
{
	sos_obj_t obj = sos_obj_new(sos);
	if (!obj) {
		fprintf(stderr, "Cannot create new object\n");
		return ;
	}
	sos_obj_attr_set(sos, MDS_TV_SEC, obj, &rec->sec);
	sos_obj_attr_set(sos, MDS_TV_USEC, obj, &rec->usec);
	sos_obj_attr_set(sos, MDS_COMP_ID, obj, &rec->comp_id);
	sos_obj_attr_set(sos, MDS_VALUE, obj, &rec->value);
	sos_obj_add(sos, obj);
}

#endif