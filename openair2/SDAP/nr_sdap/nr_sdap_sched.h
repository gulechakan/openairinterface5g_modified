/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

#ifndef NR_SDAP_SCHED_H
#define NR_SDAP_SCHED_H

#include <stdbool.h>
#include <stdint.h>

typedef bool (*nr_sdap_rlc_drql_status_query_t)(int ue_id,
                                                int rb_id,
                                                uint32_t *limit_bytes,
                                                uint32_t *occupancy_bytes,
                                                uint32_t *available_bytes);

void nr_sdap_sched_set_rlc_status_query(nr_sdap_rlc_drql_status_query_t query);
void nr_sdap_sched_start(void);
void nr_sdap_sched_notify(void);

#endif
