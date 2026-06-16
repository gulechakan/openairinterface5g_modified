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

#include "nr_sdap_sched.h"
#include "nr_sdap_drql.h"
#include "nr_sdap_entity.h"
#include "common/utils/LOG/log.h"

#include <pthread.h>
#include <stdint.h>
#include <time.h>

#define SDAP_DRQL_QUEUE_CLASSES 2
#define SDAP_DRQL_LOG_BYTE_BUCKET (10 * 1024 * 1024)

static pthread_once_t sdap_sched_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t sdap_sched_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t sdap_sched_cond = PTHREAD_COND_INITIALIZER;
static uint64_t sdap_sched_forwarded_packets;
static uint64_t sdap_sched_forwarded_bytes;
static uint64_t sdap_sched_blocked_checks;
static uint64_t sdap_sched_rlc_query_failures;
static nr_sdap_rlc_drql_status_query_t sdap_sched_rlc_status_query;

static bool sdap_sched_crossed_log_bucket(uint64_t before, uint64_t after)
{
  return before / SDAP_DRQL_LOG_BYTE_BUCKET != after / SDAP_DRQL_LOG_BYTE_BUCKET;
}

void nr_sdap_sched_set_rlc_status_query(nr_sdap_rlc_drql_status_query_t query)
{
  sdap_sched_rlc_status_query = query;
}

static void nr_sdap_sched_add_timeout(struct timespec *deadline)
{
  deadline->tv_nsec += 1000 * 1000;
  if (deadline->tv_nsec >= 1000 * 1000 * 1000) {
    deadline->tv_sec++;
    deadline->tv_nsec -= 1000 * 1000 * 1000;
  }
}

static bool nr_sdap_sched_try_forward_queue(nr_sdap_entity_t *entity, uint8_t queue_class)
{
  nr_sdap_dl_queue_head_t head = {0};
  if (!nr_sdap_dl_peek_sdu(entity, queue_class, &head))
    return false;

  rb_id_t drb_id = entity->qfi2drb_map(entity, head.qfi);
  if (drb_id == SDAP_MAP_RULE_EMPTY)
    return false;

  uint32_t limit_bytes = 0;
  uint32_t occupancy_bytes = 0;
  uint32_t available_bytes = 0;
  if (sdap_sched_rlc_status_query == NULL) {
    sdap_sched_rlc_query_failures++;
    if (sdap_sched_rlc_query_failures % 1000 == 1)
      LOG_I(SDAP,
            "[DRQL][SDAP Sched] RLC query callback missing entity UE %lu head UE %lu DRB %ld QFI %u queue_class %u failures %llu\n",
            (unsigned long)entity->ue_id,
            (unsigned long)head.ue_id,
            (long)drb_id,
            (unsigned)head.qfi,
            (unsigned)queue_class,
            (unsigned long long)sdap_sched_rlc_query_failures);
    return false;
  }

  if (!sdap_sched_rlc_status_query((int)head.ue_id, (int)drb_id, &limit_bytes, &occupancy_bytes, &available_bytes)) {
    sdap_sched_rlc_query_failures++;
    if (sdap_sched_rlc_query_failures % 1000 == 1)
      LOG_I(SDAP,
            "[DRQL][SDAP Sched] RLC query returned false entity UE %lu head UE %lu DRB %ld QFI %u queue_class %u failures %llu\n",
            (unsigned long)entity->ue_id,
            (unsigned long)head.ue_id,
            (long)drb_id,
            (unsigned)head.qfi,
            (unsigned)queue_class,
            (unsigned long long)sdap_sched_rlc_query_failures);
    return false;
  }

  const uint32_t pdu_bytes = head.sdu_buffer_size + SDAP_HDR_LENGTH;
  if (pdu_bytes > available_bytes) {
    sdap_sched_blocked_checks++;
    if (sdap_sched_blocked_checks % 1000 == 1)
      LOG_I(SDAP,
            "[DRQL][SDAP Sched] blocked UE %lu DRB %ld QFI %u queue_class %u pdu_bytes %u limit %u occupancy %u available %u queue_length %u queue_bytes %u checks %llu\n",
            (unsigned long)entity->ue_id,
            (long)drb_id,
            (unsigned)head.qfi,
            (unsigned)queue_class,
            pdu_bytes,
            limit_bytes,
            occupancy_bytes,
            available_bytes,
            head.queue_length,
            head.queue_size,
            (unsigned long long)sdap_sched_blocked_checks);
    return false;
  }

  sdap_sdu_pdu_t *item = entity->dl_dequeue_pdu(entity, queue_class);
  if (item == NULL)
    return false;

  const uint32_t *source_l2_id = item->has_source_l2_id ? &item->source_l2_id : NULL;
  const uint32_t *destination_l2_id = item->has_destination_l2_id ? &item->destination_l2_id : NULL;

  const bool ret = entity->tx_entity(entity,
                                     &item->ctxt,
                                     item->srb_flag,
                                     item->rb_id,
                                     item->mui,
                                     item->confirm,
                                     item->sdu_buffer_size,
                                     item->sdu_buffer,
                                     item->pt_mode,
                                     source_l2_id,
                                     destination_l2_id,
                                     item->qfi,
                                     item->rqi);
  if (!ret)
    LOG_E(SDAP,
          "[DRQL][SDAP Sched] tx_entity refused UE %lu DRB %ld QFI %u queue_class %u sdu_bytes %u\n",
          (unsigned long)entity->ue_id,
          (long)drb_id,
          (unsigned)item->qfi,
          (unsigned)queue_class,
          (unsigned)item->sdu_buffer_size);

  if (ret) {
    const uint64_t forwarded_bytes_before = sdap_sched_forwarded_bytes;
    sdap_sched_forwarded_packets++;
    sdap_sched_forwarded_bytes += pdu_bytes;
    if (sdap_sched_forwarded_packets <= 10
        || sdap_sched_forwarded_packets % 10000 == 0
        || sdap_sched_crossed_log_bucket(forwarded_bytes_before, sdap_sched_forwarded_bytes))
      LOG_I(SDAP,
            "[DRQL][SDAP Sched] forwarded UE %lu DRB %ld QFI %u queue_class %u pdu_bytes %u limit %u occupancy %u available %u queue_length_before %u queue_bytes_before %u forwarded_packets %llu forwarded_bytes %llu\n",
            (unsigned long)entity->ue_id,
            (long)drb_id,
            (unsigned)item->qfi,
            (unsigned)queue_class,
            pdu_bytes,
            limit_bytes,
            occupancy_bytes,
            available_bytes,
            head.queue_length,
            head.queue_size,
            (unsigned long long)sdap_sched_forwarded_packets,
            (unsigned long long)sdap_sched_forwarded_bytes);
  }

  nr_sdap_free_queued_sdu(item);
  return ret;
}

static void nr_sdap_sched_try_forward_entity(nr_sdap_entity_t *entity, void *data)
{
  bool *forwarded = data;

  for (uint8_t queue_class = 0; queue_class < SDAP_DRQL_QUEUE_CLASSES; queue_class++) {
    if (nr_sdap_sched_try_forward_queue(entity, queue_class))
      *forwarded = true;
  }
}

static void *nr_sdap_sched_thread(void *arg)
{
  (void)arg;
  LOG_I(SDAP, "[DRQL][SDAP Sched] scheduler thread started\n");

  while (true) {
    bool forwarded = false;
    if (nr_sdap_drql_is_enabled())
      nr_sdap_for_each_entity(nr_sdap_sched_try_forward_entity, &forwarded);

    if (forwarded)
      continue;

    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    nr_sdap_sched_add_timeout(&deadline);

    pthread_mutex_lock(&sdap_sched_lock);
    pthread_cond_timedwait(&sdap_sched_cond, &sdap_sched_lock, &deadline);
    pthread_mutex_unlock(&sdap_sched_lock);
  }

  return NULL;
}

static void nr_sdap_sched_start_once(void)
{
  pthread_t thread;
  const int ret = pthread_create(&thread, NULL, nr_sdap_sched_thread, NULL);
  if (ret != 0) {
    LOG_E(SDAP, "[DRQL][SDAP Sched] failed to start scheduler thread: %d\n", ret);
    return;
  }
  pthread_detach(thread);
}

void nr_sdap_sched_start(void)
{
  if (!nr_sdap_drql_is_enabled())
    return;

  pthread_once(&sdap_sched_once, nr_sdap_sched_start_once);
}

void nr_sdap_sched_notify(void)
{
  pthread_mutex_lock(&sdap_sched_lock);
  pthread_cond_signal(&sdap_sched_cond);
  pthread_mutex_unlock(&sdap_sched_lock);
}
