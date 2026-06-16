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
#include <stdlib.h>
#include <time.h>

#define SDAP_DRQL_QUEUE_CLASSES 2
#define SDAP_DRQL_BLOCK_COOLDOWN_NS (1000 * 1000)
#define SDAP_DRQL_LOG_BYTE_BUCKET (10 * 1024 * 1024)
#define SDAP_DRQL_MAX_BATCH_PDUS 128
#define SDAP_DRQL_MIN_BATCH_BYTES (64 * 1024)
#define SDAP_DRQL_MAX_BATCH_BYTES (256 * 1024)
#define SDAP_DRQL_AVAILABILITY_BATCH_DIVISOR 4

typedef struct sdap_sched_entity_state_s {
  nr_sdap_entity_t *entity;
  uint64_t blocked_until_ns[SDAP_DRQL_QUEUE_CLASSES];
  struct sdap_sched_entity_state_s *next;
} sdap_sched_entity_state_t;

static pthread_once_t sdap_sched_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t sdap_sched_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t sdap_sched_cond = PTHREAD_COND_INITIALIZER;
static uint64_t sdap_sched_forwarded_packets;
static uint64_t sdap_sched_forwarded_bytes;
static uint64_t sdap_sched_blocked_checks;
static uint64_t sdap_sched_rlc_query_failures;
static uint64_t sdap_sched_passes;
static uint64_t sdap_sched_queue_peeks;
static uint64_t sdap_sched_cooldown_skips;
static uint64_t sdap_sched_missing_mapping;
static uint64_t sdap_sched_available_positive_checks;
static uint64_t sdap_sched_nofit_zero_available;
static uint64_t sdap_sched_nofit_positive_available;
static uint64_t sdap_sched_unused_available_bytes;
static uint64_t sdap_sched_max_observed_queue_bytes;
static uint64_t sdap_sched_last_util_log_ns;
static uint64_t sdap_sched_batch_calls;
static uint64_t sdap_sched_batch_multi_pdu;
static uint64_t sdap_sched_batch_pdu_limited;
static uint64_t sdap_sched_batch_byte_limited;
static uint64_t sdap_sched_batch_target_limited;
static nr_sdap_rlc_drql_status_query_t sdap_sched_rlc_status_query;
static sdap_sched_entity_state_t *sdap_sched_entity_states;

typedef struct sdap_sched_queue_snapshot_s {
  uint64_t queued_bytes;
  uint32_t active_queues;
} sdap_sched_queue_snapshot_t;

static bool sdap_sched_crossed_log_bucket(uint64_t before, uint64_t after)
{
  return before / SDAP_DRQL_LOG_BYTE_BUCKET != after / SDAP_DRQL_LOG_BYTE_BUCKET;
}

static uint64_t sdap_sched_now_ns(void)
{
  struct timespec ts = {0};
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000ULL * 1000ULL * 1000ULL + ts.tv_nsec;
}

static sdap_sched_entity_state_t *sdap_sched_get_entity_state(nr_sdap_entity_t *entity)
{
  for (sdap_sched_entity_state_t *state = sdap_sched_entity_states; state != NULL; state = state->next)
    if (state->entity == entity)
      return state;

  sdap_sched_entity_state_t *state = calloc(1, sizeof(*state));
  if (state == NULL)
    return NULL;

  state->entity = entity;
  state->next = sdap_sched_entity_states;
  sdap_sched_entity_states = state;
  return state;
}

static void nr_sdap_sched_collect_entity_queue(nr_sdap_entity_t *entity, void *data)
{
  sdap_sched_queue_snapshot_t *snapshot = data;

  for (uint8_t queue_class = 0; queue_class < SDAP_DRQL_QUEUE_CLASSES; queue_class++) {
    sdap_sdu_queue_t *queue = &entity->sdap_sdu_pdu_queues[queue_class];

    pthread_mutex_lock(&queue->lock);
    snapshot->queued_bytes += queue->size;
    if (queue->length > 0)
      snapshot->active_queues++;
    pthread_mutex_unlock(&queue->lock);
  }
}

static void nr_sdap_sched_log_util_if_due(bool forwarded)
{
  const uint64_t now_ns = sdap_sched_now_ns();
  if (sdap_sched_last_util_log_ns != 0 && now_ns - sdap_sched_last_util_log_ns < 1000ULL * 1000ULL * 1000ULL)
    return;

  sdap_sched_last_util_log_ns = now_ns;

  sdap_sched_queue_snapshot_t snapshot = {0};
  nr_sdap_for_each_entity(nr_sdap_sched_collect_entity_queue, &snapshot);
  if (snapshot.queued_bytes > sdap_sched_max_observed_queue_bytes)
    sdap_sched_max_observed_queue_bytes = snapshot.queued_bytes;

  LOG_I(SDAP,
        "[DRQL][SDAP Util] passes %llu forwarded_last_pass %d queued_bytes %llu active_queues %u max_queued_bytes %llu forwarded_packets %llu forwarded_bytes %llu queue_peeks %llu available_positive %llu nofit_zero_available %llu nofit_positive_available %llu unused_available_bytes %llu cooldown_skips %llu missing_mapping %llu rlc_query_failures %llu blocked_checks %llu batch_calls %llu batch_multi_pdu %llu batch_pdu_limited %llu batch_byte_limited %llu batch_target_limited %llu\n",
        (unsigned long long)sdap_sched_passes,
        forwarded ? 1 : 0,
        (unsigned long long)snapshot.queued_bytes,
        snapshot.active_queues,
        (unsigned long long)sdap_sched_max_observed_queue_bytes,
        (unsigned long long)sdap_sched_forwarded_packets,
        (unsigned long long)sdap_sched_forwarded_bytes,
        (unsigned long long)sdap_sched_queue_peeks,
        (unsigned long long)sdap_sched_available_positive_checks,
        (unsigned long long)sdap_sched_nofit_zero_available,
        (unsigned long long)sdap_sched_nofit_positive_available,
        (unsigned long long)sdap_sched_unused_available_bytes,
        (unsigned long long)sdap_sched_cooldown_skips,
        (unsigned long long)sdap_sched_missing_mapping,
        (unsigned long long)sdap_sched_rlc_query_failures,
        (unsigned long long)sdap_sched_blocked_checks,
        (unsigned long long)sdap_sched_batch_calls,
        (unsigned long long)sdap_sched_batch_multi_pdu,
        (unsigned long long)sdap_sched_batch_pdu_limited,
        (unsigned long long)sdap_sched_batch_byte_limited,
        (unsigned long long)sdap_sched_batch_target_limited);
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
  bool forwarded_any = false;
  uint32_t batch_pdus = 0;
  uint32_t batch_bytes = 0;
  uint32_t target_batch_bytes = SDAP_DRQL_MIN_BATCH_BYTES;

  sdap_sched_batch_calls++;

  while (batch_pdus < SDAP_DRQL_MAX_BATCH_PDUS && batch_bytes < SDAP_DRQL_MAX_BATCH_BYTES) {
    nr_sdap_dl_queue_head_t head = {0};
    if (!nr_sdap_dl_peek_sdu(entity, queue_class, &head))
      break;

    sdap_sched_queue_peeks++;
    if (head.queue_size > sdap_sched_max_observed_queue_bytes)
      sdap_sched_max_observed_queue_bytes = head.queue_size;

    const uint64_t now_ns = sdap_sched_now_ns();
    sdap_sched_entity_state_t *state = sdap_sched_get_entity_state(entity);
    if (state != NULL && state->blocked_until_ns[queue_class] > now_ns) {
      sdap_sched_cooldown_skips++;
      break;
    }

    rb_id_t drb_id = entity->qfi2drb_map(entity, head.qfi);
    if (drb_id == SDAP_MAP_RULE_EMPTY) {
      sdap_sched_missing_mapping++;
      break;
    }

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
      break;
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
      break;
    }

    if (available_bytes > 0)
      sdap_sched_available_positive_checks++;

    target_batch_bytes = available_bytes / SDAP_DRQL_AVAILABILITY_BATCH_DIVISOR;
    if (target_batch_bytes < SDAP_DRQL_MIN_BATCH_BYTES)
      target_batch_bytes = SDAP_DRQL_MIN_BATCH_BYTES;
    if (target_batch_bytes > SDAP_DRQL_MAX_BATCH_BYTES)
      target_batch_bytes = SDAP_DRQL_MAX_BATCH_BYTES;

    const uint32_t pdu_bytes = head.sdu_buffer_size + SDAP_HDR_LENGTH;
    if (pdu_bytes > available_bytes) {
      if (available_bytes == 0)
        sdap_sched_nofit_zero_available++;
      else {
        sdap_sched_nofit_positive_available++;
        sdap_sched_unused_available_bytes += available_bytes;
      }

      if (state != NULL)
        state->blocked_until_ns[queue_class] = now_ns + SDAP_DRQL_BLOCK_COOLDOWN_NS;

      sdap_sched_blocked_checks++;
      if (sdap_sched_blocked_checks <= 10 || sdap_sched_blocked_checks % 100000 == 0)
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
      break;
    }

    if (batch_pdus > 0 && batch_bytes + pdu_bytes > target_batch_bytes) {
      sdap_sched_batch_target_limited++;
      break;
    }

    if (batch_bytes + pdu_bytes > SDAP_DRQL_MAX_BATCH_BYTES) {
      sdap_sched_batch_byte_limited++;
      break;
    }

    sdap_sdu_pdu_t *item = entity->dl_dequeue_pdu(entity, queue_class);
    if (item == NULL)
      break;

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
      if (state != NULL)
        state->blocked_until_ns[queue_class] = 0;

      const uint64_t forwarded_bytes_before = sdap_sched_forwarded_bytes;
      sdap_sched_forwarded_packets++;
      sdap_sched_forwarded_bytes += pdu_bytes;
      batch_pdus++;
      batch_bytes += pdu_bytes;
      forwarded_any = true;

      if (sdap_sched_forwarded_packets <= 10
          || sdap_sched_forwarded_packets % 10000 == 0
          || sdap_sched_crossed_log_bucket(forwarded_bytes_before, sdap_sched_forwarded_bytes))
        LOG_I(SDAP,
              "[DRQL][SDAP Sched] forwarded UE %lu DRB %ld QFI %u queue_class %u pdu_bytes %u limit %u occupancy %u available %u queue_length_before %u queue_bytes_before %u forwarded_packets %llu forwarded_bytes %llu batch_pdus %u batch_bytes %u\n",
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
              (unsigned long long)sdap_sched_forwarded_bytes,
              batch_pdus,
              batch_bytes);
    }

    nr_sdap_free_queued_sdu(item);
    if (!ret)
      break;
  }

  if (batch_pdus > 1)
    sdap_sched_batch_multi_pdu++;
  if (batch_pdus == SDAP_DRQL_MAX_BATCH_PDUS)
    sdap_sched_batch_pdu_limited++;

  return forwarded_any;
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
    if (nr_sdap_drql_is_enabled()) {
      sdap_sched_passes++;
      nr_sdap_for_each_entity(nr_sdap_sched_try_forward_entity, &forwarded);
      nr_sdap_sched_log_util_if_due(forwarded);
    }

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
