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
#include "common/utils/LOG/log.h"

#include <pthread.h>
#include <time.h>

static pthread_once_t sdap_sched_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t sdap_sched_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t sdap_sched_cond = PTHREAD_COND_INITIALIZER;

static void nr_sdap_sched_add_timeout(struct timespec *deadline)
{
  deadline->tv_nsec += 1000 * 1000;
  if (deadline->tv_nsec >= 1000 * 1000 * 1000) {
    deadline->tv_sec++;
    deadline->tv_nsec -= 1000 * 1000 * 1000;
  }
}

static void *nr_sdap_sched_thread(void *arg)
{
  (void)arg;
  LOG_I(SDAP, "[DRQL][SDAP Sched] scheduler thread started\n");

  while (true) {
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
