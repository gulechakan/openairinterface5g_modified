#ifndef NR_SDAP_SCHEDULER_H_
#define NR_SDAP_SCHEDULER_H_

#include "openair2/F1AP/drql_common.h"

void *sdap_dl_scheduler(void *arguments);
void *sdap_analysis(void *arguments);
void *sdap_predictions_receiver(void *arguments);

void rlc_information(int ue_id,
                       int drb_id,
                       int *real_limit,
                       int *limit,
                       int *real_actual_size,
                       int *actual_size);

extern FILE *dataset_file;
extern sdap_rlc_response_t *sdap_rlc_response;
extern sdap_rlc_prediction_list_t *sdap_rlc_prediction_list;

#endif