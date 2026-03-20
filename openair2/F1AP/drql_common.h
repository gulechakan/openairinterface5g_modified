// HakanGulec: Structs used for DRQL

#ifndef DRQL_H_
#define DRQL_H_

#pragma once

#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>


#define REQUEST_SIZE 1024


// Requests
#define SDAP_RLC_INDICATION_REQUEST 0

// Responses
#define SDAP_RLC_INDICATION_REQUEST 10


typedef struct sdap_rlc_response_s {

    volatile int acknowledgement_number;
    char         packet[REQUEST_SIZE];

    // This lock is used to synchronize the SCTP thread with 
    // the SDAP scheduler since unexpected behavior is observed
    pthread_mutex_t lock;

} sdap_rlc_response_t;

typedef struct tx_limit_prediction_node_s {
    
    int                                 index;
    unsigned long                       timestamp_in_microseconds;
    uint32_t                            predictions_length;
    uint32_t                            *predictions;
    long long                           *timestamps;
    struct tx_limit_prediction_node_s   *nxt;
    struct tx_limit_prediction_node_s   *prev; 

} tx_limit_prediction_node_t;


typedef struct tx_actual_size_prediction_node_s {
    
    int                                 index;
    unsigned long                       timestamp_in_microseconds;
    uint32_t                            predictions_length;
    uint32_t                            *predictions;
    long long                           *timestamps;
    struct tx_limit_prediction_node_s   *nxt;
    struct tx_limit_prediction_node_s   *prev; 

} tx_actual_size_prediction_node_t;


typedef struct sdap_rlc_prediction_list_s {

    pthread_mutex_t tx_limit_predictions_mutex;
    pthread_mutex_t tx_actual_size_predictions_mutex;

    tx_limit_prediction_node_t *tx_limit_predictions_head;
    tx_limit_prediction_node_t *tx_limit_predictions_tail;

    tx_actual_size_prediction_node_t *tx_actual_size_predictions_head;
    tx_actual_size_prediction_node_t *tx_actual_size_predictions_tail;

} sdap_rlc_prediction_list_t;

// Custom Parameters for DRQL
typedef struct {

    bool        ric_enabled;
    uint32_t    drql_threshold;

} custom_parameters_t;

extern custom_parameters_t  custom_parameters;
extern bool                 testing_port;
 
void *du_handle_plain_text_indication_request(void *arguments);
char *extract_substring_between_patterns(char *string, const char *left_pattern, const char *right_pattern);


#endif

// HakanGulec: Some of them might be unnecessary since they are used for ML predictions.