#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
 #include <stdlib.h>
#include "nr_sdap_entity.h"
#include "nr_sdap_sched.h"
#include "openair2/F1AP/drql_common.h"
#include "openair2/analysis_conf.h"


int sequence_number = 0;



typedef struct predictions {
  volatile long double timestamp;
  int *actual_size_array;
  volatile int actual_size_array_length;

  char debug_buffer[1024];
} predictions_t;

typedef struct analysis {
  volatile long double timestamp;

  volatile long false_positive_counter; // Example predicted: 10, actual size: 5 and SDAP wants to forward 6 (and forwards it even though it shouldn't)
  volatile long false_negative_counter; // Example predicted: 5, actual size: 10 and SDAP wants to forward 6 (and does not forward even though it would actual could)  
  volatile long false_positive_negative_counter;

  volatile long dl_bytes_dequeued;

} analysis_t;


pthread_mutex_t predictions_mutex;
predictions_t predictions = {0};

pthread_mutex_t analysis_mutex;
analysis_t analysis = {0};


// Retrieve RLC information from all RLC entities based on a sequence number from openairinterface5g-drql/openair2/F1AP/f1ap_du_interface_management.c (du_handle_plain_text_indication_request())
void query_sdap_rlc(int socket_fd, int drb, int *limit, int *actual_size){
  char buffer[REQUEST_SIZE];
  char response[REQUEST_SIZE];
  // char *type_str;
  char *acknowledgement_number_str;


  char *limit_str;
  char *actual_size_str;

  memset(buffer, 0, REQUEST_SIZE * sizeof(char));

  sprintf(buffer + strlen(buffer), "{Type:%d,SEQ:%d,DRB:%d}", SDAP_RLC_INDICATION_REQUEST, sequence_number, drb);

  while(1){
    // SDAP queries limit and actual size of RLC entities buffers
    if(write(socket_fd, buffer, sizeof(buffer) * sizeof(char)) < 0){
      printf("[ERROR] On write() in query_sdap_rlc()\n"); 
      fflush(stdout);
      continue;
    }  
  

    memset(response, 0, REQUEST_SIZE * sizeof(char));
    
    if(read(socket_fd, response, REQUEST_SIZE * sizeof(char)) < 0){
      printf("READ ERROR\n"); 
      fflush(stdout);
      continue;
    
    }

    // type_str = extract_substring_between_patterns((char *) response, "{Type:", ",");    
    acknowledgement_number_str = extract_substring_between_patterns((char *) response, "ACK:", ",");

    // Response still pending
    if(atoi(acknowledgement_number_str) < sequence_number + 1){
      continue;
    }

    // Response received
    break;
  }

  // Handling ONE UE with ONE DRB at this implementation this must be improved
  // to parse data from string and easily process. This is the MVP implementation
  // Mapping of SDAP entities (QFIs) to RLC (DRBs) must also be handled later on 
  limit_str = extract_substring_between_patterns(response, "tx_maxsize:", ",");
  *limit = atoi(limit_str);
  
  actual_size_str = extract_substring_between_patterns(response, "tx_size:", "}");
  *actual_size = atoi(actual_size_str);
  // ********************************************************************************************************//

  sequence_number++;
}


int minimum(int a, int b) {
  return (a < b) ? a : b;
}

void rlc_information(int socket_fd, int testing_socket_fd, int drb, int *real_limit, int *limit, int *real_actual_size, int *actual_size){
  *limit = -1;
  *real_limit = -1;

  *actual_size = -1;
  *real_actual_size = -1;

  int slope;
  int intercept;
  long double current_time_in_milliseconds;

  // No Predictions or RIC is Disabled (CU/DU Direct Communication)
  if(!predictions.actual_size_array_length || !custom_parameters.ric_enabled){
    LOG_E(SDAP, "DRQL no predictions or RIC is disabled query RLC from SDAP\n");
    query_sdap_rlc(socket_fd, drb, limit, actual_size);
    return;
  }

  current_time_in_milliseconds = get_time_in_ms(); 

  pthread_mutex_lock(&predictions_mutex);
  int prediction_index = (int) (current_time_in_milliseconds - predictions.timestamp);
  prediction_index = prediction_index > predictions.actual_size_array_length - 2 ? -1 : prediction_index; // -2 to exclude the last element, since we can not interpolate there
  printf("+++ Index %d\n", prediction_index);
  if(prediction_index < 0){
    pthread_mutex_unlock(&predictions_mutex);
    return;
  }
  
  // Actual Size
  slope = predictions.actual_size_array[prediction_index + 1] - predictions.actual_size_array[prediction_index]; 
  intercept = predictions.actual_size_array[prediction_index];
  *actual_size = (int) ((current_time_in_milliseconds - (predictions.timestamp + prediction_index)) * slope + intercept);
  LOG_I(SDAP, "Actual Size %d from %d and %d on index %d\n", *actual_size, predictions.actual_size_array[prediction_index], predictions.actual_size_array[prediction_index + 1], prediction_index);

  if(*actual_size < 0){
    *actual_size = 0;
  }
  

#ifdef SDAP_STATS_PERSIST
    // Do not add latency in this case
    query_sdap_rlc(testing_socket_fd, drb, real_limit, real_actual_size);
#endif

  pthread_mutex_unlock(&predictions_mutex);

  LOG_D(SDAP, "Predicted Limit %d and Actual Size %d\n", *limit, *actual_size);
}



void *sdap_e2ap_listener(void *args) {
  int server_socket, client_socket;
  struct sockaddr_in server_addr, client_addr;
  char buffer[1024];
  char qfi_stats_str[1024];

  // Create socket
  if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    perror("Socket creation failed");
    exit(EXIT_FAILURE);
  }

  // Prepare the server address struct
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(9000);

  // Bind the socket
  if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
    perror("Binding failed");
    exit(EXIT_FAILURE);
  }

  // Listen for connections
  if (listen(server_socket, 5) == -1) {
    perror("Listening failed");
    exit(EXIT_FAILURE);
  }

  printf("Server is listening on port 9000...\n");

   // Accept incoming connection
  socklen_t client_addr_len = sizeof(client_addr);
  if ((client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len)) == -1) {
      perror("Accepting connection failed");
      exit(EXIT_FAILURE);
  }

  printf("Connection accepted from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

  while (1) {
    // Receive data from client
    ssize_t bytes_received = recv(client_socket, buffer, 1024, 0);
    if (bytes_received <= 0) {
      printf("Client disconnected.\n");
      break;
    }


    // Build and send the response
    memset(buffer, 0, 1024 * sizeof(char));
    
    sprintf(buffer, "{");

    // Iterate SDAP Entities
    for(struct nr_sdap_entity_s *sdap_entity = sdap_info.sdap_entity_llist; sdap_entity != NULL; sdap_entity = sdap_entity->next_entity){  
      
      memset(qfi_stats_str, 0, 1024 * sizeof(char));
      long double current_time_in_milliseconds = get_time_in_ms();
      int length = 0;
      int size = 0; 
      int tx_sdu_bytes = 0;
      int tx_pdu_bytes = 0;

      for(int qfi = 0; qfi < SDAP_MAX_QFI; qfi++){        
        if(!sdap_entity->sdap_sdu_pdu_queues[qfi].enabled){
          continue;
        }

        length += sdap_entity->sdap_sdu_pdu_queues[qfi].length; 
        size += sdap_entity->sdap_sdu_pdu_queues[qfi].size;
        tx_sdu_bytes += sdap_entity->sdap_sdu_pdu_queues[qfi].tx_sdu_bytes;
        tx_pdu_bytes += sdap_entity->sdap_sdu_pdu_queues[qfi].tx_pdu_bytes;

        // sprintf(qfi_stats_str + strlen(qfi_stats_str), 
        //   "\"%d\":{\"length\":%d, \"size\":%d, \"tx_sdu_bytes\":%d, \"tx_pdu_bytes\":%d},", 
        //   qfi, sdap_entity->sdap_sdu_pdu_queues[qfi].length, sdap_entity->sdap_sdu_pdu_queues[qfi].size, 
        //   sdap_entity->sdap_sdu_pdu_queues[qfi].tx_sdu_bytes, sdap_entity->sdap_sdu_pdu_queues[qfi].tx_pdu_bytes);

      }
      
      sprintf(qfi_stats_str + strlen(qfi_stats_str), 
          "\"%Lf\":{\"length\":%d, \"size\":%d, \"tx_sdu_bytes\":%d, \"tx_pdu_bytes\":%d},", 
          current_time_in_milliseconds, length, size, tx_sdu_bytes, tx_pdu_bytes);

      qfi_stats_str[strlen(qfi_stats_str) - 1] = '\0'; // Remove tailing comma

      if(strlen(qfi_stats_str) > 0){
        sprintf(buffer + strlen(buffer), "\"%ld\":{%s},", sdap_entity->ue_id, qfi_stats_str);
      }
    }

    if(buffer[strlen(buffer) - 1] != '{'){
      buffer[strlen(buffer) - 1] = '\0'; // Remove tailing comma
    } 
    sprintf(buffer + strlen(buffer), "}");

    // Send data back to client
    LOG_D(SDAP, "Sending %s to RIC\n", buffer);
    send(client_socket, buffer, strlen(buffer), 0);
  }

  // Close client socket
  close(client_socket);

  // Close server socket
  close(server_socket);

  return NULL;
}



void *sdap_analysis(void *arguments){
  long long last_time_ms;
  FILE *sdap_analysis_fp;

  sdap_analysis_fp = fopen("sdap_tx_analysis.csv", "a+");

  if(!sdap_analysis_fp){
    LOG_E(SDAP, "Failed to create sdap_tx_analysis.csv...\n");

    exit(EXIT_FAILURE);
  }
  fseek(sdap_analysis_fp, 0, SEEK_SET);
  if(ftruncate(fileno(sdap_analysis_fp), 0) != 0){
    exit(EXIT_FAILURE);
  }

  // limit_percentage_error: (real_limit - predicted_limit / real_limit) * 100
  fprintf(sdap_analysis_fp, "time_s,throughput_mbps,false_positives_percentage,false_negatives_percentage\n");
  fflush(sdap_analysis_fp);

  memset(&analysis, 0, sizeof(analysis));
  while(1){
    last_time_ms = get_time_in_ms();

    usleep(1000 * 1000);

    pthread_mutex_lock(&analysis_mutex);

    if (!analysis.false_positive_negative_counter){
      pthread_mutex_unlock(&analysis_mutex);
      continue;
    }
    
    double false_positive_percentage = (double) (analysis.false_positive_counter * 100) / analysis.false_positive_negative_counter;
    double false_negative_percentage = (double) (analysis.false_negative_counter * 100) / analysis.false_positive_negative_counter;

    double throughput = ((double) analysis.dl_bytes_dequeued * 8) / ((get_time_in_ms() - last_time_ms) * 0.001) / 1e6;
    fprintf(sdap_analysis_fp, "%d,%f,%f,%f\n", (int) (get_time_in_ms() / 1e3), throughput, false_positive_percentage, false_negative_percentage); 
    fflush(sdap_analysis_fp);

    memset(&analysis, 0, sizeof(analysis));

    pthread_mutex_unlock(&analysis_mutex);
  }
  
  return NULL;
}


void *sdap_dl_scheduler(void *arguments){
  // Response int fields
  int limit;
  int actual_size;

  int real_limit; // When compare predictions to the real limit
  int real_actual_size; // When compare predictions to the real actual size

  sdap_sdu_pdu_t *sdap_pdu; 

	int socket_fd;
  int testing_socket_fd;
 	struct sockaddr_in servaddr;
 	struct sockaddr_in testing_servaddr;

	socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	assert(socket_fd != -1);
  
	testing_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	assert(testing_socket_fd != -1);

  int reuse = 1;
  assert(setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) != -1);
  assert(setsockopt(testing_socket_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) != -1);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	servaddr.sin_port = htons(8060);
  assert((bind(socket_fd, (struct sockaddr *) &servaddr, sizeof(servaddr))) != -1);
	
  servaddr.sin_port = htons(8080);
  while(connect(socket_fd, (struct sockaddr *) &servaddr, sizeof(servaddr)) != 0);
  LOG_E(SDAP, "[DRQL]: Connected to latency socket 8060 (CU) -> 8080 (DU)\n");


  bzero(&testing_servaddr, sizeof(testing_servaddr));
	testing_servaddr.sin_family = AF_INET;
	testing_servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	testing_servaddr.sin_port = htons(8070);
  assert((bind(testing_socket_fd, (struct sockaddr *) &testing_servaddr, sizeof(testing_servaddr))) != -1);
	
  testing_servaddr.sin_port = htons(8090);
  while(connect(testing_socket_fd, (struct sockaddr *) &testing_servaddr, sizeof(testing_servaddr)) != 0);
  LOG_E(SDAP, "[DRQL]: Connected to no-latency socket 8070 (CU) -> 8090 (DU)\n");

  // Wait till at least one SDAP entity is available
  while (!sdap_info.sdap_entity_llist){
    sleep(1);
  }

  // Create the E2 custom endpoint when a UE connects
  if(custom_parameters.ric_enabled){
    for(struct nr_sdap_entity_s *sdap_entity = sdap_info.sdap_entity_llist; sdap_entity != NULL; sdap_entity = sdap_entity->next_entity){
      if (pthread_create(&sdap_entity->sdap_e2ap_listener_thread, NULL, sdap_e2ap_listener, (void *) sdap_entity) != 0) {
        fprintf(stderr, "Error in %s:%d: Error creating sdap_e2ap_listener_thread thread\n", __FILE__, __LINE__);
        exit(EXIT_FAILURE);
      }
    }
  }

  while (1){
    // Iterate SDAP Entities
    for(struct nr_sdap_entity_s *sdap_entity = sdap_info.sdap_entity_llist; sdap_entity != NULL; sdap_entity = sdap_entity->next_entity){  
      // Iterate QFI Buffers of each SDAP Entity to check QFI/DRB Mapping 
      for(int qfi = 0; qfi < SDAP_MAX_QFI; qfi++){
        if(!sdap_entity->sdap_sdu_pdu_queues[qfi].length){
          continue;
        }

        long long start = get_time_in_ms();
        rlc_information(socket_fd, testing_socket_fd, sdap_entity->qfi2drb_table[sdap_entity->sdap_sdu_pdu_queues[qfi].tail->qfi].drb_id, &real_limit, &limit, &real_actual_size, &actual_size);
        if((limit < 0 || actual_size < 0) && real_limit < 0){
          break; // Give priority to lower qfi (replace with continue if RR)
        }
        long long end = get_time_in_ms();
        LOG_I(SDAP, "[DRQL]: RLC Limit(Bytes): %d, RLC Actual Size(Bytes): %d, Duration (ms): %lld, SDAP[QFI=%d] Size(Bytes): %d\n", limit, actual_size, end - start, qfi, sdap_entity->sdap_sdu_pdu_queues[qfi].size);

#ifdef SDAP_STATS_PERSIST
        if(real_actual_size > 0){
          LOG_E(SDAP, "[DRQL]: Actual Size %d (Queried/Predicted) vs %d (Real) = %d\n", actual_size, real_actual_size, actual_size - real_actual_size);

          pthread_mutex_lock(&analysis_mutex);

          if(sdap_entity->sdap_sdu_pdu_queues[qfi].head->sdu_buffer_size > actual_size && sdap_entity->sdap_sdu_pdu_queues[qfi].head->sdu_buffer_size <= real_actual_size){
            LOG_E(SDAP, "[DRQL][False Negative (Should have forwarded packet...)]: Packet Size %d vs Actual Size %d (Queried/Predicted) vs %d (Real) = %d\n", sdap_entity->sdap_sdu_pdu_queues[qfi].head->sdu_buffer_size, actual_size, real_actual_size, actual_size - real_actual_size);
            analysis.false_negative_counter++;
          }
          if(sdap_entity->sdap_sdu_pdu_queues[qfi].head->sdu_buffer_size <= actual_size && sdap_entity->sdap_sdu_pdu_queues[qfi].head->sdu_buffer_size > real_actual_size){
            LOG_E(SDAP, "[DRQL][False Positive (Packet will be dropped...)]: Packet Size %d vs Actual Size %d (Queried/Predicted) vs %d (Real) = %d\n", sdap_entity->sdap_sdu_pdu_queues[qfi].head->sdu_buffer_size, actual_size, real_actual_size, actual_size - real_actual_size);
            analysis.false_positive_counter++;
          }

          analysis.false_positive_negative_counter++;
          
          pthread_mutex_unlock(&analysis_mutex);
        }
#endif

        // Pacing Data from SDAP to RLC
        if(sdap_entity->sdap_sdu_pdu_queues[qfi].head->sdu_buffer_size > actual_size){ 
          LOG_E(SDAP, "[DRQL]: Can not forward packet since RLC queue is full\n");
          break; // Give priority to lower qfi (replace with continue if RR)
        }
        
        // Dequeue Packet
        pthread_mutex_lock(&sdap_entity->sdap_sdu_pdu_queues[qfi].lock);
        
        clock_t start_dequeue = clock();

        sdap_pdu = sdap_entity->dl_dequeue_pdu(sdap_entity, qfi);
        assert(sdap_pdu != NULL);

        clock_t end_dequeue = clock();
        LOG_D(SDAP, "--- Dequeued from SDAP[%ld] QFI[%d] in %f seconds\n", sdap_entity->ue_id, qfi, ((double) (end_dequeue - start_dequeue)) / CLOCKS_PER_SEC);

        // Unlock
        pthread_mutex_unlock(&sdap_entity->sdap_sdu_pdu_queues[qfi].lock);
                
        bool ret = sdap_entity->tx_entity(sdap_entity,
                              sdap_pdu->ctxt_p,
                              sdap_pdu->srb_flag,
                              sdap_pdu->rb_id,
                              sdap_pdu->mui,
                              sdap_pdu->confirm,
                              sdap_pdu->sdu_buffer_size,
                              sdap_pdu->sdu_buffer,
                              sdap_pdu->pt_mode,
                              sdap_pdu->sourceL2Id,
                              sdap_pdu->destinationL2Id,
                              sdap_pdu->qfi,
                              sdap_pdu->rqi);    


        pthread_mutex_lock(&analysis_mutex);
        analysis.dl_bytes_dequeued += sdap_pdu->sdu_buffer_size;
        pthread_mutex_unlock(&analysis_mutex);


        if(!ret){
          LOG_E(SDAP, "%s:%d:%s: PDCP refused PDU\n", __FILE__, __LINE__, __FUNCTION__);
        }
      }
    } 
  }
  
  return NULL;
}




void *sdap_predictions_receiver(void *arguments){
  int server_fd, client_socket;
  struct sockaddr_in address;
  int opt = 1;
  int addrlen = sizeof(address);
  char buffer[1024];
  struct timeval tv;


  // Creating socket file descriptor
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
    exit(EXIT_FAILURE);
  }

  // Forcefully attaching socket to the port 65432
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
    exit(EXIT_FAILURE);
  }

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(9010);

  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));

  // Bind the socket to the port 65432
  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    exit(EXIT_FAILURE);
  }

  // Listen to incoming connections
  if (listen(server_fd, 1) < 0) {
    exit(EXIT_FAILURE);
  }

  printf("Server is listening on port 9010...\n");

  // Accept incoming connection
  if ((client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
    exit(EXIT_FAILURE);
  }
 
  while(1){
    memset(buffer, 0, 1024 * sizeof(char));
    int bytes_read = read(client_socket, buffer, 1024);
    if (bytes_read < 0 || !bytes_read){
      const char* nack_message = "NACK";
      assert(write(client_socket, nack_message, strlen(nack_message)) != -1);
      continue;
    }

    pthread_mutex_lock(&predictions_mutex);
    memset(&predictions, 0, sizeof(predictions));
    
    gettimeofday(&tv, NULL);
    predictions.timestamp = 1000000 * tv.tv_sec + tv.tv_usec;
    predictions.timestamp = (long double) predictions.timestamp / 1000.0;

    // For debugging
    memcpy(predictions.debug_buffer, buffer, 1024 * sizeof(char));

    char *token;
    token = strtok(buffer, ",");

    // Process each token
    int i = 0;
    predictions.actual_size_array_length = atoi(token);
    if (predictions.actual_size_array != NULL){
      free(predictions.actual_size_array);
      predictions.actual_size_array = NULL;
    }
    predictions.actual_size_array = (int *) calloc(predictions.actual_size_array_length, sizeof(int));
    token = strtok(NULL, ",");
    
    int actual_size_predictions_index = 0;
    while (token != NULL) {
      if(i < predictions.actual_size_array_length){
        predictions.actual_size_array[actual_size_predictions_index++] = atoi(token); 
      } 
      token = strtok(NULL, ",");
      i++;
    }

    pthread_mutex_unlock(&predictions_mutex);

    const char* ack_message = "ACK";
    assert(write(client_socket, ack_message, strlen(ack_message)) != -1);
  }
 
  return NULL;
}