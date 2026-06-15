#include "nr_sdap_drql.h"

static bool nr_sdap_drql_enabled;
static uint32_t nr_sdap_drql_queue_max_bytes = 16777216;

void nr_sdap_drql_set_config(bool enabled, uint32_t max_queue_bytes)
{
  nr_sdap_drql_enabled = enabled;
  nr_sdap_drql_queue_max_bytes = max_queue_bytes;
}

bool nr_sdap_drql_is_enabled(void)
{
  return nr_sdap_drql_enabled;
}

uint32_t nr_sdap_drql_max_queue_bytes(void)
{
  return nr_sdap_drql_queue_max_bytes;
}
