#include "nr_rlc_drql.h"

static bool nr_rlc_drql_enabled;

void nr_rlc_drql_set_enabled(bool enabled)
{
  nr_rlc_drql_enabled = enabled;
}

bool nr_rlc_drql_is_enabled(void)
{
  return nr_rlc_drql_enabled;
}
