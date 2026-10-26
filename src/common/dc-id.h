/*
    Telegram DC identifiers addressable by direct-mode address overrides.

    Production DCs are numbered 1-5.  CDN DCs are numbered 200 + the base
    production DC, i.e. 201-299.  Negative media ids are normalized by
    direct_dc_lookup() before the override table is consulted, so they are
    not listed separately here.
*/
#pragma once

#define DC_ID_PROD_MIN 1
#define DC_ID_PROD_MAX 5
#define DC_ID_CDN_BASE 200
#define DC_ID_CDN_MIN  (DC_ID_CDN_BASE + 1)
#define DC_ID_CDN_MAX  (DC_ID_CDN_BASE + 99)

static inline int dc_override_id_is_valid (long long dc_id) {
  return (dc_id >= DC_ID_PROD_MIN && dc_id <= DC_ID_PROD_MAX) ||
         (dc_id >= DC_ID_CDN_MIN && dc_id <= DC_ID_CDN_MAX);
}