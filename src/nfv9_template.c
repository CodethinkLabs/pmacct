/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2016 by Paolo Lucente
*/

/*
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* defines */
#define __NFV9_TEMPLATE_C

/* includes */
#include "pmacct.h"
#include "addr.h"
#include "nfacctd.h"
#include "pmacct-data.h"

struct template_cache_entry *handle_template(struct template_hdr_v9 *hdr, struct packet_ptrs *pptrs, u_int16_t tpl_type,
						u_int32_t sid, u_int16_t *pens, u_int16_t len, u_int32_t seq)
{
  struct template_cache_entry *tpl = NULL;
  u_int8_t version = 0;

  if (pens) *pens = FALSE;

  if (tpl_type == 0 || tpl_type == 1) version = 9;
  else if (tpl_type == 2 || tpl_type == 3) version = 10;

  /* 0 NetFlow v9, 2 IPFIX */
  if (tpl_type == 0 || tpl_type == 2) {
    if (tpl = find_template(hdr->template_id, pptrs, tpl_type, sid))
      tpl = refresh_template(hdr, tpl, pptrs, tpl_type, sid, pens, version, len, seq);
    else tpl = insert_template(hdr, pptrs, tpl_type, sid, pens, version, len, seq);
  }
  /* 1 NetFlow v9, 3 IPFIX */
  else if (tpl_type == 1 || tpl_type == 3) {
    if (tpl = find_template(hdr->template_id, pptrs, tpl_type, sid))
      tpl = refresh_opt_template(hdr, tpl, pptrs, tpl_type, sid, version, len, seq);
    else tpl = insert_opt_template(hdr, pptrs, tpl_type, sid, version, len, seq);
  }

  return tpl;
}

struct template_cache_entry *find_template(u_int16_t id, struct packet_ptrs *pptrs, u_int16_t tpl_type, u_int32_t sid)
{
  struct template_cache_entry *ptr;
  u_int16_t modulo = (ntohs(id)%tpl_cache.num);

  ptr = tpl_cache.c[modulo];

  while (ptr) {
    if ((ptr->template_id == id) && (!sa_addr_cmp((struct sockaddr *)pptrs->f_agent, &ptr->agent)) &&
	(ptr->source_id == sid))
      return ptr;
    else ptr = ptr->next;
  }

  return NULL;
}

struct template_cache_entry *insert_template(struct template_hdr_v9 *hdr, struct packet_ptrs *pptrs, u_int16_t tpl_type,
						u_int32_t sid, u_int16_t *pens, u_int8_t version, u_int16_t len, u_int32_t seq)
{
  struct template_cache_entry *ptr, *prevptr = NULL;
  struct template_field_v9 *field;
  u_int16_t modulo = (ntohs(hdr->template_id)%tpl_cache.num), count;
  u_int16_t num = ntohs(hdr->num), type, port, off;
  u_int32_t *pen;
  u_int8_t ipfix_ebit;
  u_char *tpl;

  ptr = tpl_cache.c[modulo];

  while (ptr) {
    prevptr = ptr;
    ptr = ptr->next;
  }

  ptr = malloc(sizeof(struct template_cache_entry));
  if (!ptr) {
    Log(LOG_ERR, "ERROR ( %s/core ): Unable to allocate enough memory for a new Template Cache Entry.\n", config.name);
    return NULL;
  }

  memset(ptr, 0, sizeof(struct template_cache_entry));
  sa_to_addr((struct sockaddr *)pptrs->f_agent, &ptr->agent, &port);
  ptr->source_id = sid;
  ptr->template_id = hdr->template_id;
  ptr->template_type = 0;
  ptr->num = num;

  log_template_header(ptr, pptrs, tpl_type, sid, version);

  count = off = 0;
  tpl = (u_char *) hdr;
  tpl += NfTplHdrV9Sz;
  off += NfTplHdrV9Sz;
  field = (struct template_field_v9 *)tpl;

  while (count < num) {
    if (off >= len) {
      notify_malf_packet(LOG_INFO, "INFO: unable to read next Template Flowset (malformed template)",
                        (struct sockaddr *) pptrs->f_agent, seq);
      xflow_tot_bad_datagrams++;
      free(ptr);
      return NULL;
    }

    pen = NULL; 
    ipfix_ebit = FALSE;
    type = ntohs(field->type);

    if (type & IPFIX_TPL_EBIT && version == 10) {
      ipfix_ebit = TRUE;
      type ^= IPFIX_TPL_EBIT;
      if (pens) (*pens)++;
      pen = (u_int32_t *) field;
      pen++;
    }

    log_template_field(ptr->vlen, pen, type, ptr->len, ntohs(field->len), version);

    /* Let's determine if we use legacy template registry or the
       new template database (ie. if we have a PEN or high field
       value, >= 384) */
    if (type < NF9_MAX_DEFINED_FIELD && !pen) {
      ptr->tpl[type].off = ptr->len; 
      ptr->tpl[type].tpl_len = ntohs(field->len);

      if (ptr->vlen) ptr->tpl[type].off = 0;

      if (ptr->tpl[type].tpl_len == IPFIX_VARIABLE_LENGTH) {
        ptr->tpl[type].len = 0;
        ptr->vlen = TRUE;
        ptr->len = 0;
      }
      else {
        ptr->tpl[type].len = ptr->tpl[type].tpl_len;
        if (!ptr->vlen) ptr->len += ptr->tpl[type].len;
      }
      ptr->list[count].ptr = (char *) &ptr->tpl[type];
      ptr->list[count].type = TPL_TYPE_LEGACY;
    }
    else {
      u_int8_t repeat_id = 0;
      struct utpl_field *ext_db_ptr = ext_db_get_next_ie(ptr, type, &repeat_id);

      if (ext_db_ptr) {
	if (pen) ext_db_ptr->pen = ntohl(*pen);
	ext_db_ptr->type = type;
	ext_db_ptr->off = ptr->len;
	ext_db_ptr->tpl_len = ntohs(field->len);
	ext_db_ptr->repeat_id = repeat_id;

        if (ptr->vlen) ext_db_ptr->off = 0;

	if (ext_db_ptr->tpl_len == IPFIX_VARIABLE_LENGTH) {
	  ext_db_ptr->len = 0;
	  ptr->vlen = TRUE;
	  ptr->len = 0;
	}
	else {
	  ext_db_ptr->len = ext_db_ptr->tpl_len;
	  if (!ptr->vlen) ptr->len += ext_db_ptr->len;
	}
      }
      ptr->list[count].ptr = (char *) ext_db_ptr;
      ptr->list[count].type = TPL_TYPE_EXT_DB;
    }

    count++;
    off += NfTplFieldV9Sz;
    if (ipfix_ebit) {
      field++; /* skip 32-bits ahead */ 
      off += sizeof(u_int32_t);
    }
    field++;
  }

  if (prevptr) prevptr->next = ptr;
  else tpl_cache.c[modulo] = ptr;

  log_template_footer(ptr, ptr->len, version);

#ifdef WITH_JANSSON
  if (config.nfacctd_templates_file)
    save_template(ptr, config.nfacctd_templates_file);
#endif

  return ptr;
}

#ifdef WITH_JANSSON
void save_template(struct template_cache_entry *tpl, char *file)
{
  u_int16_t field_idx;
  u_int8_t idx;
  char *fmt;
  char ip_addr[INET6_ADDRSTRLEN];
  json_t *root = json_object(), *agent_obj, *kv;
  json_t *tpl_array, *ext_db_array, *list_array;
  FILE *tpl_file = open_output_file(config.nfacctd_templates_file, "a", TRUE);
    Log(LOG_ERR, "ERROR ( %s/core ): Opened output file.\n", config.name);

  addr_to_str(ip_addr, &tpl->agent);
  kv = json_pack("{ss}", "agent", ip_addr);
  json_object_update_missing(root, kv);
  json_decref(kv);

  kv = json_pack("{sI}", "source_id", tpl->source_id);
  json_object_update_missing(root, kv);
  json_decref(kv);

  kv = json_pack("{sI}", "template_id", tpl->template_id);
  json_object_update_missing(root, kv);
  json_decref(kv);

  kv = json_pack("{sI}", "template_type", tpl->template_type);
  json_object_update_missing(root, kv);
  json_decref(kv);

  kv = json_pack("{sI}", "num", tpl->num);
  json_object_update_missing(root, kv);
  json_decref(kv);

  kv = json_pack("{sI}", "len", tpl->len);
  json_object_update_missing(root, kv);
  json_decref(kv);

  kv = json_pack("{sI}", "vlen", tpl->vlen);
  json_object_update_missing(root, kv);
  json_decref(kv);

  tpl_array = json_array();
  for (field_idx = 0; field_idx < NF9_MAX_DEFINED_FIELD; field_idx++) {
    json_t *json_otpl_field = json_object();

    kv = json_pack("{sI}", "off", tpl->tpl[field_idx].off);
    json_object_update_missing(json_otpl_field, kv);
    json_decref(kv);

    kv = json_pack("{sI}", "len", tpl->tpl[field_idx].len);
    json_object_update_missing(json_otpl_field, kv);
    json_decref(kv);

    kv = json_pack("{sI}", "tpl_len", tpl->tpl[field_idx].tpl_len);
    json_object_update_missing(json_otpl_field, kv);
    json_decref(kv);

    json_array_append_new(tpl_array, json_otpl_field);
  }
  json_object_set_new(root, "tpl", tpl_array);

  ext_db_array = json_array();
  for (field_idx = 0; field_idx < TPL_EXT_DB_ENTRIES; field_idx++) {
    json_t *json_tfd_field = json_object();

    for (idx = 0; idx < IES_PER_TPL_EXT_DB_ENTRY; idx++) {
      json_t *json_utpl_field = json_object();

      kv = json_pack("{sI}", "pen", tpl->ext_db[field_idx].ie[idx].pen);
      json_object_update_missing(json_utpl_field, kv);
      json_decref(kv);

      kv = json_pack("{sI}", "type", tpl->ext_db[field_idx].ie[idx].type);
      json_object_update_missing(json_utpl_field, kv);
      json_decref(kv);

      kv = json_pack("{sI}", "off", tpl->ext_db[field_idx].ie[idx].off);
      json_object_update_missing(json_utpl_field, kv);
      json_decref(kv);

      kv = json_pack("{sI}", "len", tpl->ext_db[field_idx].ie[idx].len);
      json_object_update_missing(json_utpl_field, kv);
      json_decref(kv);

      kv = json_pack("{sI}", "tpl_len", tpl->ext_db[field_idx].ie[idx].tpl_len);
      json_object_update_missing(json_utpl_field, kv);
      json_decref(kv);

      kv = json_pack("{sI}", "repeat_id", tpl->ext_db[field_idx].ie[idx].repeat_id);
      json_object_update_missing(json_utpl_field, kv);
      json_decref(kv);

      json_array_append_new(json_tfd_field, json_utpl_field);
    }
    json_array_append_new(ext_db_array, json_tfd_field);
  }
  json_object_set_new(root, "ext_db", ext_db_array);

  list_array = json_array();
  for (field_idx = 0; field_idx < TPL_LIST_ENTRIES; field_idx++) {
    json_t *json_tfl_field = json_object();

    kv = json_pack("{sI}", "type", tpl->list[field_idx].type);
    json_object_update_missing(json_tfl_field, kv);
    json_decref(kv);

    kv = json_pack("{ss}", "ptr", tpl->list[field_idx].ptr);  //FIXME: reference to either ext_db or tpl entry
    json_object_update_missing(json_tfl_field, kv);
    json_decref(kv);

    json_array_append_new(list_array, json_tfl_field);
  }
  json_object_set_new(root, "list", list_array);

  /* NB: member `next` is willingly excluded from serialisation, since
   * it would make more sense for it to be computed when de-serializing,
   * to prevent the template cache from being corrupted. */

  if (root) {
      write_and_free_json(tpl_file, root);
  }

  close_output_file(tpl_file);
    Log(LOG_ERR, "ERROR ( %s/core ): closed output file.\n", config.name);
}
#else
void save_template(template_cache_entry *tpl, char *file) {
  if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/%s ): save_template(): JSON object not created due to missing --enable-jansson\n", config.name, config.type);
}
#endif

struct template_cache_entry *refresh_template(struct template_hdr_v9 *hdr, struct template_cache_entry *tpl, struct packet_ptrs *pptrs, u_int16_t tpl_type,
						u_int32_t sid, u_int16_t *pens, u_int8_t version, u_int16_t len, u_int32_t seq)
{
  struct template_cache_entry backup, *next;
  struct template_field_v9 *field;
  u_int16_t count, num = ntohs(hdr->num), type, port, off;
  u_int32_t *pen;
  u_int8_t ipfix_ebit;
  u_char *ptr;

  next = tpl->next;
  memcpy(&backup, tpl, sizeof(struct template_cache_entry));
  memset(tpl, 0, sizeof(struct template_cache_entry));
  sa_to_addr((struct sockaddr *)pptrs->f_agent, &tpl->agent, &port);
  tpl->source_id = sid;
  tpl->template_id = hdr->template_id;
  tpl->template_type = 0;
  tpl->num = num;
  tpl->next = next;

  log_template_header(tpl, pptrs, tpl_type, sid, version);

  count = off = 0;
  ptr = (u_char *) hdr;
  ptr += NfTplHdrV9Sz;
  off += NfTplHdrV9Sz;
  field = (struct template_field_v9 *)ptr;

  while (count < num) {
    if (off >= len) {
      notify_malf_packet(LOG_INFO, "INFO: unable to read next Template Flowset (malformed template)",
                        (struct sockaddr *) pptrs->f_agent, seq);
      xflow_tot_bad_datagrams++;
      memcpy(tpl, &backup, sizeof(struct template_cache_entry));
      return NULL;
    }

    pen = NULL;
    ipfix_ebit = FALSE;
    type = ntohs(field->type);

    if (type & IPFIX_TPL_EBIT && version == 10) {
      ipfix_ebit = TRUE;
      type ^= IPFIX_TPL_EBIT;
      if (pens) (*pens)++;
      pen = (u_int32_t *) field; pen++;
    }
    log_template_field(tpl->vlen, pen, type, tpl->len, ntohs(field->len), version);

    if (type < NF9_MAX_DEFINED_FIELD && !pen) {
      tpl->tpl[type].off = tpl->len;
      tpl->tpl[type].tpl_len = ntohs(field->len);

      if (tpl->vlen) tpl->tpl[type].off = 0;

      if (tpl->tpl[type].tpl_len == IPFIX_VARIABLE_LENGTH) {
        tpl->tpl[type].len = 0;
        tpl->vlen = TRUE;
        tpl->len = 0;
      }
      else {
        tpl->tpl[type].len = tpl->tpl[type].tpl_len;
        if (!tpl->vlen) tpl->len += tpl->tpl[type].len;
      }
      tpl->list[count].ptr = (char *) &tpl->tpl[type];
      tpl->list[count].type = TPL_TYPE_LEGACY;
    }
    else {
      u_int8_t repeat_id = 0;
      struct utpl_field *ext_db_ptr = ext_db_get_next_ie(tpl, type, &repeat_id);

      if (ext_db_ptr) {
        if (pen) ext_db_ptr->pen = ntohl(*pen);
        ext_db_ptr->type = type;
        ext_db_ptr->off = tpl->len;
        ext_db_ptr->tpl_len = ntohs(field->len);
	ext_db_ptr->repeat_id = repeat_id;

        if (tpl->vlen) ext_db_ptr->off = 0;

        if (ext_db_ptr->tpl_len == IPFIX_VARIABLE_LENGTH) {
          ext_db_ptr->len = 0;
          tpl->vlen = TRUE;
          tpl->len = 0;
        }
        else {
          ext_db_ptr->len = ext_db_ptr->tpl_len;
          if (!tpl->vlen) tpl->len += ext_db_ptr->len;
        }
      }
      tpl->list[count].ptr = (char *) ext_db_ptr;
      tpl->list[count].type = TPL_TYPE_EXT_DB;
    }

    count++;
    off += NfTplFieldV9Sz;
    if (ipfix_ebit) {
      field++; /* skip 32-bits ahead */
      off += sizeof(u_int32_t);
    }
    field++;
  }

  log_template_footer(tpl, tpl->len, version);

  return tpl;
}

void log_template_header(struct template_cache_entry *tpl, struct packet_ptrs *pptrs, u_int16_t tpl_type, u_int32_t sid, u_int8_t version)
{
  struct host_addr a;
  u_char agent_addr[50];
  u_int16_t agent_port, count, size;

  sa_to_addr((struct sockaddr *)pptrs->f_agent, &a, &agent_port);
  addr_to_str(agent_addr, &a);

  Log(LOG_DEBUG, "DEBUG ( %s/core ): NfV%u agent         : %s:%u\n", config.name, version, agent_addr, sid);
  Log(LOG_DEBUG, "DEBUG ( %s/core ): NfV%u template type : %s\n", config.name, version, ( tpl->template_type == 0 || tpl->template_type == 2 ) ? "flow" : "options");
  Log(LOG_DEBUG, "DEBUG ( %s/core ): NfV%u template ID   : %u\n", config.name, version, ntohs(tpl->template_id));

  if ( tpl->template_type == 0 || tpl->template_type == 2 ) {
    Log(LOG_DEBUG, "DEBUG ( %s/core ): -------------------------------------------------------------\n", config.name);
    Log(LOG_DEBUG, "DEBUG ( %s/core ): |    pen     |         field type         | offset |  size  |\n", config.name);
  }
  else {
    Log(LOG_DEBUG, "DEBUG ( %s/core ): ------------------------------------------------\n", config.name);
    Log(LOG_DEBUG, "DEBUG ( %s/core ): |         field type         | offset |  size  |\n", config.name);
  }
}

void log_template_field(u_int8_t vlen, u_int32_t *pen, u_int16_t type, u_int16_t off, u_int16_t len, u_int8_t version)
{
  if (!pen) {
    if (type <= MAX_TPL_DESC_LIST && strlen(tpl_desc_list[type])) { 
      if (!off && vlen)
        Log(LOG_DEBUG, "DEBUG ( %s/core ): | %-10u | %-18s [%-5u] | %6s | %6u |\n", config.name, 0, tpl_desc_list[type], type, "tbd", len);
      else
        Log(LOG_DEBUG, "DEBUG ( %s/core ): | %-10u | %-18s [%-5u] | %6u | %6u |\n", config.name, 0, tpl_desc_list[type], type, off, len);
    }
    else {
      if (!off && vlen)
        Log(LOG_DEBUG, "DEBUG ( %s/core ): | %-10u | %-18u [%-5u] | %6s | %6u |\n", config.name, 0, type, type, "tbd", len);
      else
        Log(LOG_DEBUG, "DEBUG ( %s/core ): | %-10u | %-18u [%-5u] | %6u | %6u |\n", config.name, 0, type, type, off, len);
    }
  }
  else {
    if (!off && vlen) 
      Log(LOG_DEBUG, "DEBUG ( %s/core ): | %-10u | %-18u [%-5u] | %6s | %6u |\n", config.name, ntohl(*pen), type, type, "tbd", len);
    else 
      Log(LOG_DEBUG, "DEBUG ( %s/core ): | %-10u | %-18u [%-5u] | %6u | %6u |\n", config.name, ntohl(*pen), type, type, off, len);
  }
}

void log_opt_template_field(u_int16_t type, u_int16_t off, u_int16_t len, u_int8_t version)
{
  if (type <= MAX_OPT_TPL_DESC_LIST && strlen(opt_tpl_desc_list[type]))
    Log(LOG_DEBUG, "DEBUG ( %s/core ): | %-18s [%-5u] | %6u | %6u |\n", config.name, opt_tpl_desc_list[type], type, off, len);
  else
    Log(LOG_DEBUG, "DEBUG ( %s/core ): | %-18u [%-5u] | %6u | %6u |\n", config.name, type, type, off, len);
}

void log_template_footer(struct template_cache_entry *tpl, u_int16_t size, u_int8_t version)
{
  if ( tpl->template_type == 0 || tpl->template_type == 2 )
    Log(LOG_DEBUG, "DEBUG ( %s/core ): -------------------------------------------------------------\n", config.name);
  else 
    Log(LOG_DEBUG, "DEBUG ( %s/core ): ------------------------------------------------\n", config.name);

  if (!size)
    Log(LOG_DEBUG, "DEBUG ( %s/core ): Netflow V9/IPFIX record size : %s\n", config.name, "tbd");
  else 
    Log(LOG_DEBUG, "DEBUG ( %s/core ): Netflow V9/IPFIX record size : %u\n", config.name, size);
  Log(LOG_DEBUG, "DEBUG ( %s/core ): \n", config.name);
}

struct template_cache_entry *insert_opt_template(void *hdr, struct packet_ptrs *pptrs, u_int16_t tpl_type,
							u_int32_t sid, u_int8_t version, u_int16_t len, u_int32_t seq)
{
  struct options_template_hdr_v9 *hdr_v9 = (struct options_template_hdr_v9 *) hdr;
  struct options_template_hdr_ipfix *hdr_v10 = (struct options_template_hdr_ipfix *) hdr;
  struct template_cache_entry *ptr, *prevptr = NULL;
  struct template_field_v9 *field;
  u_int16_t modulo, count, slen, olen, type, port, tid, off;
  u_char *tpl;

  /* NetFlow v9 */
  if (tpl_type == 1) {
    modulo = ntohs(hdr_v9->template_id)%tpl_cache.num;
    tid = hdr_v9->template_id;
    slen = ntohs(hdr_v9->scope_len)/sizeof(struct template_field_v9);
    olen = ntohs(hdr_v9->option_len)/sizeof(struct template_field_v9);
  }
  /* IPFIX */
  else if (tpl_type == 3) {
    modulo = ntohs(hdr_v10->template_id)%tpl_cache.num;
    tid = hdr_v10->template_id;
    slen = ntohs(hdr_v10->scope_count);
    olen = ntohs(hdr_v10->option_count)-slen;
  }

  ptr = tpl_cache.c[modulo];

  while (ptr) {
    prevptr = ptr;
    ptr = ptr->next;
  }

  ptr = malloc(sizeof(struct template_cache_entry));
  if (!ptr) {
    Log(LOG_ERR, "ERROR ( %s/core ): Unable to allocate enough memory for a new Options Template Cache Entry.\n", config.name);
    return NULL;
  }

  memset(ptr, 0, sizeof(struct template_cache_entry));
  sa_to_addr((struct sockaddr *)pptrs->f_agent, &ptr->agent, &port);
  ptr->source_id = sid; 
  ptr->template_id = tid;
  ptr->template_type = 1;
  ptr->num = olen+slen;

  log_template_header(ptr, pptrs, tpl_type, sid, version);

  off = 0;
  count = ptr->num;
  tpl = (u_char *) hdr;
  tpl += NfOptTplHdrV9Sz;
  off += NfOptTplHdrV9Sz;
  field = (struct template_field_v9 *)tpl;

  while (count) {
    if (off >= len) {
      notify_malf_packet(LOG_INFO, "INFO: unable to read next Options Template Flowset (malformed template)",
                        (struct sockaddr *) pptrs->f_agent, seq);
      xflow_tot_bad_datagrams++;
      free(ptr);
      return NULL;
    }

    type = ntohs(field->type);
    log_opt_template_field(type, ptr->len, ntohs(field->len), version);
    if (type < NF9_MAX_DEFINED_FIELD) { 
      ptr->tpl[type].off = ptr->len;
      ptr->tpl[type].len = ntohs(field->len);
      ptr->len += ptr->tpl[type].len;
    }
    else ptr->len += ntohs(field->len);

    count--;
    field++;
    off += NfTplFieldV9Sz;
  }

  if (prevptr) prevptr->next = ptr;
  else tpl_cache.c[modulo] = ptr;

  log_template_footer(ptr, ptr->len, version);

  return ptr;
}

struct template_cache_entry *refresh_opt_template(void *hdr, struct template_cache_entry *tpl, struct packet_ptrs *pptrs, u_int16_t tpl_type,
							u_int32_t sid, u_int8_t version, u_int16_t len, u_int32_t seq)
{
  struct options_template_hdr_v9 *hdr_v9 = (struct options_template_hdr_v9 *) hdr;
  struct options_template_hdr_ipfix *hdr_v10 = (struct options_template_hdr_ipfix *) hdr;
  struct template_cache_entry backup, *next;
  struct template_field_v9 *field;
  u_int16_t slen, olen, count, type, port, tid, off;
  u_char *ptr;

  /* NetFlow v9 */
  if (tpl_type == 1) {
    tid = hdr_v9->template_id;
    slen = ntohs(hdr_v9->scope_len)/sizeof(struct template_field_v9);
    olen = ntohs(hdr_v9->option_len)/sizeof(struct template_field_v9);
  }
  /* IPFIX */
  else if (tpl_type == 3) {
    tid = hdr_v10->template_id;
    slen = ntohs(hdr_v10->scope_count);
    olen = ntohs(hdr_v10->option_count)-slen;
  }

  next = tpl->next;
  memcpy(&backup, tpl, sizeof(struct template_cache_entry));
  memset(tpl, 0, sizeof(struct template_cache_entry));
  sa_to_addr((struct sockaddr *)pptrs->f_agent, &tpl->agent, &port);
  tpl->source_id = sid;
  tpl->template_id = tid;
  tpl->template_type = 1;
  tpl->num = olen+slen;
  tpl->next = next;

  log_template_header(tpl, pptrs, tpl_type, sid, version);  

  off = 0;
  count = tpl->num;
  ptr = (u_char *) hdr;
  ptr += NfOptTplHdrV9Sz;
  off += NfOptTplHdrV9Sz;
  field = (struct template_field_v9 *)ptr;

  while (count) {
    if (off >= len) {
      notify_malf_packet(LOG_INFO, "INFO: unable to read next Options Template Flowset (malformed template)",
                        (struct sockaddr *) pptrs->f_agent, seq);
      xflow_tot_bad_datagrams++;
      memcpy(tpl, &backup, sizeof(struct template_cache_entry));
      return NULL;
    }

    type = ntohs(field->type);
    log_opt_template_field(type, tpl->len, ntohs(field->len), version);
    if (type < NF9_MAX_DEFINED_FIELD) {
      tpl->tpl[type].off = tpl->len;
      tpl->tpl[type].len = ntohs(field->len);
      tpl->len += tpl->tpl[type].len;
    }
    else tpl->len += ntohs(field->len);

    count--;
    field++;
    off += NfTplFieldV9Sz;
  }

  log_template_footer(tpl, tpl->len, version);

  return tpl;
}

void resolve_vlen_template(char *ptr, struct template_cache_entry *tpl)
{
  struct otpl_field *otpl_ptr;
  struct utpl_field *utpl_ptr;
  u_int16_t idx = 0, len = 0;
  u_int8_t vlen = 0, add_len;

  while (idx < tpl->num) {
    add_len = 0;
    if (tpl->list[idx].type == TPL_TYPE_LEGACY) { 
      otpl_ptr = (struct otpl_field *) tpl->list[idx].ptr;
      if (vlen) otpl_ptr->off = len;

      if (otpl_ptr->tpl_len == IPFIX_VARIABLE_LENGTH) {
	vlen = TRUE;
	add_len = get_ipfix_vlen(ptr+len, &otpl_ptr->len);
	otpl_ptr->off = len+add_len;
      }

      len += (otpl_ptr->len+add_len); 
    }
    else if (tpl->list[idx].type == TPL_TYPE_EXT_DB) {
      utpl_ptr = (struct utpl_field *) tpl->list[idx].ptr;
      if (vlen) utpl_ptr->off = len;

      if (utpl_ptr->tpl_len == IPFIX_VARIABLE_LENGTH) {
        vlen = TRUE;
        add_len = get_ipfix_vlen(ptr+len, &utpl_ptr->len);
	utpl_ptr->off = len+add_len;
      }

      len += (utpl_ptr->len+add_len);
    }

    idx++;
  }
  
  tpl->len = len;
}

u_int8_t get_ipfix_vlen(char *base, u_int16_t *len)
{
  char *ptr = base;
  u_int8_t *len8, ret = 0;
  u_int16_t *len16;

  if (ptr && len) {
    len8 = (u_int8_t *) ptr;
    if (*len8 < 255) {
      ret = 1;
      *len = *len8;
    }
    else {
      ptr++;
      len16 = (u_int16_t *) ptr;
      ret = 3;
      *len = ntohs(*len16);
    }
  }

  return ret;
}

struct utpl_field *ext_db_get_ie(struct template_cache_entry *ptr, u_int32_t pen, u_int16_t type, u_int8_t repeat_id)
{
  u_int16_t ie_idx, ext_db_modulo = (type%TPL_EXT_DB_ENTRIES);
  struct utpl_field *ext_db_ptr = NULL;

  for (ie_idx = 0; ie_idx < IES_PER_TPL_EXT_DB_ENTRY; ie_idx++) {
    if (ptr->ext_db[ext_db_modulo].ie[ie_idx].type == type &&
	ptr->ext_db[ext_db_modulo].ie[ie_idx].pen == pen &&
	ptr->ext_db[ext_db_modulo].ie[ie_idx].repeat_id == repeat_id) {
      ext_db_ptr = &ptr->ext_db[ext_db_modulo].ie[ie_idx];
      break;
    }
  }

  return ext_db_ptr;
}

struct utpl_field *ext_db_get_next_ie(struct template_cache_entry *ptr, u_int16_t type, u_int8_t *repeat_id)
{
  u_int16_t ie_idx, ext_db_modulo = (type%TPL_EXT_DB_ENTRIES);
  struct utpl_field *ext_db_ptr = NULL;

  (*repeat_id) = 0;

  for (ie_idx = 0; ie_idx < IES_PER_TPL_EXT_DB_ENTRY; ie_idx++) {
    if (ptr->ext_db[ext_db_modulo].ie[ie_idx].type == type) (*repeat_id)++;

    if (ptr->ext_db[ext_db_modulo].ie[ie_idx].type == 0) {
      ext_db_ptr = &ptr->ext_db[ext_db_modulo].ie[ie_idx];
      break;
    }
  }

  return ext_db_ptr;
}
