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
    if (tpl = find_template(hdr->template_id, (struct host_addr *) pptrs->f_agent, tpl_type, sid))
      tpl = refresh_template(hdr, tpl, pptrs, tpl_type, sid, pens, version, len, seq);
    else tpl = insert_template(hdr, pptrs, tpl_type, sid, pens, version, len, seq);
  }
  /* 1 NetFlow v9, 3 IPFIX */
  else if (tpl_type == 1 || tpl_type == 3) {
    if (tpl = find_template(hdr->template_id, (struct host_addr *) pptrs->f_agent, tpl_type, sid))
      tpl = refresh_opt_template(hdr, tpl, pptrs, tpl_type, sid, version, len, seq);
    else tpl = insert_opt_template(hdr, pptrs, tpl_type, sid, version, len, seq);
  }

  return tpl;
}

struct template_cache_entry *find_template(u_int16_t id, struct host_addr *agent, u_int16_t tpl_type, u_int32_t sid)
{
  struct template_cache_entry *ptr;
  u_int16_t modulo = (ntohs(id)%tpl_cache.num);

  ptr = tpl_cache.c[modulo];

  while (ptr) {
    if ((ptr->template_id == id) && (!sa_addr_cmp((struct sockaddr *)agent, &ptr->agent)) &&
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
void load_templates_from_file(char *path)
{
  FILE *tmp_file = fopen(path, "r");
  char errbuf[SRVBUFLEN], *tmpbuf;
  int line = 1;
  u_int16_t modulo;

  tmpbuf = malloc(LARGEBUFLEN);
  if (!tmpbuf) {
    Log(LOG_ERR, "ERROR ( %s/core ): load_templates_from_file(): unable to malloc() tmpbuf. File skipped.\n",
	config.name);
    return;
  }

  if (!tmp_file) {
    Log(LOG_ERR, "ERROR ( %s/core ): [%s] load_templates_from_file(): unable to fopen(). File skipped.\n",
               config.name, path);
    return;
  }

  struct template_cache_entry *tpl, *prev_ptr = NULL, *ptr = NULL;

  while (fgets(tmpbuf, LARGEBUFLEN, tmp_file)) {
    tpl = nfacctd_offline_read_json_template(tmpbuf, errbuf, SRVBUFLEN);
    if (tpl == NULL) {
      Log(LOG_WARNING, "WARN ( %s/core ): [%s:%u] %s\n", config.name, path, line, errbuf);
    }
    else {
      /* We assume the cache is empty when templates are loaded */
      if (find_template(tpl->template_id, &tpl->agent, tpl->template_type, tpl->source_id))
        Log(LOG_DEBUG, "WARN ( %s/core ): Template %d already exists in cache. Skipping\n",
                config.name, tpl->template_id);
      else {
        modulo = (ntohs(tpl->template_id)%tpl_cache.num);
        ptr = tpl_cache.c[modulo];

        while (ptr) {
          prev_ptr = ptr;
          ptr = ptr->next;
        }

        if (prev_ptr) prev_ptr->next = tpl;
        else tpl_cache.c[modulo] = tpl;

        Log(LOG_DEBUG, "DEBUG ( %s/core ): Loaded template %d into cache.\n",
                config.name, tpl->template_id);
      }
    }

    prev_ptr = NULL;
    line++;
  }

  free(tmpbuf);
  fclose(tmp_file);
}

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

  list_array = json_array();
  for (field_idx = 0; field_idx < tpl->num; field_idx++) {
    json_t *json_tfl_field = json_object();

    kv = json_pack("{sI}", "type", tpl->list[field_idx].type);
    json_object_update_missing(json_tfl_field, kv);
    json_decref(kv);

    /* idea: depending on tpl->list[field_idx].type,
     * serialize either an otpl_field (if TPL_TYPE_LEGACY) or
     * an utpl_field (if TPL_TYPE_EXT_DB) */
    if (tpl->list[field_idx].type == TPL_TYPE_LEGACY){
      struct otpl_field *otpl_field = (struct otpl_field *) tpl->list[field_idx].ptr;
      json_t *json_otpl_field = json_object();

      kv = json_pack("{sI}", "off", otpl_field->off);
      json_object_update_missing(json_otpl_field, kv);
      json_decref(kv);

      kv = json_pack("{sI}", "len", otpl_field->len);
      json_object_update_missing(json_otpl_field, kv);
      json_decref(kv);

      kv = json_pack("{sI}", "tpl_len", otpl_field->tpl_len);
      json_object_update_missing(json_otpl_field, kv);
      json_decref(kv);

      json_object_update_missing(json_tfl_field, json_otpl_field);
      json_decref(json_otpl_field);
    }
    else if (tpl->list[field_idx].type == TPL_TYPE_EXT_DB) {
      struct utpl_field *ext_db_ptr = (struct utpl_field *) tpl->list[field_idx].ptr;
      json_t *json_utpl_field = json_object();

      kv = json_pack("{sI}", "pen", ext_db_ptr->pen);
      json_object_update_missing(json_utpl_field, kv);
      json_decref(kv);

      kv = json_pack("{sI}", "type", ext_db_ptr->type);
      json_object_update_missing(json_utpl_field, kv);
      json_decref(kv);

      kv = json_pack("{sI}", "off", ext_db_ptr->off);
      json_object_update_missing(json_utpl_field, kv);
      json_decref(kv);

      kv = json_pack("{sI}", "len", ext_db_ptr->len);
      json_object_update_missing(json_utpl_field, kv);
      json_decref(kv);

      kv = json_pack("{sI}", "tpl_len", ext_db_ptr->tpl_len);
      json_object_update_missing(json_utpl_field, kv);
      json_decref(kv);

      kv = json_pack("{sI}", "repeat_id", ext_db_ptr->repeat_id);
      json_object_update_missing(json_utpl_field, kv);
      json_decref(kv);

      json_object_update_missing(json_tfl_field, json_utpl_field);
      json_decref(json_utpl_field);
    }

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

struct template_cache_entry *nfacctd_offline_read_json_template(char *buf, char *errbuf, int errlen)
{
  struct template_cache_entry *ret = NULL;
  u_int16_t field_idx;

  json_error_t json_err;
  json_t *json_obj;

  json_obj = json_loads(buf, 0, &json_err);

  if (!json_obj) {
    snprintf(errbuf, errlen, "nfacctd_offline_read_json_template(): json_loads() error: %s. Line skipped.\n", json_err.text);
  }
  else {
    if (!json_is_object(json_obj)) {
      snprintf(errbuf, errlen, "nfacctd_offline_read_json_template(): json_is_object() failed. Line skipped.\n");
    }
    else {
      ret = malloc(sizeof(struct template_cache_entry));
      if (!ret) {
        snprintf(errbuf, errlen, "nfacctd_offline_read_json_template(): Unable to allocate enough memory for a new Template Cache Entry.\n");
        return NULL;
      }

      memset(ret, 0, sizeof(struct template_cache_entry));

      json_t *json_tpl_id = json_object_get(json_obj, "template_id");
      if (json_tpl_id == NULL) {
        snprintf(errbuf, errlen, "nfacctd_offline_read_json_template(): template ID null. Line skipped.\n");
        free(ret);
        return NULL;
      }
      else {
        ret->template_id = json_integer_value(json_tpl_id);
      }

      free(json_tpl_id);

      json_t *json_src_id = json_object_get(json_obj, "source_id");
      if (json_src_id == NULL) {
        snprintf(errbuf, errlen, "nfacctd_offline_read_json_template(): source ID null. Line skipped.\n");
        free(ret);
        return NULL;
      }
      else {
        ret->source_id = json_integer_value(json_src_id);
      }

      free(json_src_id);

      json_t *json_tpl_type = json_object_get(json_obj, "template_type");
      if (json_tpl_type == NULL) {
        snprintf(errbuf, errlen, "nfacctd_offline_read_json_template(): template type null. Line skipped.\n");
        free(ret);
        return NULL;
      }
      else {
        ret->template_type = json_integer_value(json_tpl_type);
      }

      free(json_tpl_type);

      json_t *json_num = json_object_get(json_obj, "num");
      if (json_num == NULL) {
        snprintf(errbuf, errlen, "nfacctd_offline_read_json_template(): num null. Line skipped.\n");
        free(ret);
        return NULL;
      }
      else {
        ret->num = json_integer_value(json_num);
      }

      free(json_num);

      json_t *json_len = json_object_get(json_obj, "len");
      if (json_len == NULL) {
        snprintf(errbuf, errlen, "nfacctd_offline_read_json_template(): len null. Line skipped.\n");
        free(ret);
        return NULL;
      }
      else {
        ret->len = json_integer_value(json_len);
      }

      free(json_len);

      json_t *json_vlen = json_object_get(json_obj, "vlen");
      if (json_vlen == NULL) {
        snprintf(errbuf, errlen, "nfacctd_offline_read_json_template(): vlen null. Line skipped.\n");
        free(ret);
        return NULL;
      }
      else {
        ret->vlen = json_integer_value(json_vlen);
      }

      free(json_vlen);

      json_t *json_agent = json_object_get(json_obj, "agent");
      const char *agent_str = json_string_value(json_agent);
      if(!str_to_addr(agent_str, &ret->agent)) {
        snprintf(errbuf, errlen, "nfacctd_offline_read_json_template(): error creating agent.\n");
        free(ret);
        return NULL;
      }

      json_t *json_list = json_object_get(json_obj, "list");
      if (!json_is_array(json_list))
        snprintf(errbuf, errlen, "nfacctd_offline_read_json_template(): error parsing template fields list.\n");
      else {
          size_t key;
          json_t *value;
          int idx = 0;
          json_array_foreach(json_list, key, value) {
            if (json_object_iter_at(value, "pen") == NULL) {
              ret->list[idx].type = TPL_TYPE_LEGACY;
              struct otpl_field *otpl = malloc(sizeof(struct otpl_field));
              if (!otpl) {
                snprintf(errbuf, errlen, "nfacctd_offline_read_json_template(): Unable to allocate enough memory for a new legacy template field.\n");
                free(ret);
                return NULL;
              }
              memset(otpl, 0, sizeof (struct otpl_field));

              json_t *json_otpl_member = json_object_get(value, "off");
              if (json_otpl_member == NULL) {
                snprintf(errbuf, errlen, "nfacctd_offline_read_json_template(): off null. Line skipped.\n");
                free(ret);
                return NULL;
              }
              else {
                otpl->off = json_integer_value(json_otpl_member);
              }

              json_otpl_member = json_object_get(value, "len");
              if (json_otpl_member == NULL) {
                snprintf(errbuf, errlen, "nfacctd_offline_read_json_template(): len null. Line skipped.\n");
                free(ret);
                return NULL;
              }
              else {
                otpl->len = json_integer_value(json_otpl_member);
              }

              json_otpl_member = json_object_get(value, "tpl_len");
              if (json_otpl_member == NULL) {
                snprintf(errbuf, errlen, "nfacctd_offline_read_json_template(): tpl_len null. Line skipped.\n");
                free(ret);
                return NULL;
              }
              else {
                otpl->tpl_len = json_integer_value(json_otpl_member);
              }

              ret->list[idx].ptr = (char *) otpl;
              free(json_otpl_member);
            }
            else {
              ret->list[idx].type = TPL_TYPE_EXT_DB;
              struct utpl_field *utpl = malloc(sizeof(struct utpl_field));
              if (!utpl) {
                snprintf(errbuf, errlen, "nfacctd_offline_read_json_template(): Unable to allocate enough memory for a new ext_db template field.\n");
                free(ret);
                return NULL;
              }
              memset(utpl, 0, sizeof(struct utpl_field));

              json_t *json_utpl_member = json_object_get(value, "pen");
              if (json_utpl_member == NULL) {
                snprintf(errbuf, errlen, "nfacctd_offline_read_json_template(): pen null. Line skipped.\n");
                free(ret);
                return NULL;
              }
              else {
                utpl->pen = json_integer_value(json_utpl_member);
              }

              json_utpl_member = json_object_get(value, "type");
              if (json_utpl_member == NULL) {
                snprintf(errbuf, errlen, "nfacctd_offline_read_json_template(): type null. Line skipped.\n");
                free(ret);
                return NULL;
              }
              else {
                utpl->type = json_integer_value(json_utpl_member);
              }

              json_utpl_member = json_object_get(value, "off");
              if (json_utpl_member == NULL) {
                snprintf(errbuf, errlen, "nfacctd_offline_read_json_template(): off null. Line skipped.\n");
                free(ret);
                return NULL;
              }
              else {
                utpl->off = json_integer_value(json_utpl_member);
              }

              json_utpl_member = json_object_get(value, "len");
              if (json_utpl_member == NULL) {
                snprintf(errbuf, errlen, "nfacctd_offline_read_json_template(): len null. Line skipped.\n");
                free(ret);
                return NULL;
              }
              else {
                utpl->len = json_integer_value(json_utpl_member);
              }

              json_utpl_member = json_object_get(value, "tpl_len");
              if (json_utpl_member == NULL) {
                snprintf(errbuf, errlen, "nfacctd_offline_read_json_template(): tpl_len null. Line skipped.\n");
                free(ret);
                return NULL;
              }
              else {
                utpl->tpl_len = json_integer_value(json_utpl_member);
              }

              json_utpl_member = json_object_get(value, "repeat_id");
              if (json_utpl_member == NULL) {
                snprintf(errbuf, errlen, "nfacctd_offline_read_json_template(): repeat_id null. Line skipped.\n");
                free(ret);
                return NULL;
              }
              else {
                utpl->repeat_id = json_integer_value(json_utpl_member);
              }

              ret->list[idx].ptr = (char *) utpl;
              free(json_utpl_member);
            }
            idx++;
          }
          free(value);
      }

      free (json_list);
      return ret;
    }

    json_decref(json_obj);
  }
  return ret;
}
#else
void load_templates_from_file(char *path)
{
  if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/core ): load_templates_from_file(): JSON object not created due to missing --enable-jansson\n", config.name);
}

void save_template(struct template_cache_entry *tpl, char *file)
{
  if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/core ): save_template(): JSON object not created due to missing --enable-jansson\n", config.name);
}

struct template_cache_entry *nfacctd_offline_read_json_template(char *buf, char *errbuf, int errlen)
{
  if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/core ): nfacctd_offline_read_json_template(): JSON object not created due to missing --enable-jansson\n", config.name);
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
