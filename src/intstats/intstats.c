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
#define __INTSTATSD_C

/* includes */
#include "pmacct.h"
#include "addr.h"
#include "thread_pool.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "intstats.h"

/* variables to be exported away */
thread_pool_t *intstats_pool;
struct stats_channel_entry stats_channels_list[MAX_N_PLUGINS]; /* stats communication channels: core <-> plugins */
struct channels_list_entry *channels_list; // TODO make it usable for several daemons
struct daemon_stats_linked_func *daemon_stats_funcs = NULL; /* pointer to first daemon stats generation function */
struct active_thread *at;

//TODO: note: stats will only work for one daemon at a time in the current config
// if several daemons have config enabled, each wrapper will trigger config for its daemon and
// all the previous ones (if all of this code works properly)
/* Functions */
#if defined ENABLE_THREADS
void intstats_wrapper(const struct channels_list_entry *chan_list, void (*func)())
{
  struct intstats_data *t_data;
  struct daemon_stats_linked_func *dslf = NULL, *prev_dslf = NULL;

  if (!config.metrics_what_to_count) {
    Log(LOG_WARNING, "WARN ( %s/core/STATS ): No metric set. Check your configuration.\n", config.name);
    return;
  }

  /* initialize threads pool */
  intstats_pool = allocate_thread_pool(1);
  assert(intstats_pool);
  Log(LOG_DEBUG, "DEBUG ( %s/core/STATS ): %d thread(s) initialized\n", config.name, 1);

  t_data = malloc(sizeof(struct intstats_data));
  if (!t_data) {
    Log(LOG_ERR, "ERROR ( %s/core/STATS ): malloc() struct intstats_data failed. Terminating.\n", config.name);
    exit_all(1);
  }
  intstats_prepare_thread(t_data);

  channels_list = chan_list;
  if (daemon_stats_funcs) dslf = daemon_stats_funcs;

  while (dslf) {
    prev_dslf = dslf;
    dslf = dslf->next;
  }
  dslf = malloc(sizeof(struct daemon_stats_linked_func));
  if (!dslf) {
    Log(LOG_ERR, "ERROR ( %s/core/STATS ): Unable to allocate enough memory for a new daemon stats linked function.\n", config.name);
    return;
  }
  memset(dslf, 0, sizeof(struct daemon_stats_linked_func));

  dslf->func = func;
  if (prev_dslf) prev_dslf->next = dslf;

  if (!prev_dslf) daemon_stats_funcs = dslf;

  /* giving a kick to the intstats thread */
  send_to_pool(intstats_pool, intstats_daemon, t_data);
  Log(LOG_DEBUG, "DEBUG ( %s/core/STATS ): intstats_daemon sent to pool\n", config.name);
}
#endif

void intstats_prepare_thread(struct intstats_data *t_data)
{
  if (!t_data) return;

  memset(t_data, 0, sizeof(struct intstats_data));
  t_data->is_thread = TRUE;
  t_data->log_str = malloc(strlen("core/STATS") + 1);
  strcpy(t_data->log_str, "core/STATS");
}

void intstats_daemon(void *t_data_void)
{
  struct metric *met_tmp = NULL;
  time_t start, end;
  sighandler_t prev_sig;
  int sock, nb_children, nb_term;
  int counter = 0, test; // TEST

  /* The first metric should not need to be on a shared memory area since metrics are
   * initialised following an array which first element represents a metric that is currently
   * computed in this thread. However, this is done so to maintain consistency with other metrics
   * structures and avoid side effects in case plugin_buffers_generate_stats() eventually creates
   * its own thread(s). */
  met = map_shared(0, sizeof(struct metric), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
  if (met == MAP_FAILED) {
    Log(LOG_ERR, "ERROR ( %s/core/STATS ): unable to allocate metric structure. Exiting ...\n", config.name);
    exit(1);
  }

  memset(met, 0, sizeof(struct metric));

  if (init_metrics(&met) <= 0) {
    Log(LOG_ERR, "ERROR ( %s/core/STATS ): Error during metrics initialisation. Exiting.\n", config.name);
    exit(1);
  }
  //check_test_met(met);
  Log(LOG_DEBUG, "DEBUG ( %s/core/STATS ): metric values initialised\n", config.name);

  sock = init_statsd_sock();
  Log(LOG_DEBUG, "DEBUG ( %s/core/STATS ): socket initialized\n", config.name);

  if (!config.statsd_refresh_time) config.statsd_refresh_time = STATS_REFRESH_TIME_DEFAULT;

  //XXX: this periodicity implementation assumes stats collection and sending combined are shorter than configured period
  Log(LOG_DEBUG, "DEBUG ( %s/core/STATS ): CONFIGURED REFRESH TIME: %d\n", config.name, config.statsd_refresh_time);
  while (1) {
    nb_children = 0;
    nb_term = 0;
    start = time(NULL);
    reset_metrics_values(met);
    Log(LOG_DEBUG, "DEBUG ( %s/core/STATS ): metric values reset\n", config.name);

    nb_children += launch_core_daemons(met);
    Log(LOG_DEBUG, "DEBUG ( %s/core/STATS ): core daemon launched\n", config.name);
    nb_children += launch_plugins_daemons(met);
    Log(LOG_DEBUG, "DEBUG ( %s/core/STATS ): plugins daemon launched\n", config.name);

    plugin_buffers_generate_stats(met);

    int term_pid = -1;
    while ((term_pid = waitpid(-1, NULL, WUNTRACED)) > 0) {
      /* Terminated thread is deleted from the list only if it is one
       * of the threads that were being waited for */
      if (delete_active_thread(term_pid)) nb_term++;
      printf("Just terminated process ID: %d\n", term_pid);
      printf("nb_term: %d , nb_children: %d\n", nb_term, nb_children);
      print_active_threads(); // TEST

      if (!at || !check_active_threads()) break;
    }

    met_tmp = met;
    while(met_tmp) {
      send_data(met_tmp, sock);
      met_tmp = met_tmp->next;
    }
    end = time(NULL);
    prev_sig = signal(SIGCHLD, SIG_IGN); /* SIGCHLD has to be ignored otherwise sleep is interrupted */
    test = sleep(MAX(0, config.statsd_refresh_time - (end - start)));
    signal(SIGCHLD, prev_sig);
    Log(LOG_DEBUG, "DEBUG ( %s/core/STATS ): --------- finished iteration #%d (%u left to sleep)\n", config.name, counter, test);
    counter++;
  }
}

int check_test_met(struct metric const *met_ptr)
{
  //XXX: Test function. Can be safely deleted once internal stats are stable
  int cnt = 0;
  struct metric *tmp;

  tmp = met_ptr;
  while (tmp) { cnt++; tmp = tmp->next; }
  Log(LOG_DEBUG, "DEBUG ( %s/core/STATS ): TEST: %d metrics found (%p)\n", config.name, cnt, met_ptr);

  return cnt;
}

void print_metrics(struct metric *ptr)
{
  //XXX: Test function. Can be safely deleted once internal stats are stable
  struct metric *tmp;
  tmp = ptr;

  while(tmp) {
    Log(LOG_DEBUG, "DEBUG ( %s/core/STATS ): address: %p, \n", config.name, tmp);
    Log(LOG_DEBUG, "DEBUG ( %s/core/STATS ): label: %s, \n", config.name, tmp->type.label);
    Log(LOG_DEBUG, "DEBUG ( %s/core/STATS ): type: %d, \n", config.name, tmp->type.type);
    Log(LOG_DEBUG, "DEBUG ( %s/core/STATS ): statsd_fmt: %d, \n", config.name, tmp->type.statsd_fmt);
    Log(LOG_DEBUG, "DEBUG ( %s/core/STATS ): id: %d, \n", config.name, tmp->type.id);

    switch(tmp->type.type) {
      case STATS_TYPE_INT:
        Log(LOG_DEBUG, "DEBUG ( %s/core/STATS ): value (int): %d, \n", config.name, tmp->int_value);
        break;
      case STATS_TYPE_LONGINT:
        Log(LOG_DEBUG, "DEBUG ( %s/core/STATS ): value (long int): %ld, \n", config.name, tmp->long_value);
        break;
      case STATS_TYPE_FLOAT:
        Log(LOG_DEBUG, "DEBUG ( %s/core/STATS ): value (float): %f, \n", config.name, tmp->float_value);
        break;
      case STATS_TYPE_STRING:
        Log(LOG_DEBUG, "DEBUG ( %s/core/STATS ): value (string): %s, \n", config.name, tmp->string_value);
        break;
      default:
        Log(LOG_DEBUG, "DEBUG ( %s/core/STATS ): ERROR: no type found, \n", config.name, tmp->string_value);
        break;
    }
    tmp = tmp->next;
  }
}


int launch_plugins_daemons(struct metric *met_ptr)
{
  int pid, ret, index = 0, thread_cnt = 0;
  struct plugins_list_entry *list = plugins_list;

  while (list) {
    if (list->cfg.intstats_daemon && list->type.stats_func) {
      switch (pid = fork()) {
        case -1: /* Something went wrong */
          Log(LOG_WARNING, "WARN ( %s/%s ): Unable to initialize stats generation in: %s\n", list->name, list->type.string, strerror(errno));
          break;
        case 0: /* Child */
        /* SIGCHLD handling issue: SysV avoids zombies by ignoring SIGCHLD; to emulate
           such semantics on BSD systems, we need a handler like handle_falling_child() */
#if defined (IRIX) || (SOLARIS)
          signal(SIGCHLD, SIG_IGN);
#else
          signal(SIGCHLD, ignore_falling_child);
#endif

#if defined HAVE_MALLOPT
          mallopt(M_CHECK_ACTION, 0);
#endif

          (*list->type.stats_func)(met_ptr, list->cfg.name);
          exit(0);
        default: /* Parent */
          insert_active_thread(pid);
          printf("Kafka: Just started process ID: %d\n", pid); //TEST
          thread_cnt++;
          break;
      }
    }
    list = list->next;
  }
  return thread_cnt;
}

int launch_core_daemons(struct metric *met_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  struct daemon_stats_linked_func *dslf;
  struct active_thread *at_tmp;
  int pid, status, thread_cnt = 0;

  dslf = daemon_stats_funcs;
  if(!dslf) Log(LOG_ERR, "dslf NULL\n");
  while (dslf) {
    if(dslf->func) {
      switch (pid = fork()) {
        case -1: /* Something went wrong */
          Log(LOG_WARNING, "WARN ( %s/core ): Unable to initialize stats generation in daemon: %s\n", config.name, config.proc_name, strerror(errno));
          //delete_pipe_channel(list->pipe[1]);
          break;
        case 0: /* Child */
        /* SIGCHLD handling issue: SysV avoids zombies by ignoring SIGCHLD; to emulate
           such semantics on BSD systems, we need a handler like handle_falling_child() */
#if defined (IRIX) || (SOLARIS)
          signal(SIGCHLD, SIG_IGN);
#else
          signal(SIGCHLD, ignore_falling_child);
#endif

#if defined HAVE_MALLOPT
          mallopt(M_CHECK_ACTION, 0);
#endif

          /*
          close(config.sock);
          close(config.bgp_sock);
          if (!list->cfg.pipe_amqp) close(list->pipe[1]);
          */
          (*dslf->func)(met_ptr);
          exit(0);
        default: /* Parent */
          insert_active_thread(pid);
          printf("Core: Just started process ID: %d\n", pid); //TEST
          thread_cnt++;
          break;
      }
    }
    thread_cnt++;
    dslf = dslf->next;
  }

  return thread_cnt;
}

void plugin_buffers_generate_stats(struct metric *met_ptr)
{
  struct plugins_list_entry *plugin;
  struct channels_list_entry *cle = channels_list;
  struct metric *met_tmp, *fill_rate_met = NULL;
  int index, tot_sz = 0, used_sz = 0;

  //XXX: could eventually launch a separate thread if more metrics are needed
  for (index = 0; index < MAX_N_PLUGINS; index++) {
    plugin = cle[index].plugin;
    if (plugin == NULL) continue;

    tot_sz += cle->rg.end - cle->rg.base;
    used_sz += cle->rg.ptr - cle->rg.base;

    met_tmp = met_ptr;
    while (met_tmp) {
      switch (met_tmp->type.id) {
        case METRICS_INT_PLUGIN_QUEUES_TOT_SZ:
          met_tmp->int_value += cle->rg.end - cle->rg.base;
          break;
        case METRICS_INT_PLUGIN_QUEUES_USED_SZ:
          met_tmp->int_value += cle->rg.ptr - cle->rg.base;
          break;
        case METRICS_INT_PLUGIN_QUEUES_USED_CNT:
          //TODO check functional validity
          met_tmp->int_value += (int) ((cle->rg.ptr - cle->rg.base) / sizeof(struct pkt_data));
          break;
        case METRICS_INT_PLUGIN_QUEUES_FILL_RATE:
          //TODO check functional validity
          fill_rate_met = met_tmp;
          break;
        default:
          break;
    }
    met_tmp = met_tmp->next;
    }
  }

  if (fill_rate_met) {
    fill_rate_met->float_value = (float) (100 * used_sz) / (float) tot_sz;
  }
}

int init_metrics(struct metric **met_ptr)
{
  int met_cnt = 0, met_idx;
  struct metric *met_tmp, *prev_met = NULL;
  struct plugins_list_entry *list = plugins_list;

  met_tmp = *met_ptr;
  while (list) {
    for(met_idx = 0; strcmp(_metrics_types_matrix[met_idx].label, ""); met_idx++) {

      if(list->cfg.metrics_what_to_count & _metrics_types_matrix[met_idx].id
          && (list->type.id == _metrics_types_matrix[met_idx].plugin_id)) {

        if (prev_met) {
          met_tmp = map_shared(0, sizeof(struct metric), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
          if (met_tmp == MAP_FAILED) {
            Log(LOG_ERR, "ERROR ( %s/%s/STATS ): unable to allocate metric structure. Exiting ...\n", list->cfg.name, list->type.string);
            exit(1);
          }
          memset(met_tmp, 0, sizeof(struct metric));
        }

        met_tmp->type = _metrics_types_matrix[met_idx];

        /* Prefix metric label with possible plugin name, truncated if needed
         * (NB: some characters (brackets, etc) are ignored by statsD, resulting in ugly names) */
        if (list->cfg.name) {
          char lbl[STATS_LABEL_LEN];

          memset(lbl, 0, STATS_LABEL_LEN);
          strncat(lbl, list->cfg.name, STATS_LABEL_LEN - 1);
          strcat(lbl, "-");
          strncat(lbl, met_tmp->type.label, STATS_LABEL_LEN - strlen(lbl) - 1);
          strncpy(met_tmp->type.label, lbl, STATS_LABEL_LEN - 1);
        }

        Log(LOG_DEBUG, "DEBUG ( %s/%s/STATS ): Initializing metric \"%s\"\n", list->cfg.name, list->type.string, met_tmp->type.label);

        if (met_ptr == NULL) met_ptr = &met_tmp;

        if (prev_met) prev_met->next = met_tmp;

        prev_met = met_tmp;
        met_cnt++;
      }
    }
    list = list->next;
  }

  return met_cnt;
}

void reset_metrics_values(struct metric *m)
{
  struct metric *m_tmp;
  m_tmp = m;
  while (m_tmp) {
    switch(m_tmp->type.type) {
      case STATS_TYPE_INT:
        m_tmp->int_value = 0;
        break;
      case STATS_TYPE_LONGINT:
        m_tmp->long_value = 0;
        break;
      case STATS_TYPE_FLOAT:
        m_tmp->float_value = 0.0;
        break;
      case STATS_TYPE_STRING:
        m_tmp->string_value = "";
        break;
      default:
        break;
    }
    m_tmp = m_tmp->next;
  }
}

int init_statsd_sock() {
  int sock, slen;
  int rc, ret, yes=1, no=0, buflen=0;
  struct host_addr addr;
#if defined ENABLE_IPV6
  struct sockaddr_storage server, dest_sockaddr;
#else
  struct sockaddr server, dest_sockaddr;
#endif

  memset(&server, 0, sizeof(server));
  memset(&dest_sockaddr, 0, sizeof(dest_sockaddr));

  /* If no IP address is supplied, let's set our default
     behaviour: IPv4 address, INADDR_ANY, port 2100 */
  if (!config.intstats_src_port) config.intstats_src_port = STATS_SRC_PORT_DEFAULT;
#if (defined ENABLE_IPV6)
  if (!config.intstats_src_ip) {
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&server;

    sa6->sin6_family = AF_INET6;
    sa6->sin6_port = htons(config.intstats_src_port);
    slen = sizeof(struct sockaddr_in6);
  }
#else
  if (!config.intstats_src_ip) {
    struct sockaddr_in *sa4 = (struct sockaddr_in *)&server;

    sa4->sin_family = AF_INET;
    sa4->sin_addr.s_addr = htonl(0);
    sa4->sin_port = htons(config.intstats_src_port);
    slen = sizeof(struct sockaddr_in);
  }
#endif
  else {
    trim_spaces(config.intstats_src_ip);
    ret = str_to_addr(config.intstats_src_ip, &addr);
    if (!ret) {
      Log(LOG_ERR, "ERROR ( %s/core ): 'intstats_src_ip' value is not valid. Exiting.\n", config.name);
      exit(1);
    }
    slen = addr_to_sa((struct sockaddr *)&server, &addr, config.intstats_src_port);
  }

  sock = socket(((struct sockaddr *)&server)->sa_family, SOCK_DGRAM, 0);

  if (sock < 0) {
    Log(LOG_ERR, "ERROR ( %s/%s ): socket() failed. Terminating.\n", config.name, config.type);
    exit_all(1);
  }

  /* bind socket to port */
  rc = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));
  if (rc < 0) Log(LOG_ERR, "WARN ( %s/%s ): setsockopt() failed for SO_REUSEADDR.\n", config.name, config.type);

#if (defined ENABLE_IPV6) && (defined IPV6_BINDV6ONLY)
  rc = setsockopt(sock, IPPROTO_IPV6, IPV6_BINDV6ONLY, (char *) &no, (socklen_t) sizeof(no));
  if (rc < 0) Log(LOG_ERR, "WARN ( %s/%s ): setsockopt() failed for IPV6_BINDV6ONLY.\n", config.name, config.type);
#endif

  rc = bind(sock, (struct sockaddr *) &server, slen);
  if (rc < 0) {
    Log(LOG_ERR, "ERROR ( %s/%s ): bind() to ip=%s port=%d/udp failed (errno: %d).\n", config.name, config.type, config.intstats_src_ip, config.intstats_src_port, errno);
    exit(1);
  }
  return sock;
}

int send_data(struct metric *m, int sd) {
  int dest_addr_len;
  int ret, buflen=0;
  char *statsd_type;
  char data[SRVBUFLEN], databuf[SRVBUFLEN], val_str[SRVBUFLEN];
  struct host_addr dest_addr;
#if defined ENABLE_IPV6
  struct sockaddr_storage server, dest_sockaddr;
#else
  struct sockaddr server, dest_sockaddr;
#endif

  memset(databuf, 0, sizeof(databuf));

  switch(m->type.type) {
    case STATS_TYPE_INT:
      sprintf(val_str, "%d", m->int_value);
      break;
    case STATS_TYPE_LONGINT:
      sprintf(val_str, "%ld", m->long_value);
      break;
    case STATS_TYPE_FLOAT:
      sprintf(val_str, "%.2f", m->float_value);
      break;
    case STATS_TYPE_STRING:
      sprintf(val_str, "%s", m->string_value);
      break;
  }

  switch(m->type.statsd_fmt) {
    case STATSD_FMT_COUNTER:
      statsd_type = "c";
      break;
    case STATSD_FMT_GAUGE:
      statsd_type = "g";
      break;
  }

  sprintf(data, "%s:%s|%s", m->type.label, val_str, statsd_type);

  ret = str_to_addr(config.statsd_host, &dest_addr);
  if (!ret) {
    Log(LOG_ERR, "ERROR ( %s/%s ): statsd_host value is not a valid IPv4/IPv6 address. Terminating.\n", config.name, config.type);
    exit_all(1);
  }
  dest_addr_len = addr_to_sa((struct sockaddr *)&dest_sockaddr, &dest_addr, config.statsd_port);
  memcpy(databuf, data, strlen(data));
  buflen += strlen(data);
  databuf[buflen] = '\x4'; /* EOT */

  ret = sendto(sd, databuf, buflen, 0, &dest_sockaddr, dest_addr_len);
  if (ret == -1)
    Log(LOG_ERR, "ERROR ( %s/%s ): Error sending message :%s\n", config.name, config.type, strerror(errno));
  else
    Log(LOG_DEBUG, "DEBUG ( %s/core/STATS ): sent data: %s\n", config.name, data);

  return ret;
}

void insert_active_thread(int pid) {
  struct active_thread *at_tmp;

  if (!at) {
    at = malloc(sizeof(struct active_thread));
    memset(at, 0, sizeof(struct active_thread));
    at->pid = pid;
  }
  else {
    at_tmp = malloc(sizeof(struct active_thread));
    memset(at_tmp, 0, sizeof(struct active_thread));
    at_tmp->pid = pid;
    at_tmp->next = at;
    at = at_tmp;
  }
}

int delete_active_thread(int pid) {
  struct active_thread *at_tmp, *at_del, *at_prev = NULL;
  int ret = 0;

  at_tmp = at;
  while (at_tmp) {
      if (at_tmp->pid == pid) {
        at_del = at_tmp;
        if (!at_prev) {
          at = at_tmp->next;
        }
        else {
          at_prev->next = at_tmp->next;
        }
        free(at_tmp);
        ret++;
        break;
      }
      at_prev = at_tmp;
      at_tmp = at_tmp->next;
  }
  return ret;
}

int check_active_threads() {
  struct active_thread *at_tmp;
  int nb_threads = 0;

  at_tmp = at;
  while (at_tmp) {
    nb_threads++;
    if (kill(at_tmp->pid, 0) == -1) {
      int pid = at_tmp->pid;
      delete_active_thread(at_tmp->pid);
      printf("Deleted non-existent thread %d\n", pid);
      nb_threads--;
    }
    at_tmp = at_tmp->next;
  }
  return nb_threads; /* remaining active threads */
}

void print_active_threads() {
  //XXX: Test function. Can be safely deleted once internal stats are stable
    struct active_thread *at_tmp = at;
    while(at_tmp) {
        printf("Active thread pid: %d\n", at_tmp->pid);
        at_tmp = at_tmp->next;
    }
}
