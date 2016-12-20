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
#include "nfacctd.h"
#include "intstatsd.h"
#include "pretag_handlers.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "pkt_handlers.h"
#include "ip_flow.h"
#include "classifier.h"
#include "net_aggr.h"
#include "bgp/bgp_packet.h"
#include "bgp/bgp.h"
#include "bmp/bmp.h"

/* variables to be exported away */
struct channels_list_entry channels_list[MAX_N_PLUGINS]; /* communication channels: core <-> plugins */

/* Functions */
void usage_daemon(char *prog_name)
{
  printf("%s (%s)\n", INTSTATS_USAGE_HEADER, PMACCT_BUILD);
  printf("Usage: %s [ -D | -d ] [ -c primitive [ , ... ] ] [ -P plugin [ , ... ] ]\n", prog_name);
  printf("       %s [ -f config_file ]\n", prog_name);
  printf("       %s [ -h ]\n", prog_name);
  printf("\nGeneral options:\n");
  printf("  -h  \tShow this page\n");
  printf("  -V  \tShow version and compile-time options and exit\n");
  printf("  -f  \tLoad configuration from the specified file\n");
  printf("  -a  \tPrint list of supported aggregation primitives\n");
  printf("  -c  \tAggregation method, see full list of primitives with -a (DEFAULT: src_host)\n");
  printf("  -D  \tDaemonize\n"); 
  printf("  -P  \t[ memory | print | mysql | pgsql | sqlite3 | mongodb | amqp | kafka | tee ] \n\tActivate plugin\n"); 
  printf("  -d  \tEnable debug\n");
  printf("  -S  \t[ auth | mail | daemon | kern | user | local[0-7] ] \n\tLog to the specified syslog facility\n");
  printf("  -F  \tWrite Core Process PID into the specified file\n");
  printf("  -R  \tRenormalize sampled data\n");
  printf("  -u  \tLeave IP protocols in numerical format\n");
  printf("\nMemory plugin (-P memory) options:\n");
  printf("  -p  \tSocket for client-server communication (DEFAULT: /tmp/collect.pipe)\n");
  printf("  -b  \tNumber of buckets\n");
  printf("  -m  \tNumber of memory pools\n");
  printf("  -s  \tMemory pool size\n");
  printf("\nPrint plugin (-P print) plugin options:\n");
  printf("  -r  \tRefresh time (in seconds)\n");
  printf("  -O  \t[ formatted | csv | json | avro ] \n\tOutput format\n");
  printf("  -o  \tPath to output file\n");
  printf("  -A  \tAppend output (applies to -o)\n");
  printf("  -E  \tCSV format serparator (applies to -O csv, DEFAULT: ',')\n");
  printf("\n");
  printf("  See QUICKSTART or visit http://wiki.pmacct.net/ for examples.\n");
  printf("\n");
  printf("For suggestions, critics, bugs, contact me: %s.\n", MANTAINER);
}


int main(int argc,char **argv, char **envp)
{
  struct plugins_list_entry *list;
  struct plugin_requests req;
  char config_file[SRVBUFLEN];
  int logf, rc, yes=1, no=0, allowed;
  struct host_addr addr;
  u_int32_t idx;
  int ret;

#if defined ENABLE_IPV6
  struct sockaddr_storage server, client;
  struct ipv6_mreq multi_req6;
#else
  struct sockaddr server, client;
#endif
  int clen = sizeof(client), slen;
  struct ip_mreq multi_req4;

  /* getopt() stuff */
  extern char *optarg;
  extern int optind, opterr, optopt;
  int errflag, cp; 

#if defined HAVE_MALLOPT
  mallopt(M_CHECK_ACTION, 0);
#endif

  umask(077);
  compute_once();

  /* a bunch of default definitions */ 
  reload_map = FALSE;
  reload_geoipv2_file = FALSE;
  sampling_map_allocated = FALSE;
  bpas_map_allocated = FALSE;
  blp_map_allocated = FALSE;
  bmed_map_allocated = FALSE;
  biss_map_allocated = FALSE;
  bta_map_allocated = FALSE;
  bitr_map_allocated = FALSE;
  custom_primitives_allocated = FALSE;
  bta_map_caching = TRUE;
  sampling_map_caching = TRUE;
  plugins_list = NULL;

  errflag = 0;

  memset(cfg_cmdline, 0, sizeof(cfg_cmdline));
  memset(&server, 0, sizeof(server));
  memset(&config, 0, sizeof(struct configuration));
  memset(&config_file, 0, sizeof(config_file));
  memset(&failed_plugins, 0, sizeof(failed_plugins));
  memset(&req, 0, sizeof(req));
  memset(&class, 0, sizeof(class));
  memset(&xflow_status_table, 0, sizeof(xflow_status_table));

  memset(&reload_map_tstamp, 0, sizeof(reload_map_tstamp));
  log_notifications_init(&log_notifications);

  rows = 0;
  glob_pcapt = NULL;

  /* getting commandline values */
  while (!errflag && ((cp = getopt(argc, argv, ARGS_INTSTATSD)) != -1)) {
    if (!cfg_cmdline[rows]) cfg_cmdline[rows] = malloc(SRVBUFLEN);
    memset(cfg_cmdline[rows], 0, SRVBUFLEN);
    switch (cp) {
    case 'P':
      strlcpy(cfg_cmdline[rows], "plugins: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'D':
      strlcpy(cfg_cmdline[rows], "daemonize: true", SRVBUFLEN);
      rows++;
      break;
    case 'd':
      debug = TRUE;
      strlcpy(cfg_cmdline[rows], "debug: true", SRVBUFLEN);
      rows++;
      break;
    case 'O':
      strlcpy(cfg_cmdline[rows], "print_output: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'o':
      strlcpy(cfg_cmdline[rows], "print_output_file: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'A':
      strlcpy(cfg_cmdline[rows], "print_output_file_append: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'E':
      strlcpy(cfg_cmdline[rows], "print_output_separator: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'u':
      strlcpy(cfg_cmdline[rows], "print_num_protos: true", SRVBUFLEN);
      rows++;
      break;
    case 'f':
      strlcpy(config_file, optarg, sizeof(config_file));
      free(cfg_cmdline[rows]);
      cfg_cmdline[rows] = NULL;
      break;
    case 'F':
      strlcpy(cfg_cmdline[rows], "pidfile: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'c':
      strlcpy(cfg_cmdline[rows], "aggregate: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'b':
      strlcpy(cfg_cmdline[rows], "imt_buckets: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'm':
      strlcpy(cfg_cmdline[rows], "imt_mem_pools_number: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'p':
      strlcpy(cfg_cmdline[rows], "imt_path: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'r':
      strlcpy(cfg_cmdline[rows], "sql_refresh_time: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 's':
      strlcpy(cfg_cmdline[rows], "imt_mem_pools_size: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'S':
      strlcpy(cfg_cmdline[rows], "syslog: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'R':
      strlcpy(cfg_cmdline[rows], "sfacctd_renormalize: true", SRVBUFLEN);
      rows++;
      break;
    case 'h':
      usage_daemon(argv[0]);
      exit(0);
      break;
    case 'V':
      version_daemon(NFACCTD_USAGE_HEADER);
      exit(0);
      break;
    case 'a':
      print_primitives(config.acct_type, NFACCTD_USAGE_HEADER);
      exit(0);
      break;
    default:
      usage_daemon(argv[0]);
      exit(1);
      break;
    }
  }

  /* post-checks and resolving conflicts */
  if (strlen(config_file)) {
    if (parse_configuration_file(config_file) != SUCCESS) 
      exit(1);
  }
  else {
    if (parse_configuration_file(NULL) != SUCCESS)
      exit(1);
  }
    
  /* XXX: glue; i'm conscious it's a dirty solution from an engineering viewpoint;
     someday later i'll fix this */
  list = plugins_list;
  while (list) {
    list->cfg.acct_type = ACCT_NF;
    set_default_preferences(&list->cfg);
    if (!strcmp(list->type.string, "core")) { 
      memcpy(&config, &list->cfg, sizeof(struct configuration)); 
      config.name = list->name;
      config.type = list->type.string;
    }
    list = list->next;
  }

  if (config.files_umask) umask(config.files_umask);

  if (config.daemon) {
    list = plugins_list;
    while (list) {
      if (!strcmp(list->type.string, "print") && !list->cfg.print_output_file)
	printf("INFO ( %s/%s ): Daemonizing. Bye bye screen.\n", list->name, list->type.string);
      list = list->next;
    }
    if (debug || config.debug)
      printf("WARN ( %s/core ): debug is enabled; forking in background. Logging to standard error (stderr) will get lost.\n", config.name); 
    daemonize();
  }

  initsetproctitle(argc, argv, envp);
  if (config.syslog) {
    logf = parse_log_facility(config.syslog);
    if (logf == ERR) {
      config.syslog = NULL;
      printf("WARN ( %s/core ): specified syslog facility is not supported. Logging to standard error (stderr).\n", config.name);
    }
    else openlog(NULL, LOG_PID, logf);
    Log(LOG_INFO, "INFO ( %s/core ): Start logging ...\n", config.name);
  }

  if (config.logfile)
  {
    config.logfile_fd = open_output_file(config.logfile, "a", FALSE);
    list = plugins_list;
    while (list) {
      list->cfg.logfile_fd = config.logfile_fd ;
      list = list->next;
    }
  }

  if (config.proc_priority) {
    int ret;

    ret = setpriority(PRIO_PROCESS, 0, config.proc_priority);
    if (ret) Log(LOG_WARNING, "WARN ( %s/core ): proc_priority failed (errno: %d)\n", config.name, errno); 
    else Log(LOG_INFO, "INFO ( %s/core ): proc_priority set to %d\n", config.name, getpriority(PRIO_PROCESS, 0));
  }

  Log(LOG_INFO, "INFO ( %s/core ): %s (%s)\n", config.name, INTSTATS_USAGE_HEADER, PMACCT_BUILD);
  Log(LOG_INFO, "INFO ( %s/core ): %s\n", config.name, PMACCT_COMPILE_ARGS);

  if (strlen(config_file)) {
    char canonical_path[PATH_MAX], *canonical_path_ptr;

    canonical_path_ptr = realpath(config_file, canonical_path);
    if (canonical_path_ptr) Log(LOG_INFO, "INFO ( %s/core ): Reading configuration file '%s'.\n", config.name, canonical_path);
  }
  else Log(LOG_INFO, "INFO ( %s/core ): Reading configuration from cmdline.\n", config.name);

  if (!config.statsd_refresh_time) config.statsd_refresh_time = STATS_REFRESH_TIME_DEFAULT;

  /* Enforcing policies over aggregation methods */
  list = plugins_list;
  while (list) {
   list->cfg.what_to_count = COUNT_NONE;
   list->cfg.data_type = PIPE_TYPE_MSG;
   list = list->next;
  }

  /* signal handling we want to inherit to plugins (when not re-defined elsewhere) */
  signal(SIGCHLD, startup_handle_falling_child); /* takes note of plugins failed during startup phase */
  signal(SIGHUP, reload); /* handles reopening of syslog channel */
  signal(SIGUSR1, push_stats); /* logs various statistics via Log() calls */ 
  signal(SIGUSR2, reload_maps); /* sets to true the reload_maps flag */
  signal(SIGPIPE, SIG_IGN); /* we want to exit gracefully when a pipe is broken */

  /* If no IP address is supplied, let's set our default
     behaviour: IPv4 address, INADDR_ANY, port 2100 */
  if (!config.nfacctd_port) config.nfacctd_port = DEFAULT_NFACCTD_PORT;
#if (defined ENABLE_IPV6)
  if (!config.nfacctd_ip) {
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&server;

    sa6->sin6_family = AF_INET6;
    sa6->sin6_port = htons(config.nfacctd_port);
    slen = sizeof(struct sockaddr_in6);
  }
#else
  if (!config.nfacctd_ip) {
    struct sockaddr_in *sa4 = (struct sockaddr_in *)&server;

    sa4->sin_family = AF_INET;
    sa4->sin_addr.s_addr = htonl(0);
    sa4->sin_port = htons(config.nfacctd_port);
    slen = sizeof(struct sockaddr_in);
  }
#endif
  else {
    trim_spaces(config.nfacctd_ip);
    ret = str_to_addr(config.nfacctd_ip, &addr);
    if (!ret) {
      Log(LOG_ERR, "ERROR ( %s/core ): 'nfacctd_ip' value is not valid. Exiting.\n", config.name);
      exit(1);
    }
    slen = addr_to_sa((struct sockaddr *)&server, &addr, config.nfacctd_port);
  }

  /* socket creation */
  config.sock = socket(((struct sockaddr *)&server)->sa_family, SOCK_DGRAM, 0);
  if (config.sock < 0) {
#if (defined ENABLE_IPV6)
    /* retry with IPv4 */
    if (!config.nfacctd_ip) {
      struct sockaddr_in *sa4 = (struct sockaddr_in *)&server;

      sa4->sin_family = AF_INET;
      sa4->sin_addr.s_addr = htonl(0);
      sa4->sin_port = htons(config.nfacctd_port);
      slen = sizeof(struct sockaddr_in);

      config.sock = socket(((struct sockaddr *)&server)->sa_family, SOCK_DGRAM, 0);
    }
#endif

    if (config.sock < 0) {
      Log(LOG_ERR, "ERROR ( %s/core ): socket() failed.\n", config.name);
      exit(1);
    }
  }

  /* bind socket to port */
  rc = setsockopt(config.sock, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));
  if (rc < 0) Log(LOG_ERR, "WARN ( %s/core ): setsockopt() failed for SO_REUSEADDR.\n", config.name);

#if (defined ENABLE_IPV6) && (defined IPV6_BINDV6ONLY)
  rc = setsockopt(config.sock, IPPROTO_IPV6, IPV6_BINDV6ONLY, (char *) &no, (socklen_t) sizeof(no));
  if (rc < 0) Log(LOG_ERR, "WARN ( %s/core ): setsockopt() failed for IPV6_BINDV6ONLY.\n", config.name);
#endif

  if (config.nfacctd_pipe_size) {
    int l = sizeof(config.nfacctd_pipe_size);
    int saved = 0, obtained = 0;

    getsockopt(config.sock, SOL_SOCKET, SO_RCVBUF, &saved, &l);
    Setsocksize(config.sock, SOL_SOCKET, SO_RCVBUF, &config.nfacctd_pipe_size, sizeof(config.nfacctd_pipe_size));
    getsockopt(config.sock, SOL_SOCKET, SO_RCVBUF, &obtained, &l);

    if (obtained < saved) {
      Setsocksize(config.sock, SOL_SOCKET, SO_RCVBUF, &saved, l);
      getsockopt(config.sock, SOL_SOCKET, SO_RCVBUF, &obtained, &l);
    }
    Log(LOG_INFO, "INFO ( %s/core ): nfacctd_pipe_size: obtained=%d target=%d.\n", config.name, obtained, config.nfacctd_pipe_size);
  }

  /* Multicast: memberships handling */
  for (idx = 0; mcast_groups[idx].family && idx < MAX_MCAST_GROUPS; idx++) {
    if (mcast_groups[idx].family == AF_INET) { 
      memset(&multi_req4, 0, sizeof(multi_req4));
      multi_req4.imr_multiaddr.s_addr = mcast_groups[idx].address.ipv4.s_addr;
      if (setsockopt(config.sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&multi_req4, sizeof(multi_req4)) < 0) {
        Log(LOG_ERR, "ERROR ( %s/core ): IPv4 multicast address - ADD membership failed.\n", config.name);
        exit(1);
      }
    }
#if defined ENABLE_IPV6
    if (mcast_groups[idx].family == AF_INET6) {
      memset(&multi_req6, 0, sizeof(multi_req6));
      ip6_addr_cpy(&multi_req6.ipv6mr_multiaddr, &mcast_groups[idx].address.ipv6); 
      if (setsockopt(config.sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, (char *)&multi_req6, sizeof(multi_req6)) < 0) {
        Log(LOG_ERR, "ERROR ( %s/core ): IPv6 multicast address - ADD membership failed.\n", config.name);
        exit(1);
      }
    }
#endif
  }

  rc = bind(config.sock, (struct sockaddr *) &server, slen);
  if (rc < 0) {
    Log(LOG_ERR, "ERROR ( %s/core ): bind() to ip=%s port=%d/udp failed (errno: %d).\n", config.name, config.nfacctd_ip, config.nfacctd_port, errno);
    exit(1);
  }

  init_classifiers(NULL);

  /* plugins glue: creation */
  load_plugins(&req);
    Log(LOG_INFO, "INFO ( %s/core ): TEST\n", config.name);
  load_plugin_filters(1);
  evaluate_packet_handlers();
  pm_setproctitle("%s [%s]", "Core Process", config.proc_name);
  if (config.pidfile) write_pid_file(config.pidfile);
  load_networks(config.networks_file, &nt, &nc);

  /* signals to be handled only by the core process;
     we set proper handlers after plugin creation */
  signal(SIGINT, my_sigint_handler);
  signal(SIGTERM, my_sigint_handler);
  signal(SIGCHLD, handle_falling_child);
  kill(getpid(), SIGCHLD);

  /* Main loop */
  for(;;) {
    generate_stats();
    // TODO use refresh_time config key
    sleep(1);
  }
}

void compute_once()
{
  struct pkt_data dummy;

  CounterSz = sizeof(dummy.pkt_len);
  PdataSz = sizeof(struct pkt_data);
  PpayloadSz = sizeof(struct pkt_payload);
  PmsgSz = sizeof(struct pkt_msg);
  PextrasSz = sizeof(struct pkt_extras);
  PbgpSz = sizeof(struct pkt_bgp_primitives);
  PlbgpSz = sizeof(struct pkt_legacy_bgp_primitives);
  PnatSz = sizeof(struct pkt_nat_primitives);
  PmplsSz = sizeof(struct pkt_mpls_primitives);
  PvhdrSz = sizeof(struct pkt_vlen_hdr_primitives);
  PmLabelTSz = sizeof(pm_label_t);
  PtLabelTSz = sizeof(pt_label_t);
  ChBufHdrSz = sizeof(struct ch_buf_hdr);
  CharPtrSz = sizeof(char *);
  NfHdrV1Sz = sizeof(struct struct_header_v1);
  NfHdrV5Sz = sizeof(struct struct_header_v5);
  NfHdrV7Sz = sizeof(struct struct_header_v7);
  NfHdrV8Sz = sizeof(struct struct_header_v8);
  NfHdrV9Sz = sizeof(struct struct_header_v9);
  NfDataHdrV9Sz = sizeof(struct data_hdr_v9);
  NfTplHdrV9Sz = sizeof(struct template_hdr_v9);
  NfTplFieldV9Sz = sizeof(struct template_field_v9);
  NfOptTplHdrV9Sz = sizeof(struct options_template_hdr_v9);
  NfDataV1Sz = sizeof(struct struct_export_v1);
  NfDataV5Sz = sizeof(struct struct_export_v5);
  NfDataV7Sz = sizeof(struct struct_export_v7);
  IP4HdrSz = sizeof(struct my_iphdr);
  IP4TlSz = sizeof(struct my_iphdr)+sizeof(struct my_tlhdr);
  PptrsSz = sizeof(struct packet_ptrs);
  CSSz = sizeof(struct class_st);
  HostAddrSz = sizeof(struct host_addr);
  UDPHdrSz = sizeof(struct my_udphdr);
  IpFixHdrSz = sizeof(struct struct_header_ipfix); 

#if defined ENABLE_IPV6
  IP6HdrSz = sizeof(struct ip6_hdr);
  IP6AddrSz = sizeof(struct in6_addr);
  IP6TlSz = sizeof(struct ip6_hdr)+sizeof(struct my_tlhdr);
#endif
}

void generate_stats()
{
  struct plugins_list_entry *plugin;
  int index;
  u_int64_t tot_pipe_sz, tot_pipe_used_sz, tot_pipe_used_cnt;

  tot_pipe_sz = tot_pipe_used_sz = 0;
  for(index = 0; index < MAX_N_PLUGINS; index++) {
    if (!channels_list[index].plugin) continue;
    plugin = channels_list[index].plugin;
    Log(LOG_INFO, "INFO ( %s/core ): config name %s: pipe_size: %lu\n", config.name, plugin->name, plugin->cfg.pipe_size);
    tot_pipe_sz += plugin->cfg.pipe_size;
    //tot_pipe_used_sz += 

    switch (plugin->cfg.type_id) {
    case PLUGIN_ID_KAFKA:
      // TODO
      break;
    default:
      break;
    }
  }
  Log(LOG_INFO, "INFO ( %s/core ): total_pipe_size: %lu\n", config.name, tot_pipe_sz);
  
}
