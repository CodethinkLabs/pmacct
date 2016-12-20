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
#define STATS_REFRESH_TIME_DEFAULT  60

/* functions */
#if (!defined __INTSTATSD_C)
#define EXT extern
#else
#define EXT
#endif
EXT u_int8_t NF_evaluate_flow_type(struct template_cache_entry *, struct packet_ptrs *);
EXT u_int16_t NF_evaluate_direction(struct template_cache_entry *, struct packet_ptrs *);
EXT pm_class_t NF_evaluate_classifiers(struct xflow_status_entry_class *, pm_class_t *, struct xflow_status_entry *);
EXT void reset_mac(struct packet_ptrs *);
EXT void reset_mac_vlan(struct packet_ptrs *);
EXT void reset_ip4(struct packet_ptrs *);
EXT void reset_ip6(struct packet_ptrs *);
EXT void notify_malf_packet(short int, char *, struct sockaddr *, u_int32_t);
EXT int NF_find_id(struct id_table *, struct packet_ptrs *, pm_id_t *, pm_id_t *);

EXT char *nfv578_check_status(struct packet_ptrs *);
EXT char *nfv9_check_status(struct packet_ptrs *, u_int32_t, u_int32_t, u_int32_t, u_int8_t);

EXT struct template_cache tpl_cache;
EXT struct v8_handler_entry v8_handlers[15];

EXT struct host_addr debug_a;
EXT u_char debug_agent_addr[50];
EXT u_int16_t debug_agent_port;
#undef EXT

#if (!defined __NFV9_TEMPLATE_C)
#define EXT extern
#else
#define EXT
#endif
EXT void generate_stats();
#undef EXT
