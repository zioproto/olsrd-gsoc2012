/* System includes */
#include <stddef.h>             /* NULL */
#include <sys/types.h>          /* ssize_t */
#include <string.h>             /* strerror() */
#include <stdarg.h>             /* va_list, va_start, va_end */
#include <errno.h>              /* errno */
#include <assert.h>             /* assert() */
#include <linux/if_ether.h>     /* ETH_P_IP */
#include <linux/if_packet.h>    /* struct sockaddr_ll, PACKET_MULTICAST */
//#include <pthread.h> /* pthread_t, pthread_create() */
#include <signal.h>             /* sigset_t, sigfillset(), sigdelset(), SIGINT */
#include <netinet/ip.h>         /* struct ip */
#include <netinet/udp.h>        /* struct udphdr */
#include <unistd.h>             /* close() */

#include <netinet/in.h>
#include <netinet/ip6.h>

/* OLSRD includes */
#include "plugin_util.h"        /* set_plugin_int */
#include "defs.h"               /* olsr_cnf, //OLSR_PRINTF */
#include "ipcalc.h"
#include "olsr.h"               /* //OLSR_PRINTF */
#include "mid_set.h"            /* mid_lookup_main_addr() */
#include "link_set.h"           /* get_best_link_to_neighbor() */
#include "net_olsr.h"           /* ipequal */
#include "hna_set.h"

/* plugin includes */
#include "NetworkInterfaces.h"  /* TBmfInterface, CreateBmfNetworkInterfaces(), CloseBmfNetworkInterfaces() */
#include "Address.h"            /* IsMulticast() */
#include "Packet.h"             /* ENCAP_HDR_LEN, BMF_ENCAP_TYPE, BMF_ENCAP_LEN etc. */
#include "list_backport.h"
#include "RouterElection.h"
#include "mdns.h"

int ENTRYTTL = 120;
ISMASTER = 1;

//List for routers
struct list_entity ListOfRouter;
#define ROUTER_ELECTION_ENTRIES(nr, iterator) listbackport_for_each_element_safe(&ListOfRouter, nr, list, iterator)

int ParseElectionPacket (struct RtElHelloPkt *rcvPkt, struct RouterListEntry *listEntry){
  OLSR_PRINTF(0, "parsing ipv4 packet");
  listEntry = (struct RouterListEntry *)malloc(sizeof(struct RouterListEntry));
  listEntry->ttl = ENTRYTTL;
  listEntry->network_id = rcvPkt->network_id;
  (void) memcpy(&listEntry->router_id, &rcvPkt->router_id.v4, sizeof(struct in_addr));  //Need to insert an address validity check?
  return 1;
}

int ParseElectionPacket6 (struct RtElHelloPkt *rcvPkt, struct RouterListEntry6 *listEntry6){
  OLSR_PRINTF(0, "parsing ipv6 packet");
  listEntry6 = (struct RouterListEntry6 *)malloc(sizeof(struct RouterListEntry6));
  listEntry6->ttl = ENTRYTTL;
  listEntry6->network_id = rcvPkt->network_id;
  (void) memcpy(&listEntry6->router_id, &rcvPkt->router_id.v6, sizeof(struct in6_addr));//Need to insert an address validity check?
  return 1;
}

int UpdateRouterList (struct RouterListEntry *listEntry){

  struct RouterListEntry *tmp, *iterator;
  int exist = 0;

  if (olsr_cnf->ip_version == AF_INET6)		//mdns plugin is running in ipv4, discard ipv6
    return 0;

  ROUTER_ELECTION_ENTRIES(tmp, iterator) {
    if((tmp->network_id == listEntry->network_id) &&
		(memcmp(&(listEntry->router_id), &(tmp->router_id), sizeof(struct in_addr)) == 0)){
      exist = 1;
      tmp->ttl = listEntry->ttl;
    }
  }
    if (exist == 0)
      listbackport_add_tail(&ListOfRouter, &(listEntry->list));
  return 0;
}

int UpdateRouterList6 (struct RouterListEntry6 *listEntry6){

  struct RouterListEntry6 *tmp, *iterator;
  int exist = 0;

  if (olsr_cnf->ip_version == AF_INET)		//mdns plugin is running in ipv6, discard ipv4
    return 0;
 
  ROUTER_ELECTION_ENTRIES(tmp, iterator) { 
    if((tmp->network_id == listEntry6->network_id) &&
              (memcmp(&listEntry6->router_id, &(tmp->router_id), sizeof(struct in6_addr))) == 0){
      exist = 1;
      tmp->ttl = listEntry6->ttl;
    }
  }
    if (exist == 0)
      listbackport_add_tail(&ListOfRouter, &(listEntry6->list));
  return 0;
}

void helloTimer (void *foo __attribute__ ((unused))){

  struct TBmfInterface *walker;
  struct RtElHelloPkt *hello;
  struct sockaddr_in dest;
  char hd[] = "$REP";
  OLSR_PRINTF(0,"hello start \n");

  for (walker = BmfInterfaces; walker != NULL; walker = walker->next) {
    if (olsr_cnf->ip_version == AF_INET) {
      memset((char *) &dest, 0, sizeof(dest));
      dest.sin_family = AF_INET;
      dest.sin_addr.s_addr = inet_addr("224.0.0.2");
      dest.sin_port = htons(5354);

      OLSR_PRINTF(0,"hello running \n");

      hello = (struct RtElHelloPkt *) malloc(sizeof(struct RtElHelloPkt));
      OLSR_PRINTF(0,"hello running step 1\n");
      strcpy(hello->head, hd);
      hello->ipFamily = AF_INET;
      hello->network_id = NETWORK_ID;
      OLSR_PRINTF(0,"hello running step 2\n");
      memcpy(&hello->router_id, &ROUTER_ID, sizeof(union olsr_ip_addr));
      OLSR_PRINTF(0,"%i \n", sendto(walker->helloSkfd, (const char * ) hello, 
			sizeof(struct RtElHelloPkt), 0, (struct sockaddr *)&dest, sizeof(dest)));
      free(hello);
    }
    else{
  
    }
  }
  return;
}

void electTimer (void *foo __attribute__ ((unused))){

  struct RouterListEntry *tmp, *iterator;
  struct RouterListEntry6 *tmp6, *iterator6;

  OLSR_PRINTF(0,"elect start \n");

  if (listbackport_is_empty(&ListOfRouter)){
    ISMASTER = 1;
    OLSR_PRINTF(0,"elect empty \n");
    return;
  }

  ISMASTER = 1;
  if (olsr_cnf->ip_version == AF_INET) {
    ROUTER_ELECTION_ENTRIES(tmp, iterator){
      if(NETWORK_ID == tmp->network_id)
        if(memcmp(&tmp->router_id, &ROUTER_ID.v4, sizeof(struct in_addr)) < 0)
          ISMASTER = 0;
      tmp->ttl = (tmp->ttl)--;
      if(tmp->ttl <= 0){
        listbackport_remove(tmp);
        free(tmp);
      }
    }
  }
  else{
    ROUTER_ELECTION_ENTRIES(tmp6, iterator6){
      if(NETWORK_ID == tmp6->network_id)
        if(memcmp(&tmp6->router_id, &ROUTER_ID.v6, sizeof(struct in6_addr)) < 0)
          ISMASTER = 0;
      tmp6->ttl = (tmp6->ttl)--;
      if(tmp6->ttl <= 0){
        listbackport_remove(tmp6);
      free(tmp6);
      }
    }
  }

  OLSR_PRINTF(0,"elect finish \n");

  return;
}

void initTimer (void *foo __attribute__ ((unused))){
  listbackport_init_head(&ListOfRouter);

  NETWORK_ID = ((uint8_t) 1);             //Default Network id

  OLSR_PRINTF(0,"Initialization \n");
  (void) memset (&ROUTER_ID, 0, sizeof(union olsr_ip_addr));
  memcpy(&olsr_cnf->main_addr, &ROUTER_ID, sizeof(union olsr_ip_addr));
  OLSR_PRINTF(0,"Initialization end \n");
  return;
}

int
set_Network_ID(const char *Network_ID, void *data __attribute__ ((unused)), set_plugin_parameter_addon addon __attribute__ ((unused)))
{
  int temp;
  assert(Network_ID!= NULL);
  set_plugin_int(Network_ID, &temp, addon);
  NETWORK_ID = (uint8_t) temp;
} /* Set Network ID */


int InitRouterList(){

  struct olsr_cookie_info *RouterElectionTimerCookie = NULL;
  struct olsr_cookie_info *HelloTimerCookie = NULL;
  struct olsr_cookie_info *InitCookie = NULL;

  RouterElectionTimerCookie = olsr_alloc_cookie("Router Election", OLSR_COOKIE_TYPE_TIMER);
  HelloTimerCookie = olsr_alloc_cookie("Hello Packet", OLSR_COOKIE_TYPE_TIMER);
  InitCookie = olsr_alloc_cookie("Init", OLSR_COOKIE_TYPE_TIMER);

  olsr_start_timer((unsigned int) INIT_TIMER * MSEC_PER_SEC, 0, OLSR_TIMER_ONESHOT, initTimer, NULL,
		   InitCookie);
  olsr_start_timer((unsigned int) HELLO_TIMER * MSEC_PER_SEC, 0, OLSR_TIMER_PERIODIC, helloTimer, NULL,
		   HelloTimerCookie);
  olsr_start_timer((unsigned int) ELECTION_TIMER * MSEC_PER_SEC, 0, OLSR_TIMER_PERIODIC, electTimer, NULL,
                   RouterElectionTimerCookie);

  return 0;
}
