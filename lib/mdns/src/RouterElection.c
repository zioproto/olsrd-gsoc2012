#include "RouterElection.h"
#include <sys/socket.h>

int ENTRYTTL = 120;

int ParseElectionPacket (struct RtElHelloPkt *rcvPkt, struct RouterListEntry *listEntry){

 (void) memset (&listEntry, 0, sizeof(struct RouterListEntry));
 if(inet_pton( AF_INET, &rcvPkt->router_id, &listEntry->router_id) && 
			inet_pton( AF_INET, &rcvPkt->network_id, &listEntry->network_id)){
    listEntry->ttl = ENTRYTTL;
    return 1;
 }
 else
   return 0;			//if packet is not valid return 0
}

int ParseElectionPacket6 (struct RtElHelloPkt *rcvPkt, struct RouterListEntry6 *listEntry6){

  (void) memset (&listEntry6, 0, sizeof(struct RouterListEntry6));
  if(inet_pton( AF_INET6, &rcvPkt->router_id, &listEntry6->router_id) && 
                         inet_pton( AF_INET6, &rcvPkt->network_id, &listEntry6->network_id)){
    listEntry6->ttl = ENTRYTTL;
    return 1;
  }
  else
    return 0;                    //if packet is not valid return 0
}
