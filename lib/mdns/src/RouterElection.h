#include <netinet/in.h>

struct RtElHelloPkt{
  char head[3]; //"$REP"
  int ipFamily;
  char router_id[40];
  char network_id[40];
};

struct RouterListEntry{
  struct in_addr router_id;
  struct in_addr network_id;
  int ttl;
};

struct RouterListEntry6{
  struct in6_addr router_id;
  struct in6_addr network_id;
  int ttl;
};

int ParseElectionPacket (struct RtElHelloPkt *rcvPkt, struct RouterListEntry *listEntry);	//used to parse a received packet into
int ParseElectionPacket6 (struct RtElHelloPkt *rcvPkt, struct RouterListEntry6 *listEntry6);	//a list entry for ipv4/ipv6
