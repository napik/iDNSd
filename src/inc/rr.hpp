#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <thread>
#include <variant>
#include <vector>

#include "mdns.hpp"

using namespace std;

class DNS_RR {
public:
  DNS_RR(u_char *, u_char *);

  struct RES_RECORD *answer;
  u_char len;

private:
  // values
  u_char *q;
  DNS_WORKER *m_dns_q;
  // functions
  // parse functions
  u_char *read_rdata();
  void parse_RR();
  // print function
  void print_rr(struct RES_RECORD *);
};
