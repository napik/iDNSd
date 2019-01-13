#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <thread>
#include <variant>
#include <vector>

using namespace std;

#define SIZE 512
#define mDNS_MULTICAST_GROUP "224.0.0.251"
#define LISTEN_PORT 5353
#define DNS_PORT 53
#define DNS_HEADER_SIZE 12
#define SIZE_OF_RESP 512

#define CT_HTONS(x) (((x >> 8) & 0x00FF) | ((x << 8) & 0xFF00))
#define CT_HTONL(x)                                                            \
  (((x >> 24) & 0x000000FF) | ((x >> 8) & 0x0000FF00) |                        \
   ((x << 8) & 0x00FF0000) | ((x << 24) & 0xFF000000))

#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)                                                   \
  (byte & 0x80 ? '1' : '0'), (byte & 0x40 ? '1' : '0'),                        \
      (byte & 0x20 ? '1' : '0'), (byte & 0x10 ? '1' : '0'),                    \
      (byte & 0x08 ? '1' : '0'), (byte & 0x04 ? '1' : '0'),                    \
      (byte & 0x02 ? '1' : '0'), (byte & 0x01 ? '1' : '0')

struct rval {
  u_char shift;
  u_char *value;
};

class DNS_WORKER {
public:
  DNS_WORKER();
  ~DNS_WORKER();

  rval *read_name(u_char *buffer);

private:
  // values
  u_char *recv_buffer;
  u_char recv_buffer_size;
  struct DNS *dns;
  std::thread thr_send;
  std::thread thr_recv;
  bool stop_threads;
  // functions
  void send_dns();
  void recv_dns();
  // parse functions
  void parse_answer();
  u_char *read_rdata(u_char *buffer, u_char &len);
  struct RES_RECORD *parse_RR(u_char *q);
  // print function
  void print_rr(struct RES_RECORD *);
  void print_dns_header(struct DNS_HEADER *);
  void print_query(struct QUERY *);
  void print_dns();
};

/*************************************************
 *                  THE HEADER                   *
 *************************************************
 |0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7 |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                      ID                       |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                    QDCOUNT                    |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                    ANCOUNT                    |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                    NSCOUNT                    |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                    ARCOUNT                    |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+*/
//
//// DNS header structure
//
struct DNS_HEADER {
  unsigned short id;         // identification number
  unsigned char rd : 1;      // recursion desired
  unsigned char tc : 1;      // truncated message
  unsigned char aa : 1;      // authoritive answer
  unsigned char opcode : 4;  // purpose of message
  unsigned char qr : 1;      // query/response flag
  unsigned char rcode : 4;   // response code
  unsigned char cd : 1;      // checking disabled
  unsigned char ad : 1;      // authenticated data
  unsigned char z : 1;       // its z! reserved
  unsigned char ra : 1;      // recursion available
  unsigned short q_count;    // number of question entries
  unsigned short ans_count;  // number of answer entries
  unsigned short auth_count; // number of authority entries
  unsigned short add_count;  // number of resource entries
};
//
////  DNS Record Types -- Net Byte Order
//
enum class RR_TYPE : unsigned short {
  A = CT_HTONS(1),
  NS = CT_HTONS(2),
  MD = CT_HTONS(3),
  MF = CT_HTONS(4),
  CNAME = CT_HTONS(5),
  SOA = CT_HTONS(6),
  MB = CT_HTONS(7),
  MG = CT_HTONS(8),
  MR = CT_HTONS(9),
  T_NULL = CT_HTONS(10),
  WKS = CT_HTONS(11),
  PTR = CT_HTONS(12),
  HINFO = CT_HTONS(13),
  MINFO = CT_HTONS(14),
  MX = CT_HTONS(15),
  TEXT = CT_HTONS(16),
  RP = CT_HTONS(17),
  AFSDB = CT_HTONS(18),
  X25 = CT_HTONS(19),
  ISDN = CT_HTONS(20),
  RT = CT_HTONS(21),
  NSAP = CT_HTONS(22),
  NSAPPTR = CT_HTONS(23),
  SIG = CT_HTONS(24),
  KEY = CT_HTONS(25),
  PX = CT_HTONS(26),
  GPOS = CT_HTONS(27),
  AAAA = CT_HTONS(28),
  LOC = CT_HTONS(29),
  NXT = CT_HTONS(30),
  EID = CT_HTONS(31),
  NIMLOC = CT_HTONS(32),
  SRV = CT_HTONS(33),
  ATMA = CT_HTONS(34),
  NAPTR = CT_HTONS(35),
  KX = CT_HTONS(36),
  CERT = CT_HTONS(37),
  A6 = CT_HTONS(38),
  DNAME = CT_HTONS(39),
  SINK = CT_HTONS(40),
  OPT = CT_HTONS(41),
  //
  //  IANA Reserved
  //
  UINFO = CT_HTONS(100),
  UID = CT_HTONS(101),
  GID = CT_HTONS(102),
  UNSPEC = CT_HTONS(103),
  //
  //  Query only types
  //
  TKEY = CT_HTONS(249),
  TSIG = CT_HTONS(250),
  IXFR = CT_HTONS(251),
  AXFR = CT_HTONS(252),
  MAILB = CT_HTONS(253),
  MAILA = CT_HTONS(254),
  ALL = CT_HTONS(255),
  ANY = CT_HTONS(255)
};
//
////
//
#pragma pack(push, 1)
struct R_DATA {
  RR_TYPE type;
  unsigned short _class;
  unsigned int ttl;
  unsigned short data_len;
};
#pragma pack(pop)
//
////
//

struct rr_data_srv {
  uint16_t priority;
  uint16_t weight;
  uint16_t port;
  uint8_t *target; // host
};

struct rr_data_txt {
  uint8_t *txt;
};

struct rr_data_nsec {
  // uint8_t *name;	// same as record

  // NSEC occupies the 47th bit, 5 bytes
  // uint8_t bitmap_len;	// = 5
  uint8_t bitmap[5]; // network order: first byte contains LSB
};

struct rr_data_ptr {
  uint8_t *name; // NULL if entry is to be used
};

struct rr_data_a {
  uint32_t addr;
};

struct rr_data_aaaa {
  struct in6_addr *addr;
};

//
//
struct RES_RECORD {
  unsigned char *name;
  struct R_DATA *resource;
  // RR data
  union data {
    rr_data_nsec NSEC;
    rr_data_srv SRV;
    rr_data_txt TXT;
    rr_data_ptr PTR;
    rr_data_a A;
    rr_data_aaaa AAAA;
  } rdata;
  // unsigned char *rdata;
};
//
////  DNS Query Types
//
enum class Query_TYPE : unsigned short {
  QUERY = CT_HTONS(0),         // Query
  IQUERY = CT_HTONS(1),        // Obsolete: IP to name
  SERVER_STATUS = CT_HTONS(2), // Obsolete: DNS ping
  UNKNOWN = CT_HTONS(3),       // Unknown
  NOTIFY = CT_HTONS(4),        // Notify
  UPDATE = CT_HTONS(5)         // Dynamic Update
};
//
////
//
enum class Query_Class : unsigned short {
  Reserved = CT_HTONS(0), //	[RFC6895]
  Internet = CT_HTONS(1), //(IN)	[RFC1035]
  Unassigned = CT_HTONS(2),
  Chaos = CT_HTONS(3),  //(CH)
  Hesiod = CT_HTONS(4), //(HS)
  // Unassigned			5-253
  QT_NONE = CT_HTONS(254), //	[RFC2136]
  ANY = CT_HTONS(255),     //	[RFC1035]
  // Unassigne	256-65279
  // Reserved for Private Use	65280-65534	[RFC6895]
  // Reserved			65535		[RFC6895]
};
//
////
//
struct QUESTION {
  Query_TYPE qtype;
  Query_Class qclass;
};
//
////
//
struct QUERY {
  unsigned char *name;
  struct QUESTION *question;
};
//
////
//
struct DNS {
  struct DNS_HEADER *header;
  vector<struct QUERY *> queries;
  vector<struct RES_RECORD *> answers;
  vector<struct RES_RECORD *> auths;
  vector<struct RES_RECORD *> additions;
};
