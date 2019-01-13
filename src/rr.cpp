#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

//#include "inc/mdns.hpp"
#include "inc/rr.hpp"

using namespace std;

void DNS_RR(DNS_WORKER *dns_q, u_char *q) {
  m_dns_q = dns_q;
  q = q;
}

unsigned char *DNS_RR::read_rdata() {
  int shift = 0;
  string m_qName;
  m_qName.clear();
  u_char length = *q++;

  while (shift != len) {
    for (int i = 0; i < length; i++) {
      u_char c = *q++;
      m_qName.append(1, c);
    }
    shift += length;
    length = *q++;
    shift += 1;
    // if (length != 0) { m_qName.append(1,';');
    // m_qName.append(std::to_string(shift)); m_qName.append(1, ' '); };
    if (length != 0)
      m_qName.append(1, ';');
    if (shift >= len)
      break;
  }
  return (u_char *)strdup(m_qName.c_str());
}

void DNS_RR::parse_RR() {
  answer = new RES_RECORD;

  rval *ret = m_dns_q->read_name(q);
  answer->name = ret->value;
  q += ret->shift;

  struct R_DATA *resource = (struct R_DATA *)q;
  answer->resource = resource;
  q += sizeof(struct R_DATA);

  u_char len = ntohs(resource->data_len);
  switch (resource->type) {
  case RR_TYPE::A: {
    if (len >= 16) {
      /*        sprintf(answer->rdata_buffer->A.addr, "%u.%u.%u.%u",
                      data_buffer[buffer_pointer],
         data_buffer[buffer_pointer
         + 1], data_buffer[buffer_pointer + 2], data_buffer[buffer_pointer +
         3]);
      */
    } else {
      answer->rdata.A.addr =
          (u_char)'i' + (u_char)'p' + (u_char)'v' + (u_char)'4';
    }
    q += 4;
    break;
  }
  case RR_TYPE::PTR: {
    rr_data_ptr *PTR = new rr_data_ptr;
    // PTR->name = read_rdata(q, len);
    rval *ret = m_dns_q->read_name(q);
    PTR->name = ret->value;
    answer->rdata.PTR = *PTR;
    q += ret->shift;
    break;
  }
  case RR_TYPE::TEXT: {
    rr_data_txt *TXT = new rr_data_txt;
    TXT->txt = read_rdata(q, len);
    answer->rdata.TXT = *TXT;
    q += len;
    break;
  }
  default: {
    //      answer->rdata = read_rdata(q, len);
    q += len;
    break;
  }
  }
}

void DNS_RR::print_rr(struct RES_RECORD *rr) {
  if (ntohs(rr->resource->_class) == 1)
    printf("IN\t");
  printf("%s\t", rr->name);

  switch (rr->resource->type) {
  case RR_TYPE::PTR: {
    printf("%s: %s \t", "PTR", rr->rdata.PTR.name);
    break;
  }
  case RR_TYPE::TEXT: {
    printf("%s: %s \t", "TXT", rr->rdata.TXT.txt);
    break;
  }
  case RR_TYPE::NS: {
    break;
  }
  case RR_TYPE::MD: {
    break;
  }
  case RR_TYPE::MF: {
    break;
  }
  case RR_TYPE::CNAME: {
    break;
  }
  case RR_TYPE::SOA: {
    break;
  }
  case RR_TYPE::MB: {
    break;
  }
  case RR_TYPE::MG: {
    break;
  }
  case RR_TYPE::MR: {
    break;
  }
  case RR_TYPE::T_NULL: {
    break;
  }
  case RR_TYPE::WKS: {
    break;
  }
  case RR_TYPE::HINFO: {
    break;
  }
  case RR_TYPE::MINFO: {
    break;
  }
  case RR_TYPE::MX: {
    break;
  }
  case RR_TYPE::RP: {
    break;
  }
  case RR_TYPE::AFSDB: {
    break;
  }
  case RR_TYPE::X25: {
    break;
  }
  case RR_TYPE::ISDN: {
    break;
  }
  case RR_TYPE::RT: {
    break;
  }
  case RR_TYPE::NSAP: {
    break;
  }
  case RR_TYPE::NSAPPTR: {
    break;
  }
  case RR_TYPE::SIG: {
    break;
  }
  case RR_TYPE::KEY: {
    break;
  }
  case RR_TYPE::PX: {
    break;
  }
  case RR_TYPE::GPOS: {
    break;
  }
  case RR_TYPE::AAAA: {
    break;
  }
  case RR_TYPE::LOC: {
    break;
  }
  case RR_TYPE::NXT: {
    break;
  }
  case RR_TYPE::EID: {
    break;
  }
  case RR_TYPE::NIMLOC: {
    break;
  }
  case RR_TYPE::SRV: {
    break;
  }
  case RR_TYPE::ATMA: {
    break;
  }
  case RR_TYPE::NAPTR: {
    break;
  }
  case RR_TYPE::KX: {
    break;
  }
  case RR_TYPE::CERT: {
    break;
  }
  case RR_TYPE::A6: {
    break;
  }
  case RR_TYPE::DNAME: {
    break;
  }
  case RR_TYPE::SINK: {
    break;
  }
  case RR_TYPE::OPT: {
    break;
  }
  case RR_TYPE::UINFO: {
    break;
  }
  case RR_TYPE::UID: {
    break;
  }
  case RR_TYPE::GID: {
    break;
  }
  case RR_TYPE::UNSPEC: {
    break;
  }
  case RR_TYPE::TKEY: {
    break;
  }
  case RR_TYPE::TSIG: {
    break;
  }
  case RR_TYPE::IXFR: {
    break;
  }
  case RR_TYPE::AXFR: {
    break;
  }
  case RR_TYPE::MAILB: {
    break;
  }
  case RR_TYPE::MAILA: {
    break;
  }
  case RR_TYPE::ALL: {
    break;
  }
  // case RR_TYPE::ANY: {
  //  break;
  //}
  default: {
    printf("\tTYPE: %u", static_cast<unsigned short>(rr->resource->type));
    break;
  }
  }
  printf("\tTTL: %d \n", ntohl(rr->resource->ttl));
}
