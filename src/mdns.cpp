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

#include "inc/mdns.hpp"

using namespace std;

DNS_WORKER::DNS_WORKER() {
  stop_threads = false;
  // cout << thread::hardware_concurrency();

  thr_recv = std::thread(&DNS_WORKER::recv_dns, this);
  thr_send = std::thread(&DNS_WORKER::send_dns, this);

  thr_send.join();
  thr_recv.join();
}

DNS_WORKER::~DNS_WORKER() {
  stop_threads = true;
  if (thr_send.joinable())
    thr_send.join();
  if (thr_recv.joinable())
    thr_recv.join();
}

void ChangetoDnsNameFormat(unsigned char *dns, unsigned char *host) {
  u_char lock = 0, i;
  strcat((char *)host, ".");

  for (i = 0; i < strlen((char *)host); i++) {
    if (host[i] == '.') {
      *dns++ = i - lock;
      for (; lock < i; lock++) {
        *dns++ = host[lock];
      }
      lock++; // or lock=i+1;
    }
  }
  *dns++ = '\0';
}

void DNS_WORKER::send_dns() {
  struct DNS_HEADER *dns = NULL;
  struct QUESTION *qinfo = NULL;
  unsigned char buff[65536], *qname;
  u_char host[] = "NB-AARudnitskiy.local";
  int sockfd = -1;
  struct sockaddr_in dest;

  memset(&dest, 0, sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_port = htons(5353);
  dest.sin_addr.s_addr = inet_addr(mDNS_MULTICAST_GROUP);

  // int sockfd = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for
  // DNS queries
  sockfd = socket(AF_INET, SOCK_DGRAM, 0); // UDP packet for DNS queries
  if (sockfd < 0) {
    perror("send socket");
    exit(1);
  }

  dns = (struct DNS_HEADER *)&buff;

  dns->id = (unsigned short)htons(getpid());
  dns->qr = 0;     // This is a query
  dns->opcode = 0; // This is a standard query
  dns->aa = 0;     // Not Authoritative
  dns->tc = 0;     // This message is not truncated
  dns->rd = 1;     // Recursion Desired
  dns->ra = 0;     // Recursion not available! hey we dont have it (lol)
  dns->z = 0;
  dns->ad = 0;
  dns->cd = 0;
  dns->rcode = 0;
  dns->q_count = htons(1); // we have only 1 question
  dns->ans_count = 0;
  dns->auth_count = 0;
  dns->add_count = 0;

  // point to the query portion
  qname = (unsigned char *)&buff[sizeof(struct DNS_HEADER)];

  ChangetoDnsNameFormat(qname, host);
  qinfo =
      (struct QUESTION *)&buff[sizeof(struct DNS_HEADER) +
                               (strlen((const char *)qname) + 1)]; // fill it

  qinfo->qtype = htons(12); // type of the query , A , MX , CNAME , NS etc
  qinfo->qclass = htons(1); // its internet (lol)

  int nbytes = 0;
  while (!stop_threads) {
    nbytes = sendto(sockfd, &buff,
                    sizeof(struct DNS_HEADER) + strlen((const char *)qname) +
                        sizeof(QUESTION) + 1,
                    0, (struct sockaddr *)&dest, sizeof(dest));
    if (nbytes < 0) {
      perror("sendto");
      exit(1);
    }
    std::this_thread::sleep_for(std::chrono::seconds(2));
  }
}

rval *DNS_WORKER::read_name(u_char *buffer, u_char *buff) {
  u_char shift = 0;
  rval *ret = new rval;
  ret->shift = 0;
  string m_qName, m_qName_tmp;
  m_qName.clear();
  m_qName_tmp.clear();

  u_char length = 0;
  bool flag = false;
  length = (u_char)*buffer++;
  ret->shift++;
  u_char i = 0;
  while (length != 0) {
    for (i = 0; i < length; i++) {
      u_char val = (u_char)*buffer++;

      ret->shift++;
      flag = (val == 192);
      if (flag) {
        shift = (u_char)*buffer++;
        ret->shift++;
        break;
      } else {
        m_qName.append(1, val);
      }
    }
    if (!flag) {
      length = (u_char)*buffer++;
      flag = (length == 192);
      ret->shift++;
      if (flag) {
        shift = (u_char)*buffer++;
        ret->shift++;
        break;
      }
      if (length != 0)
        m_qName.append(1, '.');
    } else
      break;
  }

  if (flag) {
    m_qName.append(1, '.');
    length = buff[shift++];
    while (length != 0) {
      while (length != 0) {
        m_qName_tmp.append(1, (u_char)buff[shift++]);
        length--;
      }
      length = buff[shift++];
      if (length != 0)
        m_qName_tmp.append(1, '.');
    }
  }

  m_qName += m_qName_tmp;
  ret->value = (u_char *)strdup(m_qName.c_str());
  return ret;
}

unsigned char *DNS_WORKER::read_rdata(unsigned char *buffer, u_char &len) {
  int shift = 0;
  string m_qName;
  m_qName.clear();
  u_char length = *buffer++;

  while (shift != len) {
    for (int i = 0; i < length; i++) {
      u_char c = *buffer++;
      m_qName.append(1, c);
    }
    shift += length;
    length = *buffer++;
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

struct RES_RECORD *DNS_WORKER::parse_RR(u_char *q, u_char *buff, int size) {
  RES_RECORD *answer = new RES_RECORD;

  rval *ret = read_name(q, buff);
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
    rval *ret = read_name(q, buff);
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
  return answer;
}

void DNS_WORKER::print_rr(struct RES_RECORD *rr) {
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
  default: {
    printf("TYPE: %u \t", static_cast<unsigned short>(rr->resource->type));
    break;
  }
  }
  printf("TTL: %d \n", ntohl(rr->resource->ttl));
}

void DNS_WORKER::print_query(struct QUERY *query) {
  if (ntohs(query->question->qclass) == 1)
    printf("IN");
  else
    printf("%u", ntohs(query->question->qclass));
  switch (ntohs(query->question->qtype)) {
  case 12: {
    printf("\tPTR:\t%s\n", query->name);
    break;
  }
  case 16: {
    printf("\tA:\t%s\n", query->name);
    break;
  }
  default: {
    printf("\tTYPE:%u\t%s\n", ntohs(query->question->qtype), query->name);
    break;
  }
  }
}

void DNS_WORKER::print_dns() {
  if (ntohs(dns->header->q_count) >= 1)
    printf("\n \033[0;32m%d Questions:\033[0m\n", ntohs(dns->header->q_count));
  for (auto &query : dns->queries) {
    print_query(query);
  }

  if (ntohs(dns->header->ans_count) >= 1)
    printf("\n \033[0;32m%d Answers:\033[0m\n", ntohs(dns->header->ans_count));
  for (auto &answer : dns->answers) {
    print_rr(answer);
  }

  if (ntohs(dns->header->auth_count) >= 1)
    printf("\n \033[0;32m%d Authoritative Servers:\033[0m\n",
           ntohs(dns->header->auth_count));
  for (auto &answer : dns->auths) {
    print_rr(answer);
  }

  if (ntohs(dns->header->add_count) >= 1)
    printf("\n \033[0;32m%d Additional records:\033[0m\n",
           ntohs(dns->header->add_count));
  for (auto &answer : dns->additions) {
    print_rr(answer);
  }
}

void DNS_WORKER::parse_answer(unsigned char *q, int size) {
  u_char *buff;
  buff = q;

  dns = new DNS();

  dns->header = (struct DNS_HEADER *)q;
  q += sizeof(struct DNS_HEADER);

  for (int i = 0; i < ntohs(dns->header->q_count); i++) {
    QUERY *query = new QUERY();

    rval *ret = read_name(q, buff);
    query->name = ret->value;
    q += ret->shift;

    //  printf("\n%u\n", shift);

    query->question = (struct QUESTION *)q;
    q += (u_char)sizeof(struct QUESTION);
    // printf("%u\t%u\n", ret->shift, (u_char)sizeof(struct QUESTION));

    dns->queries.push_back(query);
  }

  int len = 0;
  for (int i = 0; i < ntohs(dns->header->ans_count); i++) {
    RES_RECORD *answer = parse_RR(q, buff, len);
    q += len;
    dns->answers.push_back(answer);
  }

  for (int i = 0; i < ntohs(dns->header->auth_count); i++) {
    RES_RECORD *auth = parse_RR(q, buff, len);
    q += len;
    dns->auths.push_back(auth);
  }

  for (int i = 0; i < ntohs(dns->header->add_count); i++) {
    RES_RECORD *addition = parse_RR(q, buff, len);
    q += len;
    dns->additions.push_back(addition);
  }
}

void DNS_WORKER::recv_dns() {
  struct sockaddr_in addr;
  socklen_t addrlen;
  int len = 1024;
  unsigned char *recvData;
  ssize_t result = 0;
  int sockfd = 0;
  const int optval = 1;
  struct ip_mreq mreq;

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    perror("send socket");
    exit(1);
  }
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) <
      0) {
    perror("setsockopt SOL_SOCKET");
    exit(1);
  }

  bzero(&addr, sizeof(struct sockaddr_in));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(LISTEN_PORT);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  bind(sockfd, (sockaddr *)&addr, sizeof(struct sockaddr_in));

  // mreq.imr_multiaddr.s_addr = inet_addr(mIP_ARRESS);
  inet_aton(mDNS_MULTICAST_GROUP, &(mreq.imr_multiaddr));
  mreq.imr_interface.s_addr = htonl(INADDR_ANY);

  if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq,
                 sizeof(struct ip_mreq)) < 0) {
    perror("setsockopt mreq");
    exit(1);
  }

  recvData = (unsigned char *)malloc(len);

  while (!stop_threads) {
    result =
        recvfrom(sockfd, recvData, len, 0, (struct sockaddr *)&addr, &addrlen);
    if (result == SO_ERROR) {
      close(sockfd);
      perror("socket err");
      exit(1);
    }

    printf("\n\033[0;31mResponse from %s:\033[0m\n", inet_ntoa(addr.sin_addr));

    parse_answer(recvData, result);
    print_dns();
  }
}
