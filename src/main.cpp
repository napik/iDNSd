#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "inc/mdns.hpp"

using namespace std;

int main() {

  DNS_WORKER *dns = new DNS_WORKER;
  ofstream myfile("log");

  if (myfile.is_open()) {
    myfile << "start" << endl;
  }

  myfile.close();
}
