#include "../jarm.h"

#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

/* JARM probes a loopback server that answers each ClientHello with a short
   flight and then holds the connection, as TLS servers do. Every probe must
   finish on its single read, including when socket numbers exceed
   FD_SETSIZE (the enrichment pool holds that many sockets). */
int main() {
  int ls = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (ls < 0 || bind(ls, (sockaddr *) &sa, sizeof sa) != 0 || listen(ls, 16) != 0) {
    std::perror("jarm_probe_test: listen");
    return 1;
  }
  socklen_t len = sizeof sa;
  getsockname(ls, (sockaddr *) &sa, &len);
  const int port = ntohs(sa.sin_port);

  std::thread([ls] {
    for (;;) {
      int c = accept(ls, nullptr, nullptr);
      if (c < 0) return;
      std::thread([c] {
        char buf[4096];
        (void) !recv(c, buf, sizeof buf, 0);
        const unsigned char alert[] = {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28};
        (void) !send(c, alert, sizeof alert, MSG_NOSIGNAL);
        std::this_thread::sleep_for(std::chrono::seconds(5));
        close(c);
      }).detach();
    }
  }).detach();

  std::vector<int> filler;
  rlimit lim{};
  if (getrlimit(RLIMIT_NOFILE, &lim) == 0 && lim.rlim_max >= 1200) {
    lim.rlim_cur = lim.rlim_max;
    setrlimit(RLIMIT_NOFILE, &lim);
    while (filler.size() < 1100) {
      int fd = open("/dev/null", O_RDONLY);
      if (fd < 0) break;
      filler.push_back(fd);
    }
  }

  auto start = std::chrono::steady_clock::now();
  std::string jarm = jarm_fingerprint("127.0.0.1", port, 2000);
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - start).count();

  int failures = 0;
  if (jarm.size() != 62) {
    std::fprintf(stderr, "FAIL: expected a 62-character JARM, got '%s'\n", jarm.c_str());
    failures++;
  }
  if (ms >= 10000) {
    std::fprintf(stderr, "FAIL: ten probes took %lld ms; each must stop after one read\n",
                 (long long) ms);
    failures++;
  }
  if (failures) return 1;
  std::printf("jarm_probe_test: 10 probes in %lld ms with %zu extra fds open\n",
              (long long) ms, filler.size());
  return 0;
}
