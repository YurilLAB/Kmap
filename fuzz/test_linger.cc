/* test_linger.cc -- LIVE proof that SO_LINGER{1,0} produces an abortive RST
 * close (the mechanism that avoids local TIME_WAIT on mass connect-scans),
 * vs a graceful FIN close without it. Loopback only.
 *
 * Build (Win): g++ -O2 -std=gnu++17 test_linger.cc -lws2_32 -o test_linger.exe
 *      (POSIX): g++ -O2 -std=gnu++17 test_linger.cc -o test_linger.exe
 */
#include <cstdio>
#include <cstring>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET sock_t;
static int sk_errno() { return WSAGetLastError(); }
#define IS_RST(e) ((e) == WSAECONNRESET)
#define CLOSESOCK closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
typedef int sock_t;
static int sk_errno() { return errno; }
#define IS_RST(e) ((e) == ECONNRESET)
#define CLOSESOCK close
#endif

static int passes = 0, fails = 0;
#define CHECK(c,m) do{ if(c){passes++;} else {printf("  FAIL: %s\n",m); fails++;} }while(0)

/* Open a loopback listener; return its port via *port. */
static sock_t make_listener(unsigned short *port) {
  sock_t s = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in a{}; a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(0x7f000001); a.sin_port = 0;
  bind(s, (sockaddr*)&a, sizeof(a));
  listen(s, 16);
  socklen_t al = sizeof(a);
  getsockname(s, (sockaddr*)&a, &al);
  *port = ntohs(a.sin_port);
  return s;
}

/* Connect to the listener, optionally set SO_LINGER{1,0}, then close.
 * Returns what the SERVER's recv() observed: 0 = graceful FIN, 1 = RST. */
static int run_once(unsigned short port, bool linger) {
  sock_t ls = socket(AF_INET, SOCK_STREAM, 0);
  unsigned short lp; sock_t srv = make_listener(&lp);
  (void)ls; (void)port;
  sockaddr_in sa{}; sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(0x7f000001); sa.sin_port = htons(lp);
  sock_t c = socket(AF_INET, SOCK_STREAM, 0);
  if (connect(c, (sockaddr*)&sa, sizeof(sa)) != 0) { printf("  connect fail\n"); return -1; }
  sock_t a = accept(srv, nullptr, nullptr);
  if (linger) {
    struct linger lg; lg.l_onoff = 1; lg.l_linger = 0;
    setsockopt(c, SOL_SOCKET, SO_LINGER, (const char*)&lg, sizeof(lg));
  }
  CLOSESOCK(c);                       /* graceful FIN, or RST if linger{1,0} */
  char buf[8];
  int n = recv(a, buf, sizeof(buf), 0);
  int e = sk_errno();
  int verdict = (n == 0) ? 0 : (n < 0 && IS_RST(e)) ? 1 : -2;
  CLOSESOCK(a); CLOSESOCK(srv);
  return verdict;
}

int main() {
#ifdef _WIN32
  WSADATA w; WSAStartup(MAKEWORD(2,2), &w);
#endif
  unsigned short port = 0; (void)port;
  int graceful = run_once(0, false);
  CHECK(graceful == 0, "without SO_LINGER: server sees graceful FIN (recv==0)");
  int abortive = run_once(0, true);
  CHECK(abortive == 1, "with SO_LINGER{1,0}: server sees RST (recv ECONNRESET)");
  printf("\n(verdicts: graceful=%d abortive=%d)\n", graceful, abortive);
  printf("SO_LINGER live proof: %d passed, %d failed\n", passes, fails);
#ifdef _WIN32
  WSACleanup();
#endif
  return fails ? 1 : 0;
}
