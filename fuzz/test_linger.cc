/* Owned loopback fixtures for graceful/abortive close and failure cleanup.
 * Windows: g++ -std=c++17 fuzz/test_linger.cc -lws2_32 -o test_linger.exe
 * POSIX: g++ -std=c++17 fuzz/test_linger.cc -o test_linger
 */
#include <cstdio>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using sock_t = SOCKET;
static constexpr sock_t invalid_socket = INVALID_SOCKET;
static int sk_errno() { return WSAGetLastError(); }
static bool pending(int e) { return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS; }
static bool is_rst(int e) { return e == WSAECONNRESET; }
static bool refused(int e) { return e == WSAECONNREFUSED; }
#define CLOSESOCK ::closesocket
#else
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
using sock_t = int;
static constexpr sock_t invalid_socket = -1;
static int sk_errno() { return errno; }
static bool pending(int e) { return e == EINPROGRESS || e == EWOULDBLOCK; }
static bool is_rst(int e) { return e == ECONNRESET; }
static bool refused(int e) { return e == ECONNREFUSED; }
#define CLOSESOCK ::close
#endif

static int passes = 0, fails = 0, sockets_owned = 0;
#define CHECK(c,m) do { if (c) ++passes; else { \
  std::printf("FAIL: %s\n", m); ++fails; } } while (0)

struct Socket {
  sock_t value;
  explicit Socket(sock_t s) : value(s) { if (valid()) ++sockets_owned; }
  Socket(const Socket &) = delete;
  Socket &operator=(const Socket &) = delete;
  ~Socket() { close(); }
  bool valid() const { return value != invalid_socket; }
  void close() {
    if (valid()) {
      CHECK(CLOSESOCK(value) == 0, "close succeeds");
      value = invalid_socket; --sockets_owned;
    }
  }
};

static bool nonblocking(const Socket &s) {
  if (!s.valid()) return false;
#ifdef _WIN32
  u_long mode = 1;
  return ioctlsocket(s.value, FIONBIO, &mode) == 0;
#else
  if (s.value >= FD_SETSIZE) return false;
  int flags = fcntl(s.value, F_GETFL, 0);
  return flags >= 0 && fcntl(s.value, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

/* All sockets are nonblocking. select bounds every wait, including connect
 * failure (Winsock signals that in exceptfds rather than writefds). */
static int ready(const Socket &s, bool write, int milliseconds = 2000) {
  fd_set set, errors;
  FD_ZERO(&set); FD_ZERO(&errors);
  FD_SET(s.value, &set); FD_SET(s.value, &errors);
  timeval timeout{milliseconds / 1000, (milliseconds % 1000) * 1000};
  return select(static_cast<int>(s.value + 1), write ? nullptr : &set,
                write ? &set : nullptr, write ? &errors : nullptr, &timeout);
}

static bool bind_loopback(const Socket &s, unsigned short &port, bool listening) {
  if (!nonblocking(s)) return false;
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(0x7f000001);
  if (bind(s.value, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0)
    return false;
  if (listening && listen(s.value, 1) != 0) return false;
  socklen_t length = sizeof(address);
  if (getsockname(s.value, reinterpret_cast<sockaddr *>(&address), &length) != 0)
    return false;
  port = ntohs(address.sin_port);
  return port != 0;
}

static bool connect_loopback(const Socket &s, unsigned short port, int &error) {
  error = 0;
  if (!nonblocking(s)) { error = sk_errno(); return false; }
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(0x7f000001);
  address.sin_port = htons(port);
  if (connect(s.value, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0)
    return true;
  error = sk_errno();
  if (!pending(error)) return false;
  int status = ready(s, true);
  if (status <= 0) { error = status == 0 ? -1 : sk_errno(); return false; }
  socklen_t length = sizeof(error);
  if (getsockopt(s.value, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&error), &length) != 0) {
    error = sk_errno(); return false;
  }
  return error == 0;
}

static int run_once(bool abortive) {
  Socket listener(socket(AF_INET, SOCK_STREAM, 0));
  unsigned short port = 0;
  if (!bind_loopback(listener, port, true)) {
    std::fprintf(stderr, "listener setup failed: %d\n", sk_errno()); return -1;
  }
  Socket client(socket(AF_INET, SOCK_STREAM, 0));
  int error;
  if (!connect_loopback(client, port, error)) {
    std::fprintf(stderr, "connect failed: %d\n", error); return -1;
  }
  if (ready(listener, false) != 1) {
    std::fprintf(stderr, "accept readiness failed/timed out\n"); return -1;
  }
  Socket accepted(accept(listener.value, nullptr, nullptr));
  if (!nonblocking(accepted)) {
    std::fprintf(stderr, "accept setup failed: %d\n", sk_errno()); return -1;
  }
  CHECK(ready(accepted, false, 20) == 0, "idle receive readiness times out");
  if (abortive) {
    linger option{1, 0};
    if (setsockopt(client.value, SOL_SOCKET, SO_LINGER,
                   reinterpret_cast<const char *>(&option), sizeof(option)) != 0) {
      std::fprintf(stderr, "SO_LINGER setup failed: %d\n", sk_errno()); return -1;
    }
  }
  client.close();
  if (ready(accepted, false) != 1) {
    std::fprintf(stderr, "receive readiness failed/timed out\n"); return -1;
  }
  char buffer[8];
  int n = recv(accepted.value, buffer, sizeof(buffer), 0);
  error = sk_errno();
  return n == 0 ? 0 : (n < 0 && is_rst(error)) ? 1 : -1;
}

static void connection_refused() {
  Socket reserved(socket(AF_INET, SOCK_STREAM, 0));
  unsigned short port = 0;
  bool bound = bind_loopback(reserved, port, false);
  CHECK(bound, "reserve non-listening loopback endpoint");
  if (!bound) return;
  Socket client(socket(AF_INET, SOCK_STREAM, 0));
  int error = 0;
  bool connected = connect_loopback(client, port, error);
  bool expected_failure = refused(error);
#ifdef _WIN32
  /* Winsock can hold SYNs for a bound-but-not-listening socket rather than
     reject them. Our explicit 2-second deadline must cancel that connection.
     Other failures (including access denied by a sandbox) still fail. */
  expected_failure = expected_failure || error == -1;
#endif
  if (connected || !expected_failure)
    std::fprintf(stderr, "unexpected connect result: %d\n", error);
  CHECK(!connected && expected_failure,
        "non-listening endpoint fails within the bounded connect deadline");
}

int main() {
#ifdef _WIN32
  WSADATA data;
  if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
    std::fprintf(stderr, "WSAStartup failed\n"); return 2;
  }
#endif
  for (int run = 0; run < 3; ++run) {
    CHECK(run_once(false) == 0, "graceful close returns FIN");
    CHECK(sockets_owned == 0, "graceful run releases every socket");
    CHECK(run_once(true) == 1, "abortive close returns RST");
    CHECK(sockets_owned == 0, "abortive run releases every socket");
  }
  connection_refused();
  CHECK(sockets_owned == 0, "failed connection releases every socket");
#ifdef _WIN32
  CHECK(WSACleanup() == 0, "WSACleanup succeeds");
#endif
  std::printf("socket lifecycle test: %d passed, %d failed\n", passes, fails);
  return fails ? 1 : 0;
}
