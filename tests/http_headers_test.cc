#include "../http_headers.h"

#include <cstdio>
#include <string>
#include <vector>

static int failures = 0;
static void expect(bool condition, const char *description) {
  if (!condition) {
    std::fprintf(stderr, "FAIL: %s\n", description);
    ++failures;
  }
}

static std::string field(const std::string &response, const char *name) {
  return kmap_http::header_value(response, kmap_http::ascii_lower(response), name);
}

int main() {
  const std::string body =
      "Example headers in a document:\nServer: body-only-fake\r\n"
      "Location: https://example.invalid/body\r\n"
      "Strict-Transport-Security: max-age=31536000\r\n"
      "Allow: DELETE\r\nSet-Cookie: fake=token; Secure; HttpOnly\r\n";
  for (const std::string separator : {"\r\n", "\n"}) {
    const std::string response = "HTTP/1.1 200 OK" + separator +
        "Content-Type: text/plain" + separator + separator + body;
    for (const char *name : {"Server", "Location", "Strict-Transport-Security",
                             "Allow", "Set-Cookie"})
      expect(field(response, name).empty(), "body lines must not become headers");
    expect(kmap_http::cookie_flag_summary(response).empty(),
           "body cookies must not become cookie metadata");
  }

  const std::string response =
      "HTTP/1.1 200 OK\r\nX-Server: wrong\r\nsErVeR:\t nginx/1.2 \t\r\n"
      "Empty:\t \r\nLocation: https://example.invalid/header\r\n\r\n" + body;
  expect(field(response, "server") == "nginx/1.2", "case and optional whitespace");
  expect(field(response, "Location") == "https://example.invalid/header",
         "real header wins over body line");
  expect(field(response, "Empty").empty(), "empty whitespace-only field");
  expect(field("HTTP/1.0 200 OK\nServer: first\nOther: second\r\n", "Server") == "first",
         "LF terminates a field even when a later CR is present");
  expect(field("HTTP/1.0 200 OK\nServer: partial", "Server") == "partial",
         "bounded reads preserve unterminated header values");
  expect(field("HTTP/1.0 200 OK\nX-Server: wrong\n\n", "Server").empty(),
         "field names match whole names");
  expect(field("HTTP/1.0 200 OK\r\n\r\nServer: fake", "Server").empty(),
         "body begins immediately after empty header block");

  const auto cookies = kmap_http::cookie_flag_summary(
      "HTTP/1.1 200 OK\r\n"
      "Set-Cookie: token=samesite=Strict\r\n"
      "Set-Cookie:\t session=secret; Secured-By=proxy;\tSecure; HttpOnly; SameSite= Lax \t\r\n"
      "Set-Cookie: other=secret; NotSameSite=Strict; X-HttpOnly=yes\r\n"
      "Set-Cookie: invalid-cookie\r\n\r\n" + body);
  expect(cookies == std::vector<std::string>{"token", "session (Secure, HttpOnly, SameSite=Lax)",
                                            "other"},
         "cookie attributes require separate tokens and never disclose values");

  for (const std::string separator : {"\r\n", "\n"}) {
    const std::string interim = "HTTP/1.1 100 Continue" + separator + separator +
        "HTTP/1.1 103 Early Hints" + separator +
        "Server: interim" + separator + "Link: </early.css>" + separator +
        "Set-Cookie: interim=token; Secure" + separator + separator;
    const std::string final = "HTTP/1.1 200 OK" + separator +
        "Server: final" + separator + "Strict-Transport-Security: max-age=60" + separator +
        "Set-Cookie: final=token; HttpOnly" + separator + separator + body;
    expect(field(interim + final, "Server") == "final", "final response follows informational blocks");
    expect(field(interim + final, "Strict-Transport-Security") == "max-age=60",
           "final response security headers retained");
    expect(field(interim + final, "Link").empty(), "informational-only fields excluded");
    expect(field(interim + final, "Location").empty(), "final body is excluded after informational blocks");
    expect(kmap_http::cookie_flag_summary(interim + final) ==
               std::vector<std::string>{"final (HttpOnly)"},
           "only final response cookies retained");
    expect(field(interim + "HTTP/1.1 200 OK" + separator + "Server: partial", "Server") == "partial",
           "partial final headers retained after informational blocks");
  }
  expect(field("HTTP/1.1 103 Early Hints\r\nServer: partial", "Server") == "partial",
         "incomplete informational block is retained");
  expect(field("HTTP/1.1 103 Early Hints\r\nServer: early\r\n\r\n", "Server") == "early",
         "complete informational block retained when final response is absent");
  expect(field("HTTP/1.1 101 Switching Protocols\r\nServer: upgrade\r\n\r\n"
               "HTTP/1.1 200 OK\r\nServer: payload\r\n\r\n", "Server") == "upgrade",
         "upgrade payload must not become a final response");

  // Exercise boundary handling over every byte without relying on text-only
  // examples: the known body is inert regardless of bytes inside the body.
  for (int byte = 0; byte < 256; ++byte) {
    std::string prefix(1, static_cast<char>(byte));
    const std::string candidate = "HTTP/1.1 200 OK\r\n\r\n" + prefix + body;
    expect(field(candidate, "Server").empty(), "binary body boundary");
  }
  if (failures) return 1;
  std::puts("http_headers_test: header boundaries, whitespace and cookie attributes PASS");
  return 0;
}
