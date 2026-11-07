#include "stored_json.h"
#include <cstdio>
#include <random>

static int failures = 0;
#define CHECK(x) do { if (!(x)) { ++failures; std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); } } while (0)

int main() {
  for (int c = 0; c <= 32; ++c)
    CHECK(kmap_single_line_text("a" + std::string(1, static_cast<char>(c)) + "b") == "a b");
  CHECK(kmap_single_line_text(" \r\nA\t \x1b[31m\x7f B\n ") == "A [31m B");
  CHECK(kmap_single_line_text("\xc3\xa9") == "\xc3\xa9");
  CHECK(kmap_single_line_text("\xc3") == "\xef\xbf\xbd");
  CHECK(kmap_stored_json_array("").is_array());
  CHECK(kmap_stored_json_array(" \n[ ]\t").empty());
  for (const char *bad : {"null", "{}", "true", "3", "[", "[{}] trailing"})
    CHECK(kmap_stored_json_array(bad).is_discarded());
  CHECK(kmap_stored_cve_ids(kmap_stored_json_array(
      "[{\"details\":{\"id\":\"wrong\"}, \"id\" : \"\\u0043VE-1\"},\"{id:wrong}\"]")) ==
      std::vector<std::string>{"CVE-1"});
  for (size_t depth : {size_t(63), size_t(64), size_t(65), size_t(100000)}) {
    const auto parsed = kmap_stored_json_array(std::string(depth, '[') + "0" + std::string(depth, ']'));
    CHECK(parsed.is_array() == (depth <= 64));
    if (parsed.is_array()) CHECK(kmap_stored_json_array(parsed.dump()) == parsed);
  }
  const std::string braces(10000, '{');
  CHECK(kmap_stored_json_array("[\"" + braces + "\"]")[0] == braces);
  CHECK(kmap_stored_json_array("[\"\\\\\\\"[\\\"\"]").is_array());
  std::string invalid = "[\"";
  invalid += static_cast<char>(0xff);
  invalid += "\"]";
  CHECK(kmap_stored_json_array(invalid)[0] == "\xef\xbf\xbd");

  std::mt19937 rng(1337);
  for (int i = 0; i < 10000; ++i) {
    std::string input(rng() % 128, '\0');
    for (char &c : input) c = static_cast<char>(rng());
    const auto parsed = kmap_stored_json_array(input);
    CHECK(parsed.is_discarded() || parsed.is_array());
    if (parsed.is_array()) CHECK(kmap_stored_json_array(parsed.dump()) == parsed);
  }
  std::printf("stored_json_test: %d failures\n", failures);
  return failures != 0;
}
