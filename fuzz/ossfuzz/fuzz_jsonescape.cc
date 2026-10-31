/* Exercise the shipping serializer, including UTF-8 repair. The previous
 * copied escaper predated validation and could pass while production changed.
 * nlohmann's strict parser is an independent JSON/UTF-8 oracle. */
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <string>
#include "../../json_escape.h"
#include "../../third-party/nlohmann/json.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string input(reinterpret_cast<const char *>(data), size);
  std::string escaped = kmap_json_escape(input);
  auto parsed = nlohmann::json::parse("\"" + escaped + "\"", nullptr, false);
  if (parsed.is_discarded() || !parsed.is_string()) std::abort();
  const std::string repaired = kmap_json_repair_utf8(input);
  if (parsed.get<std::string>() != repaired) std::abort();
  if (kmap_json_repair_utf8(repaired) != repaired) std::abort();
  return 0;
}
