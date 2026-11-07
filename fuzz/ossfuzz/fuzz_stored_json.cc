// Exercise the production stored-metadata parser and its serialization bound.
#include "../../stored_json.h"
#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const auto parsed = kmap_stored_json_array(std::string(reinterpret_cast<const char *>(data), size));
  if (parsed.is_discarded()) return 0;
  if (!parsed.is_array()) std::abort();
  const std::string canonical = parsed.dump();
  const auto roundtrip = kmap_stored_json_array(canonical);
  if (roundtrip != parsed || kmap_stored_cve_ids(roundtrip) != kmap_stored_cve_ids(parsed))
    std::abort();
  return 0;
}
