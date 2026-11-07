#ifndef KMAP_STORED_JSON_H
#define KMAP_STORED_JSON_H

#include "json_escape.h"
#include "third-party/nlohmann/json.hpp"
#include <string>
#include <vector>

// Stored metadata can be legacy or externally written JSON. Check nesting
// before building a tree: a parser callback discards values but cannot stop
// parsing deep input. The limit also bounds recursive serialization later.
inline nlohmann::json kmap_stored_json_array(const std::string &raw) {
  if (raw.empty() || raw == "[]") return nlohmann::json::array();
  size_t depth = 0;
  bool in_string = false, escaped = false;
  for (char c : raw) {
    if (in_string) {
      if (escaped) escaped = false;
      else if (c == '\\') escaped = true;
      else if (c == '"') in_string = false;
    } else if (c == '"') {
      in_string = true;
    } else if (c == '[' || c == '{') {
      if (++depth > 64) return nlohmann::json(nlohmann::json::value_t::discarded);
    } else if ((c == ']' || c == '}') && depth > 0) {
      --depth;
    }
  }
  nlohmann::json value = nlohmann::json::parse(kmap_json_repair_utf8(raw), nullptr, false);
  if (!value.is_array()) return nlohmann::json(nlohmann::json::value_t::discarded);
  return value;
}

inline std::vector<std::string> kmap_stored_cve_ids(const nlohmann::json &array,
                                                 bool *valid = nullptr) {
  std::vector<std::string> ids;
  if (valid) *valid = array.is_array();
  if (!array.is_array()) return ids;
  for (const auto &entry : array) {
    if (!entry.is_object()) {
      if (valid) *valid = false;
      continue;
    }
    const auto id = entry.find("id");
    if (id != entry.end() && id->is_string() && !id->get_ref<const std::string &>().empty())
      ids.push_back(id->get<std::string>());
    else if (valid) *valid = false;
  }
  return ids;
}

#endif
