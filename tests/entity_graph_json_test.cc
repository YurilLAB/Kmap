/* Strict JSON/UTF-8 oracle against the actual entity graph emitter. Offline. */
#include "../entity_graph.h"
#include "../third-party/nlohmann/json.hpp"
#include <filesystem>
#include <random>
#include <set>
#include <string>

struct OutputFile {
  std::filesystem::path directory;
  FILE *file = nullptr;
  OutputFile() {
    std::random_device random;
    for (int i = 0; i < 20; ++i) {
      auto candidate = std::filesystem::temp_directory_path() /
          ("kmap-graph-json-" + std::to_string(random()));
      if (std::filesystem::create_directory(candidate)) {
        directory = candidate;
        file = std::fopen((directory / "graph.json").string().c_str(), "w+b");
        return;
      }
    }
  }
  ~OutputFile() {
    if (file) std::fclose(file);
    if (!directory.empty()) {
      std::error_code error;
      std::filesystem::remove(directory / "graph.json", error);
      std::filesystem::remove(directory, error);
    }
  }
};

int main() {
  OutputFile output;
  if (!output.file) { std::fprintf(stderr, "cannot open graph fixture\n"); return 2; }
  const std::string invalid = std::string("bad") + char(0xff) + "value\n\"";
  const std::string repaired = "bad\xef\xbf\xbdvalue\n\"";
  const std::string other_invalid = std::string("bad") + char(0xfe) + "value\n\"";
  const std::string valid = "caf\xc3\xa9";
  std::map<std::string, EgNode> nodes{
      {"ip:192.0.2.1", {"ip", "192.0.2.1"}},
      {"domain:" + invalid, {"domain", invalid}},
      {"domain:" + other_invalid, {"domain", other_invalid}},
      {"domain:" + repaired, {"domain", repaired}},
      {"bytes:646f6d61696e3a626164ff76616c75650a22", {"domain", "reserved prefix"}},
      {"domain:valid", {"domain", valid}}};
  std::vector<EgEdge> edges;
  for (const auto &node : nodes)
    if (node.first != "ip:192.0.2.1") edges.push_back({"ip:192.0.2.1", node.first, "serves"});
  entity_graph_emit(output.file, "json", "192.0.2.1", 0, 0, nodes, edges);
  if (std::fflush(output.file) != 0 || std::fseek(output.file, 0, SEEK_SET) != 0) return 2;
  try {
    auto document = nlohmann::json::parse(output.file);
    if (document["nodes"].size() != nodes.size() || document["edges"].size() != edges.size()) return 1;
    bool found_repaired = false, found_valid = false;
    std::set<std::string> ids, endpoints;
    for (const auto &node : document["nodes"]) {
      ids.insert(node["id"].get<std::string>());
      if (node["id"] == "bytes:646f6d61696e3a626164ff76616c75650a22" && node["label"] == repaired)
        found_repaired = true;
      if (node["id"] == "domain:valid" && node["label"] == valid) found_valid = true;
    }
    for (const auto &edge : document["edges"]) {
      std::string from = edge["from"], to = edge["to"];
      if (!ids.count(from) || !ids.count(to)) return 1;
      endpoints.insert(to);
    }
    if (!found_repaired || !found_valid || ids.size() != nodes.size() || endpoints.size() != edges.size()) return 1;
    std::puts("entity_graph_json_test: strict JSON/UTF-8 parse and labels PASS");
    return 0;
  } catch (const nlohmann::json::exception &error) {
    std::fprintf(stderr, "entity_graph_json_test: %s\n", error.what());
    return 1;
  }
}
