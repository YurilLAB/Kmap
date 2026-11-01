#include "../string_pool.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

/* Interning must return the stored copy for a string seen before, whatever
   other lengths and prefixes the pool already holds. */
int main() {
  /* A length-only ordering bug made "ba" unreachable after "aba". */
  std::vector<std::string> words = {"ab", "ba", "aba"};
  for (int len = 2; len <= 4; len++) {
    int total = 1;
    for (int i = 0; i < len; i++)
      total *= 3;
    for (int n = 0; n < total; n++) {
      std::string word;
      for (int i = 0, v = n; i < len; i++, v /= 3)
        word.push_back((char) ('a' + v % 3));
      words.push_back(word);
    }
  }

  std::vector<const char *> first;
  for (const std::string &word : words)
    first.push_back(string_pool_insert(word.c_str()));

  int failures = 0;
  for (size_t i = 0; i < words.size(); i++) {
    const char *again = string_pool_insert(words[i].c_str());
    if (strcmp(again, words[i].c_str()) != 0 || again != first[i]) {
      std::fprintf(stderr, "FAIL: %s was not deduplicated\n", words[i].c_str());
      failures++;
    }
  }
  if (failures) {
    std::fprintf(stderr, "string_pool_test: %d of %zu re-inserts duplicated\n",
                 failures, words.size());
    return 1;
  }
  std::printf("string_pool_test: %zu strings deduplicated\n", words.size());
  return 0;
}
