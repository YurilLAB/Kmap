#ifndef KMAP_COLOR_H
#define KMAP_COLOR_H

/*
 * color.h -- Terminal color support for Kmap output.
 *
 * Provides ANSI escape code wrappers with auto-detection via isatty().
 * Controlled by --color=auto|always|never (default: auto).
 * Respects the NO_COLOR environment variable convention.
 */

#include <string>
#include <cstring>
#include <cstdlib>

#ifdef WIN32
# include <io.h>
# include <windows.h>
# define KMAP_STDOUT_FD _fileno(stdout)
# define kmap_isatty _isatty
#else
# include <unistd.h>
# define KMAP_STDOUT_FD STDOUT_FILENO
# define kmap_isatty isatty
#endif

namespace Color {

enum class Mode { NEVER, AUTO, ALWAYS };

namespace detail {
  inline Mode& current_mode() {
    static Mode mode = Mode::AUTO;
    return mode;
  }
}

#ifdef WIN32
namespace detail {
  /* On Windows 10+ ANSI escape codes are only rendered when the console
   * has ENABLE_VIRTUAL_TERMINAL_PROCESSING on the output handle. Older
   * Windows (8.1 and below) will simply ignore the SetConsoleMode call. */
  inline void enable_vt_processing_once() {
    static bool done = false;
    if (done) return;
    done = true;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h == INVALID_HANDLE_VALUE || h == nullptr) return;
    DWORD mode = 0;
    if (!GetConsoleMode(h, &mode)) return;
    SetConsoleMode(h, mode | 0x0004 /* ENABLE_VIRTUAL_TERMINAL_PROCESSING */);
  }
}
#endif

inline void set_mode(Mode m) {
  detail::current_mode() = m;
#ifdef WIN32
  if (m != Mode::NEVER) detail::enable_vt_processing_once();
#endif
}

inline Mode get_mode() {
  return detail::current_mode();
}

inline bool enabled() {
  bool on = false;
  switch (detail::current_mode()) {
    case Mode::ALWAYS: on = true; break;
    case Mode::NEVER:  on = false; break;
    case Mode::AUTO:
      on = (std::getenv("NO_COLOR") == nullptr)
           && (kmap_isatty(KMAP_STDOUT_FD) != 0);
      break;
  }
#ifdef WIN32
  if (on) detail::enable_vt_processing_once();
#endif
  return on;
}

// Wrap a string with an ANSI SGR code if colors are enabled.
inline std::string apply(const char *code, const std::string& s) {
  if (!enabled()) return s;
  return std::string("\033[") + code + "m" + s + "\033[0m";
}

inline std::string green(const std::string& s)  { return apply("32", s); }
inline std::string red(const std::string& s)    { return apply("31", s); }
inline std::string yellow(const std::string& s) { return apply("33", s); }
inline std::string cyan(const std::string& s)   { return apply("36", s); }
inline std::string bold(const std::string& s)   { return apply("1",  s); }
inline std::string bold_cyan(const std::string& s) { return apply("1;36", s); }

// Parse a --color= argument string to a Mode value.
// Returns false if the value is unrecognized.
inline bool parse_mode(const char *arg, Mode& out) {
  if (strcmp(arg, "always") == 0) { out = Mode::ALWAYS; return true; }
  if (strcmp(arg, "never")  == 0) { out = Mode::NEVER;  return true; }
  if (strcmp(arg, "auto")   == 0) { out = Mode::AUTO;   return true; }
  return false;
}

// Post-process a fully formatted port table string (after column padding is
// already applied) and wrap known port-state keywords with color codes.
// Because ANSI codes are invisible to the terminal, column alignment is
// unaffected even though the byte count of the string grows.
inline std::string colorize_port_table(const std::string& table) {
  if (!enabled()) return table;

  // State tokens ordered longest-first so "open|filtered" matches before "open".
  struct StateEntry { const char *word; const char *code; };
  static const StateEntry states[] = {
    {"open|filtered",   "33"},
    {"closed|filtered", "33"},
    {"unfiltered",      "33"},
    {"open",            "32"},
    {"closed",          "31"},
    {"filtered",        "33"},
    {nullptr, nullptr}
  };

  std::string result;
  result.reserve(table.size() + 512);

  size_t i = 0;
  const size_t n = table.size();

  while (i < n) {
    // State words always follow at least one space in the rendered table.
    if (table[i] == ' ' || table[i] == '\t') {
      size_t start = i + 1;
      bool matched = false;
      for (const StateEntry *se = states; se->word; ++se) {
        size_t wlen = strlen(se->word);
        if (start + wlen > n)
          continue;
        if (table.compare(start, wlen, se->word) != 0)
          continue;
        // Ensure the token ends at a word boundary (space, tab, newline, or EOS).
        char after = (start + wlen < n) ? table[start + wlen] : '\n';
        if (after != ' ' && after != '\t' && after != '\n' && after != '\r')
          continue;
        // Emit the leading whitespace, then the colored word.
        result += table[i];
        result += "\033[";
        result += se->code;
        result += 'm';
        result.append(table, start, wlen);
        result += "\033[0m";
        i = start + wlen;
        matched = true;
        break;
      }
      if (matched) continue;
    }
    result += table[i++];
  }
  return result;
}

} // namespace Color

#endif // KMAP_COLOR_H
