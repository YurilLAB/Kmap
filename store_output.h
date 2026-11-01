/* Open exports without destroying the SQLite store they read. */
#ifndef KMAP_STORE_OUTPUT_H
#define KMAP_STORE_OUTPUT_H

#include "net_db.h"
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <io.h>
#include <share.h>
#else
#include <unistd.h>
#endif

/* Compare the already-open output descriptor with every store file before
   truncating it. File identity also catches relative paths, links and Windows
   case aliases. Checking the descriptor avoids reopening a different output
   after the check. Concurrent replacement of store paths is not a supported
   export operation; callers must not move the store while exporting it. */
inline FILE *open_store_output(const char *path, const char *data_dir,
                               std::string &error) {
  error.clear();
  if (!path || !data_dir) { error = "invalid output path"; return nullptr; }
  // Reject reserved names before O_CREAT so refusal leaves no empty sidecar.
  std::error_code path_error;
  auto absolute = std::filesystem::absolute(path, path_error);
  if (path_error) { error = path_error.message(); return nullptr; }
  auto destination = std::filesystem::weakly_canonical(absolute, path_error);
  if (path_error) { error = path_error.message(); return nullptr; }
  absolute = std::filesystem::absolute(data_dir, path_error);
  if (path_error) { error = path_error.message(); return nullptr; }
  auto directory = std::filesystem::weakly_canonical(absolute, path_error);
  if (path_error) { error = path_error.message(); return nullptr; }
#ifdef WIN32
  auto name = destination.filename().native();
  // A stream suffix can create its base file; protect every stream belonging
  // to a reserved store name, including the default ::$DATA stream.
  auto stream = name.find(L':');
  if (stream != std::wstring::npos) name.resize(stream);
  // Ordinary Win32 names discard trailing dots/spaces when a file is created.
  // Extended literal paths deliberately retain their distinct spelling.
  if (std::strncmp(path, "\\\\?\\", 4) != 0) {
    while (!name.empty() && (name.back() == L'.' || name.back() == L' ')) name.pop_back();
  }
  destination.replace_filename(name);
#endif
  for (int shard = 0; shard <= NET_SHARD_COUNT; ++shard) {
    char filename[32];
    if (shard < NET_SHARD_COUNT) std::snprintf(filename, sizeof(filename), "shard_%03d.db", shard);
    else std::snprintf(filename, sizeof(filename), "topo.db");
    for (const char *suffix : {"", "-wal", "-shm", "-journal"}) {
      const auto reserved = directory / (std::string(filename) + suffix);
#ifdef WIN32
      const bool same = CompareStringOrdinal(destination.c_str(), -1, reserved.c_str(), -1, TRUE) == CSTR_EQUAL;
#else
      const bool same = destination == reserved;
#endif
      if (same) { error = "output aliases a store file: " + reserved.string(); return nullptr; }
    }
  }
  int fd = -1;
#ifdef WIN32
  if (_sopen_s(&fd, path, _O_WRONLY | _O_CREAT | _O_TEXT,
               _SH_DENYNO, _S_IREAD | _S_IWRITE) != 0) fd = -1;
#else
  fd = open(path, O_WRONLY | O_CREAT, 0666);
#endif
  if (fd < 0) { error = std::strerror(errno); return nullptr; }
  auto close_fd = [&]() {
#ifdef WIN32
    _close(fd);
#else
    close(fd);
#endif
  };
#ifdef WIN32
  HANDLE output_handle = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
  const bool regular = GetFileType(output_handle) == FILE_TYPE_DISK;
  BY_HANDLE_FILE_INFORMATION output_info{};
  if (regular && !GetFileInformationByHandle(output_handle, &output_info)) {
    error = "cannot identify output file"; close_fd(); return nullptr;
  }
#else
  struct stat output_info{};
  if (fstat(fd, &output_info) != 0) {
    error = std::strerror(errno); close_fd(); return nullptr;
  }
  const bool regular = S_ISREG(output_info.st_mode);
#endif
  // Protect all shards, including ones excluded by the current query filter.
  for (int shard = 0; shard <= NET_SHARD_COUNT; ++shard) {
    const std::string base = shard < NET_SHARD_COUNT
        ? net_shard_path(data_dir, shard) : std::string(data_dir) + "/topo.db";
    for (const char *suffix : {"", "-wal", "-shm", "-journal"}) {
      const std::string input = base + suffix;
      bool same = false;
#ifdef WIN32
      HANDLE h = CreateFileA(input.c_str(), FILE_READ_ATTRIBUTES,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
      if (h == INVALID_HANDLE_VALUE) {
        DWORD code = GetLastError();
        if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) continue;
        error = "cannot identify store file: " + input;
        close_fd(); return nullptr;
      }
      BY_HANDLE_FILE_INFORMATION info{};
      bool identified = GetFileInformationByHandle(h, &info) != 0;
      CloseHandle(h);
      if (!identified) {
        error = "cannot identify store file: " + input;
        close_fd(); return nullptr;
      }
      same = regular && output_info.dwVolumeSerialNumber == info.dwVolumeSerialNumber &&
          output_info.nFileIndexHigh == info.nFileIndexHigh &&
          output_info.nFileIndexLow == info.nFileIndexLow;
#else
      struct stat info{};
      if (stat(input.c_str(), &info) != 0) {
        if (errno == ENOENT) continue;
        error = "cannot identify store file: " + input;
        close_fd(); return nullptr;
      }
      same = output_info.st_dev == info.st_dev && output_info.st_ino == info.st_ino;
#endif
      if (same) {
        error = "output aliases a store file: " + input;
        close_fd(); return nullptr;
      }
    }
  }
  // Devices/pipes retain normal stream semantics; only regular files truncate.
#ifdef WIN32
  if (regular && _chsize_s(fd, 0) != 0) {
#else
  if (regular && ftruncate(fd, 0) != 0) {
#endif
    error = "cannot truncate output file"; close_fd(); return nullptr;
  }
#ifdef WIN32
  FILE *out = _fdopen(fd, "w");
#else
  FILE *out = fdopen(fd, "w");
#endif
  if (!out) { error = std::strerror(errno); close_fd(); }
  return out;
}

#endif
