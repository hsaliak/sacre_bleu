#include "src/common/policy.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <vector>

namespace sacre::policy {

namespace {
constexpr uint32_t kMagic = 0x00524353; // "SCR\0"
constexpr uint32_t kVersion = 1;

enum class Tag : uint16_t {
  kSeccomp = 2,
  kLandlockRO = 3,
  kLandlockRW = 4,
};

std::string_view Trim(std::string_view str) {
  size_t const first = str.find_first_not_of(" \t\r\n");
  if (first == std::string_view::npos) return "";
  size_t const last = str.find_last_not_of(" \t\r\n");
  return str.substr(first, (last - first + 1));
}



void ParseCommaSeparatedList(std::string_view value, std::vector<std::string>& list) {
  size_t s_pos = 0;
  while (s_pos < value.size()) {
    size_t const next_comma = value.find(',', s_pos);
    std::string_view const item = Trim(value.substr(s_pos, next_comma - s_pos));
    if (!item.empty()) {
      list.emplace_back(item);
    }
    if (next_comma == std::string_view::npos) break;
    s_pos = next_comma + 1;
  }
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void ParseSeccompSection(std::string_view key, std::string_view value, Policy& policy) {
  if (key == "allow") {
    ParseCommaSeparatedList(value, policy.allowed_syscalls);
  }
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void ParseLandlockSection(std::string_view key, std::string_view value, Policy& policy) {
  if (key == "ro") {
    ParseCommaSeparatedList(value, policy.ro_paths);
  } else if (key == "rw") {
    ParseCommaSeparatedList(value, policy.rw_paths);
  }
}
} // namespace

Result<Policy> ParseIni(std::string_view ini_content) {
  Policy policy;
  std::string_view current_section;

  size_t pos = 0;
  while (pos < ini_content.size()) {
    size_t const next_line = ini_content.find('\n', pos);
    std::string_view const line = Trim(ini_content.substr(pos, next_line - pos));
    pos = (next_line == std::string_view::npos) ? ini_content.size() : next_line + 1;

    if (line.empty() || line[0] == '#' || line[0] == ';') continue;

    if (line[0] == '[' && line.back() == ']') {
      current_section = line.substr(1, line.size() - 2);
      continue;
    }

    auto const eq_pos = line.find('=');
    if (eq_pos == std::string_view::npos) continue;

    std::string_view const key = Trim(line.substr(0, eq_pos));
    std::string_view const value = Trim(line.substr(eq_pos + 1));

    if (current_section == "seccomp") {
      ParseSeccompSection(key, value, policy);
    } else if (current_section == "landlock") {
      ParseLandlockSection(key, value, policy);
    }
  }

  return Result<Policy>::Success(std::move(policy));
}

Result<std::vector<uint8_t>> Serialize(const Policy& policy) {
  std::vector<uint8_t> buffer;

  auto push_u32 = [&](uint32_t val) {
    std::array<uint8_t, 4> bytes{};
    std::memcpy(bytes.data(), &val, 4);
    buffer.insert(buffer.end(), bytes.begin(), bytes.end());
  };

  auto push_u16 = [&](uint16_t val) {
    std::array<uint8_t, 2> bytes{};
    std::memcpy(bytes.data(), &val, 2);
    buffer.insert(buffer.end(), bytes.begin(), bytes.end());
  };

  // Header
  push_u32(kMagic);
  push_u32(kVersion);

  auto push_string_list = [&](Tag tag, const std::vector<std::string>& list) -> Result<bool> {
    if (list.empty()) return Result<bool>::Success(true);

    push_u16(static_cast<uint16_t>(tag));

    uint32_t list_len = 4;
    for (const auto& s : list) {
      list_len += static_cast<uint32_t>(s.size() + 1);
    }

    if (list_len > 0xFFFF) {
      return Result<bool>::Failure("Policy entry too large");
    }

    push_u16(static_cast<uint16_t>(list_len));
    push_u32(static_cast<uint32_t>(list.size()));
    for (const auto& s : list) {
      buffer.insert(buffer.end(), s.begin(), s.end());
      buffer.push_back('\0');
    }
    return Result<bool>::Success(true);
  };

  uint32_t entry_count = 0;
  if (!policy.allowed_syscalls.empty()) entry_count++;
  if (!policy.ro_paths.empty()) entry_count++;
  if (!policy.rw_paths.empty()) entry_count++;
  push_u32(entry_count);

  if (auto res = push_string_list(Tag::kSeccomp, policy.allowed_syscalls); !res.success) return Result<std::vector<uint8_t>>::Failure(res.error_message);
  if (auto res = push_string_list(Tag::kLandlockRO, policy.ro_paths); !res.success) return Result<std::vector<uint8_t>>::Failure(res.error_message);
  if (auto res = push_string_list(Tag::kLandlockRW, policy.rw_paths); !res.success) return Result<std::vector<uint8_t>>::Failure(res.error_message);

  return Result<std::vector<uint8_t>>::Success(std::move(buffer));
}

namespace {
uint32_t ReadU32(const uint8_t* buffer, size_t offset) {
  uint32_t val = 0;
  std::memcpy(&val, buffer + offset, 4);
  return val;
}

uint16_t ReadU16(const uint8_t* buffer, size_t offset) {
  uint16_t val = 0;
  std::memcpy(&val, buffer + offset, 2);
  return val;
}

Result<bool> ParseStringListEntry(const uint8_t* buffer, size_t offset, uint16_t len, std::vector<std::string>& list) {
  if (len < 4) return Result<bool>::Failure("Invalid entry length");
  uint32_t const count = ReadU32(buffer, offset);
  size_t s_offset = offset + 4;
  for (uint32_t j = 0; j < count; ++j) {
    if (s_offset >= offset + len) return Result<bool>::Failure("Entry count mismatch");
    const char* const str = reinterpret_cast<const char*>(buffer + s_offset);
    
    // Safety: Ensure null terminator exists within the entry length
    size_t const max_remaining = (offset + len) - s_offset;
    const char* const end = static_cast<const char*>(std::memchr(str, '\0', max_remaining));
    if (end == nullptr) {
      return Result<bool>::Failure("Malformed entry: missing null terminator");
    }
    
    size_t const s_len = end - str;
    list.emplace_back(str, s_len);
    s_offset += s_len + 1;
  }
  return Result<bool>::Success(true);
}
} // namespace

Result<Policy> Deserialize(const uint8_t* buffer, size_t size) {
  constexpr size_t kHeaderSize = 12;
  if (size < kHeaderSize) return Result<Policy>::Failure("Buffer too small for header");

  if (ReadU32(buffer, 0) != kMagic) {
    return Result<Policy>::Failure("Invalid magic");
  }

  if (ReadU32(buffer, 4) != kVersion) {
    return Result<Policy>::Failure("Unsupported version");
  }

  uint32_t const entry_count = ReadU32(buffer, 8);
  Policy policy;

  size_t offset = kHeaderSize;
  for (uint32_t i = 0; i < entry_count; ++i) {
    if (offset + 4 > size) return Result<Policy>::Failure("Unexpected EOF");

    uint16_t const tag = ReadU16(buffer, offset);
    uint16_t const len = ReadU16(buffer, offset + 2);
    offset += 4;

    if (offset + len > size) return Result<Policy>::Failure("Entry length exceeds buffer");

    if (tag == static_cast<uint16_t>(Tag::kSeccomp)) {
      auto res = ParseStringListEntry(buffer, offset, len, policy.allowed_syscalls);
      if (!res.success) return Result<Policy>::Failure(res.error_message);
    } else if (tag == static_cast<uint16_t>(Tag::kLandlockRO)) {
      // TODO(hsaliak): Resolve paths via realpath() to ensure Landlock rules are applied correctly
      // to the actual filesystem entries.
      auto res = ParseStringListEntry(buffer, offset, len, policy.ro_paths);
      if (!res.success) return Result<Policy>::Failure(res.error_message);
    } else if (tag == static_cast<uint16_t>(Tag::kLandlockRW)) {
      // TODO(hsaliak): Resolve paths via realpath()
      auto res = ParseStringListEntry(buffer, offset, len, policy.rw_paths);
      if (!res.success) return Result<Policy>::Failure(res.error_message);
    }
    offset += len;
  }

  return Result<Policy>::Success(std::move(policy));
}

const std::vector<std::string>& GetCriticalSyscalls() {
  static const std::vector<std::string> critical_syscalls = {
      "execve",          "exit_group",      "exit",
      "brk",             "arch_prctl",      "mmap",
      "munmap",          "mprotect",        "fstat",
      "read",            "write",           "close",
      "rt_sigaction",    "rt_sigprocmask",  "rt_sigreturn",
      "newfstatat",      "openat",          "readlink",
      "getpid",          "gettid",          "set_tid_address",
      "set_robust_list", "futex",           "prlimit64",
      "getrandom",       "rseq",            "prctl",
      "pread64",         "access",          "open",
      "stat",            "lstat",           "fstatfs",
      "getdents64",      "ioctl",           "fcntl",
      "writev",          "getuid",          "getgid",
      "geteuid",         "getegid",         "lseek",
      "dup",             "dup2",            "dup3",
      "pipe",            "pipe2",           "execveat"};
  return critical_syscalls;
}

} // namespace sacre::policy
