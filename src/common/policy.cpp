#include "src/common/policy.h"

#include <algorithm>
#include <cstring>

namespace sacre {
namespace policy {

namespace {

constexpr uint32_t kMagic = 0x53435200;  // "SCR\0"
constexpr uint32_t kVersion = 1;

enum class Tag : uint16_t {
  kNamespaces = 1,
  kSeccomp = 2,
};

std::string_view Trim(std::string_view s) {
  auto start = s.find_first_not_of(" \t\r\n");
  if (start == std::string_view::npos) return "";
  auto end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

}  // namespace

Result<Policy> ParseIni(std::string_view ini_content) {
  Policy policy;
  std::string_view current_section = "";

  size_t pos = 0;
  while (pos < ini_content.size()) {
    size_t next_line = ini_content.find('\n', pos);
    std::string_view line = Trim(ini_content.substr(pos, next_line - pos));
    pos = (next_line == std::string_view::npos) ? ini_content.size() : next_line + 1;

    if (line.empty() || line[0] == '#' || line[0] == ';') continue;

    if (line[0] == '[' && line.back() == ']') {
      current_section = line.substr(1, line.size() - 2);
      continue;
    }

    auto eq_pos = line.find('=');
    if (eq_pos == std::string_view::npos) continue;

    std::string_view key = Trim(line.substr(0, eq_pos));
    std::string_view value = Trim(line.substr(eq_pos + 1));

    if (current_section == "namespaces") {
      bool enabled = (value == "true" || value == "1" || value == "yes");
      if (enabled) {
        if (key == "pid") {
          policy.namespaces |= static_cast<uint32_t>(NamespaceType::kPid);
        } else if (key == "net") {
          policy.namespaces |= static_cast<uint32_t>(NamespaceType::kNet);
        } else if (key == "mount") {
          policy.namespaces |= static_cast<uint32_t>(NamespaceType::kMount);
        } else if (key == "ipc") {
          policy.namespaces |= static_cast<uint32_t>(NamespaceType::kIpc);
        } else if (key == "user") {
          policy.namespaces |= static_cast<uint32_t>(NamespaceType::kUser);
        } else if (key == "uts") {
          policy.namespaces |= static_cast<uint32_t>(NamespaceType::kUts);
        }
      }
    } else if (current_section == "seccomp") {
      if (key == "allow") {
        size_t s_pos = 0;
        while (s_pos < value.size()) {
          size_t next_comma = value.find(',', s_pos);
          std::string_view syscall =
              Trim(value.substr(s_pos, next_comma - s_pos));
          if (!syscall.empty()) {
            policy.allowed_syscalls.emplace_back(syscall);
          }
          if (next_comma == std::string_view::npos) break;
          s_pos = next_comma + 1;
        }
      }
    }
  }

  return Result<Policy>::Success(std::move(policy));
}

Result<std::vector<uint8_t>> Serialize(const Policy& policy) {
  std::vector<uint8_t> buffer;

  // Header
  auto push_u32 = [&](uint32_t val) {
    uint8_t bytes[4];
    std::memcpy(bytes, &val, 4);
    buffer.insert(buffer.end(), bytes, bytes + 4);
  };

  auto push_u16 = [&](uint16_t val) {
    uint8_t bytes[2];
    std::memcpy(bytes, &val, 2);
    buffer.insert(buffer.end(), bytes, bytes + 2);
  };

  push_u32(kMagic);
  push_u32(kVersion);

  uint32_t entry_count = 0;
  if (policy.namespaces != 0) entry_count++;
  if (!policy.allowed_syscalls.empty()) entry_count++;

  push_u32(entry_count);

  // Entry: Namespaces
  if (policy.namespaces != 0) {
    push_u16(static_cast<uint16_t>(Tag::kNamespaces));
    push_u16(4);
    push_u32(policy.namespaces);
  }

  // Entry: Seccomp
  if (!policy.allowed_syscalls.empty()) {
    push_u16(static_cast<uint16_t>(Tag::kSeccomp));

    // Calculate length
    uint32_t seccomp_len = 4;  // for the count
    for (const auto& s : policy.allowed_syscalls) {
      seccomp_len += s.size() + 1;
    }

    if (seccomp_len > 0xFFFF) {
      return Result<std::vector<uint8_t>>::Failure("Seccomp policy too large");
    }

    push_u16(static_cast<uint16_t>(seccomp_len));
    push_u32(static_cast<uint32_t>(policy.allowed_syscalls.size()));
    for (const auto& s : policy.allowed_syscalls) {
      buffer.insert(buffer.end(), s.begin(), s.end());
      buffer.push_back('\0');
    }
  }

  return Result<std::vector<uint8_t>>::Success(std::move(buffer));
}

Result<Policy> Deserialize(const uint8_t* buffer, size_t size) {
  if (size < 12) return Result<Policy>::Failure("Buffer too small for header");

  auto read_u32 = [&](size_t offset) {
    uint32_t val;
    std::memcpy(&val, buffer + offset, 4);
    return val;
  };

  auto read_u16 = [&](size_t offset) {
    uint16_t val;
    std::memcpy(&val, buffer + offset, 2);
    return val;
  };

  if (read_u32(0) != kMagic) {
    return Result<Policy>::Failure("Invalid magic");
  }

  if (read_u32(4) != kVersion) {
    return Result<Policy>::Failure("Unsupported version");
  }

  uint32_t entry_count = read_u32(8);
  size_t offset = 12;

  Policy policy;
  for (uint32_t i = 0; i < entry_count; ++i) {
    if (offset + 4 > size) return Result<Policy>::Failure("Unexpected EOF");

    uint16_t tag = read_u16(offset);
    uint16_t len = read_u16(offset + 2);
    offset += 4;

    if (offset + len > size) return Result<Policy>::Failure("Entry length exceeds buffer");

    if (tag == static_cast<uint16_t>(Tag::kNamespaces)) {
      if (len != 4) return Result<Policy>::Failure("Invalid namespace entry length");
      policy.namespaces = read_u32(offset);
    } else if (tag == static_cast<uint16_t>(Tag::kSeccomp)) {
      if (len < 4) return Result<Policy>::Failure("Invalid seccomp entry length");
      uint32_t count = read_u32(offset);
      size_t s_offset = offset + 4;
      for (uint32_t j = 0; j < count; ++j) {
        if (s_offset >= offset + len) return Result<Policy>::Failure("Seccomp count mismatch");
        const char* s = reinterpret_cast<const char*>(buffer + s_offset);
        size_t s_len = std::strlen(s);
        policy.allowed_syscalls.emplace_back(s, s_len);
        s_offset += s_len + 1;
      }
    }
    offset += len;
  }

  return Result<Policy>::Success(std::move(policy));
}

}  // namespace policy
}  // namespace sacre
