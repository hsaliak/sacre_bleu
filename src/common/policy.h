#ifndef SACRE_COMMON_POLICY_H_
#define SACRE_COMMON_POLICY_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "src/common/result.h"


namespace sacre::policy {

template <typename T>
using Result = sacre::Result<T>;

enum class NamespaceType : uint8_t {
  kNone = 0,
  kPid = 1 << 0,
  kNet = 1 << 1,
  kMount = 1 << 2,
  kIpc = 1 << 3,
  kUser = 1 << 4,
  kUts = 1 << 5,
};

struct Policy {
  uint32_t namespaces = 0;
  std::vector<std::string> allowed_syscalls;
};

// Parses an INI string into a Policy object.
Result<Policy> ParseIni(std::string_view ini_content);

// Serializes a Policy object into a binary blob.
Result<std::vector<uint8_t>> Serialize(const Policy& policy);

// Deserializes a binary blob into a Policy object.
Result<Policy> Deserialize(const uint8_t* buffer, size_t size);

} // namespace sacre::policy


#endif  // SACRE_COMMON_POLICY_H_
