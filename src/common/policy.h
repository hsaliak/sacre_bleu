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

struct Policy {
  std::vector<std::string> allowed_syscalls;
  std::vector<std::string> ro_paths;
  std::vector<std::string> rw_paths;
};

// Parses an INI string into a Policy object.
Result<Policy> ParseIni(std::string_view ini_content);

// Serializes a Policy object into a binary blob.
Result<std::vector<uint8_t>> Serialize(const Policy& policy);

// Deserializes a binary blob into a Policy object.
Result<Policy> Deserialize(const uint8_t* buffer, size_t size);

// Returns the list of critical syscalls that are always allowed by the loader.
const std::vector<std::string>& GetCriticalSyscalls();

} // namespace sacre::policy


#endif  // SACRE_COMMON_POLICY_H_
