#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "src/common/policy.h"

int main(int argc, char* argv[]) {
  if (argc != 3) {
    std::cerr << "Usage: " << argv[0] << " <policy.ini> <target_binary>"
              << std::endl;
    return 1;
  }

  std::string ini_path = argv[1];
  std::string target_path = argv[2];

  // 1. Read INI
  std::ifstream ini_file(ini_path);
  if (!ini_file.is_open()) {
    std::cerr << "Error: Could not open policy file: " << ini_path << std::endl;
    return 1;
  }
  std::stringstream ss;
  ss << ini_file.rdbuf();
  std::string ini_content = ss.str();

  // 2. Parse INI
  auto parse_result = sacre::policy::ParseIni(ini_content);
  if (!parse_result.success) {
    std::cerr << "Error parsing INI: " << parse_result.error_message
              << std::endl;
    return 1;
  }

  // 3. Serialize to Binary
  auto serialize_result = sacre::policy::Serialize(parse_result.value);
  if (!serialize_result.success) {
    std::cerr << "Error serializing policy: " << serialize_result.error_message
              << std::endl;
    return 1;
  }

  // 4. Write blob to temporary file
  std::string blob_path = "/tmp/sacre_policy.bin";
  std::ofstream blob_file(blob_path, std::ios::binary);
  blob_file.write(reinterpret_cast<const char*>(serialize_result.value.data()),
                  serialize_result.value.size());
  blob_file.close();

  // 5. Call objcopy to inject section
  // Note: We remove the section first if it exists to allow re-injection.
  std::string cmd = "objcopy --remove-section=.sacre_policy " + target_path +
                    " 2>/dev/null; " +
                    "objcopy --add-section .sacre_policy=" + blob_path + " " +
                    target_path;

  int ret = std::system(cmd.c_str());
  if (ret != 0) {
    std::cerr << "Error: objcopy failed with code " << ret << std::endl;
    return 1;
  }

  std::cout << "Successfully injected policy into " << target_path << std::endl;
  return 0;
}
