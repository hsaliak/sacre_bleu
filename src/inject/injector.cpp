#include "src/inject/injector.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <cstring>
#include <unistd.h>

#include "src/common/policy.h"

namespace sacre {
namespace inject {

Result<Args> ParseArgs(int argc, char* argv[]) {
  Args args;
  std::vector<std::string> positional;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--help" || arg == "-h") {
      args.show_help = true;
      return Result<Args>::Success(args);
    } else if (arg.empty()) {
      continue;
    } else if (arg[0] == '-') {
      return Result<Args>::Failure("Unknown option");
    } else {
      positional.push_back(arg);
    }
  }

  if (positional.size() != 2) {
    return Result<Args>::Failure("Wrong number of arguments");
  }

  args.ini_path = positional[0];
  args.target_path = positional[1];
  return Result<Args>::Success(args);
}

Result<bool> RunInjection(const Args& args) {
  // 1. Read INI
  std::ifstream ini_file(args.ini_path);
  if (!ini_file.is_open()) {
    return Result<bool>::Failure("Could not open policy file");
  }
  std::stringstream ss;
  ss << ini_file.rdbuf();
  std::string ini_content = ss.str();

  // 2. Parse INI
  auto parse_result = sacre::policy::ParseIni(ini_content);
  if (!parse_result.success) {
    return Result<bool>::Failure(parse_result.error_message);
  }

  // 3. Serialize to Binary
  auto serialize_result = sacre::policy::Serialize(parse_result.value);
  if (!serialize_result.success) {
    return Result<bool>::Failure(serialize_result.error_message);
  }

  // 4. Write blob to temporary file
  char blob_path[] = "/tmp/sacre_policyXXXXXX";
  int fd = mkstemp(blob_path);
  if (fd == -1) {
    return Result<bool>::Failure("Failed to create temporary file");
  }
  
  if (write(fd, serialize_result.value.data(), serialize_result.value.size()) != 
      static_cast<ssize_t>(serialize_result.value.size())) {
    close(fd);
    unlink(blob_path);
    return Result<bool>::Failure("Failed to write to temporary file");
  }
  close(fd);

  // 5. Call objcopy to inject section
  // We use a simple system() call but we wrap arguments in quotes to be safer.
  // In a real production tool, we should use fork/execve with an array of arguments.
  std::string cmd = "objcopy --remove-section=.sacre_policy '" + args.target_path +
                    "' 2>/dev/null; " +
                    "objcopy --add-section .sacre_policy=" + blob_path + " '" +
                    args.target_path + "'";

  int ret = std::system(cmd.c_str());
  unlink(blob_path);

  if (ret != 0) {
    return Result<bool>::Failure("objcopy failed");
  }

  return Result<bool>::Success(true);
}

}  // namespace inject
}  // namespace sacre
