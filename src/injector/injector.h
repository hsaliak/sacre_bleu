#ifndef SACRE_INJECT_INJECTOR_H_
#define SACRE_INJECT_INJECTOR_H_

#include <string>
#include "src/common/result.h"


namespace sacre::inject {

struct Args {
  // Inject mode
  std::string ini_path;
  std::string source_path;
  std::string target_path;

  // Extract mode
  bool extract_mode = false;
  std::string elf_path;
  std::string output_path;

  bool show_help = false;
};

Result<Args> ParseArgs(int argc, char** argv);

Result<bool> RunInjection(const Args& args);

} // namespace sacre::inject


#endif  // SACRE_INJECT_INJECTOR_H_
