#ifndef SACRE_INJECT_INJECTOR_H_
#define SACRE_INJECT_INJECTOR_H_

#include <string>
#include <vector>
#include "src/common/result.h"

namespace sacre {
namespace inject {

struct Args {
  std::string ini_path;
  std::string target_path;
  bool show_help = false;
};

Result<Args> ParseArgs(int argc, char* argv[]);

Result<bool> RunInjection(const Args& args);

}  // namespace inject
}  // namespace sacre

#endif  // SACRE_INJECT_INJECTOR_H_
