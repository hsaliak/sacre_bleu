#include <iostream>
#include "src/inject/injector.h"

int main(int argc, char* argv[]) {
  auto args_result = sacre::inject::ParseArgs(argc, argv);
  if (!args_result.success) {
    std::cerr << "Error: " << args_result.error_message << std::endl;
    std::cerr << "Usage: sacre-inject <policy.ini> <target_binary>" << std::endl;
    return 1;
  }

  const auto& args = args_result.value;
  if (args.show_help) {
    std::cout << "Usage: sacre-inject <policy.ini> <target_binary>" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -h, --help    Show this help message" << std::endl;
    return 0;
  }

  auto run_result = sacre::inject::RunInjection(args);
  if (!run_result.success) {
    std::cerr << "Error: " << run_result.error_message << std::endl;
    return 1;
  }

  std::cout << "Successfully injected policy into " << args.target_path << std::endl;
  return 0;
}
