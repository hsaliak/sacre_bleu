#ifndef SACRE_COMMON_RESULT_H_
#define SACRE_COMMON_RESULT_H_

#include <utility>

namespace sacre {

// Simple result type for error handling without exceptions.
template <typename T>
struct Result {
  T value;
  bool success = false;
  const char* error_message = nullptr;

  static Result Success(T val) { return {std::move(val), true, nullptr}; }
  static Result Failure(const char* msg) { return {T(), false, msg}; }
};

}  // namespace sacre

#endif  // SACRE_COMMON_RESULT_H_
