#ifndef SACRE_COMMON_FILE_CLOSER_H_
#define SACRE_COMMON_FILE_CLOSER_H_

#include <unistd.h>

namespace sacre {

// RAII wrapper for file descriptors.
class FileCloser {
 public:
  explicit FileCloser(int fd) : fd_(fd) {}
  ~FileCloser() {
    if (fd_ >= 0) {
      close(fd_);
    }
  }

  // Disable copy
  FileCloser(const FileCloser&) = delete;
  FileCloser& operator=(const FileCloser&) = delete;

  // Enable move
  FileCloser(FileCloser&& other) noexcept : fd_(other.fd_) {
    other.fd_ = -1;
  }
  FileCloser& operator=(FileCloser&& other) noexcept {
    if (this != &other) {
      if (fd_ >= 0) {
        close(fd_);
      }
      fd_ = other.fd_;
      other.fd_ = -1;
    }
    return *this;
  }

  [[nodiscard]] int get() const { return fd_; }
  
  void release() {
    fd_ = -1;
  }

  [[nodiscard]] bool is_valid() const { return fd_ >= 0; }

 private:
  int fd_;
};

}  // namespace sacre

#endif  // SACRE_COMMON_FILE_CLOSER_H_
