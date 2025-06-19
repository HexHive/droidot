//===- FuzzedDataProvider.h - Utility header for fuzz targets ---*- C++ -* ===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// A single header library providing an utility class to break up an array of
// bytes. Whenever run on the same input, provides the same output, as long as
// its methods are called in the same order, with the same arguments.
//===----------------------------------------------------------------------===//

#ifndef LLVM_FUZZER_FUZZED_DATA_PROVIDER_H_
#define LLVM_FUZZER_FUZZED_DATA_PROVIDER_H_

#include <algorithm>
#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

// In addition to the comments below, the API is also briefly documented at
// https://github.com/google/fuzzing/blob/master/docs/split-inputs.md#fuzzed-data-provider
class FuzzedDataProvider {
 public:
  // |data| is an array of length |size| that the FuzzedDataProvider wraps to
  // provide more granular access. |data| must outlive the FuzzedDataProvider.
  FuzzedDataProvider(const uint8_t *data, size_t size)
      : data_ptr_(data), remaining_bytes_(size) {}
  ~FuzzedDataProvider() = default;

  // See the implementation below (after the class definition) for more verbose
  // comments for each of the methods.

  // Methods returning std::vector of bytes. These are the most popular choice
  // when splitting fuzzing input into pieces, as every piece is put into a
  // separate buffer (i.e. ASan would catch any under-/overflow) and the memory
  // will be released automatically.
  template <typename T> std::vector<T> ConsumeBytes(size_t num_bytes);
  template <typename T>
  std::vector<T> ConsumeBytesWithTerminator(size_t num_bytes, T terminator = 0);
  template <typename T> std::vector<T> ConsumeRemainingBytes();

  // Methods returning strings. Use only when you need a std::string or a null
  // terminated C-string. Otherwise, prefer the methods returning std::vector.
  std::string ConsumeBytesAsString(size_t num_bytes);
  std::string ConsumeRandomLengthString(size_t max_length);
  std::string ConsumeRandomLengthString();
  std::string ConsumeRemainingBytesAsString();

  // Methods returning integer values.
  template <typename T> T ConsumeIntegral();
  template <typename T> T ConsumeIntegralInRange(T min, T max);

  // Methods returning floating point values.
  template <typename T> T ConsumeFloatingPoint();
  template <typename T> T ConsumeFloatingPointInRange(T min, T max);

  // 0 <= return value <= 1.
  template <typename T> T ConsumeProbability();

  bool ConsumeBool();

  // Returns a value chosen from the given enum.
  template <typename T> T ConsumeEnum();

  // Returns a value from the given array.
  template <typename T, size_t size> T PickValueInArray(const T (&array)[size]);
  template <typename T, size_t size>
  T PickValueInArray(const std::array<T, size> &array);
  template <typename T> T PickValueInArray(std::initializer_list<const T> list);

  // Writes data to the given destination and returns number of bytes written.
  size_t ConsumeData(void *destination, size_t num_bytes);

  // Reports the remaining bytes available for fuzzed input.
  size_t remaining_bytes() { return remaining_bytes_; }

 private:
  FuzzedDataProvider(const FuzzedDataProvider &) = delete;
  FuzzedDataProvider &operator=(const FuzzedDataProvider &) = delete;

  void CopyAndAdvance(void *destination, size_t num_bytes);

  void Advance(size_t num_bytes);

  template <typename T>
  std::vector<T> ConsumeBytes(size_t size, size_t num_bytes);

  template <typename TS, typename TU> TS ConvertUnsignedToSigned(TU value);

  const uint8_t *data_ptr_;
  size_t remaining_bytes_;
};

extern jint consumeBytes2Jint(FuzzedDataProvider* fuzzed_data, int min, int max);
extern jshort consumeBytes2Jshort(FuzzedDataProvider* fuzzed_data, const uint16_t min, const uint16_t max);
extern jboolean consumeBytes2Jboolean(FuzzedDataProvider* fuzzed_data);
extern jbyte consumeBytes2Jbyte(FuzzedDataProvider* fuzzed_data);
extern jchar consumeBytes2Jchar(FuzzedDataProvider* fuzzed_data);
extern jlong consumeBytes2Jlong(FuzzedDataProvider* fuzzed_data, long min, long max);
extern jfloat consumeBytes2Jfloat(FuzzedDataProvider* fuzzed_data);
extern jdouble consumeBytes2Jdouble(FuzzedDataProvider* fuzzed_data);
extern jstring consumeBytes2JstringLV(FuzzedDataProvider* fuzzed_data, JNIEnv* penv, unsigned int size_bytes);
extern jstring consumeBytes2Jstring(FuzzedDataProvider* fuzzed_data, JNIEnv* penv);
extern std::string consumeBytes2StringLV(FuzzedDataProvider* fuzzed_data, unsigned int size_bytes);
extern jbyteArray consumeBytes2JbyteArrayLV(FuzzedDataProvider* fuzzed_data, JNIEnv* penv, unsigned int size_bytes);
extern jbyteArray consumeBytes2JbyteArray(FuzzedDataProvider* fuzzed_data, JNIEnv* penv);
extern jobject consumeBytes2ByteBufferLV(FuzzedDataProvider* fuzzed_data, JNIEnv* penv, unsigned int size_bytes);
extern jobject consumeBytes2ByteBuffer(FuzzedDataProvider* fuzzed_data, JNIEnv* penv);

#endif // LLVM_FUZZER_FUZZED_DATA_PROVIDER_H_
