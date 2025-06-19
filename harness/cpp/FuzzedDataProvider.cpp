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
#include <jni.h>
#include <unistd.h>

#include "FuzzedDataProvider.h"

// Returns a std::vector containing |num_bytes| of input data. If fewer than
// |num_bytes| of data remain, returns a shorter std::vector containing all
// of the data that's left. Can be used with any byte sized type, such as
// char, unsigned char, uint8_t, etc.
template <typename T>
std::vector<T> FuzzedDataProvider::ConsumeBytes(size_t num_bytes) {
  num_bytes = std::min(num_bytes, remaining_bytes_);
  return ConsumeBytes<T>(num_bytes, num_bytes);
}

// Similar to |ConsumeBytes|, but also appends the terminator value at the end
// of the resulting vector. Useful, when a mutable null-terminated C-string is
// needed, for example. But that is a rare case. Better avoid it, if possible,
// and prefer using |ConsumeBytes| or |ConsumeBytesAsString| methods.
template <typename T>
std::vector<T> FuzzedDataProvider::ConsumeBytesWithTerminator(size_t num_bytes,
                                                              T terminator) {
  num_bytes = std::min(num_bytes, remaining_bytes_);
  std::vector<T> result = ConsumeBytes<T>(num_bytes + 1, num_bytes);
  result.back() = terminator;
  return result;
}

// Returns a std::vector containing all remaining bytes of the input data.
template <typename T>
std::vector<T> FuzzedDataProvider::ConsumeRemainingBytes() {
  return ConsumeBytes<T>(remaining_bytes_);
}

// Returns a std::string containing |num_bytes| of input data. Using this and
// |.c_str()| on the resulting string is the best way to get an immutable
// null-terminated C string. If fewer than |num_bytes| of data remain, returns
// a shorter std::string containing all of the data that's left.
inline std::string FuzzedDataProvider::ConsumeBytesAsString(size_t num_bytes) {
  static_assert(sizeof(std::string::value_type) == sizeof(uint8_t),
                "ConsumeBytesAsString cannot convert the data to a string.");

  num_bytes = std::min(num_bytes, remaining_bytes_);
  std::string result(
      reinterpret_cast<const std::string::value_type *>(data_ptr_), num_bytes);
  Advance(num_bytes);
  return result;
}

// Returns a std::string of length from 0 to |max_length|. When it runs out of
// input data, returns what remains of the input. Designed to be more stable
// with respect to a fuzzer inserting characters than just picking a random
// length and then consuming that many bytes with |ConsumeBytes|.
inline std::string
FuzzedDataProvider::ConsumeRandomLengthString(size_t max_length) {
  // Reads bytes from the start of |data_ptr_|. Maps "\\" to "\", and maps "\"
  // followed by anything else to the end of the string. As a result of this
  // logic, a fuzzer can insert characters into the string, and the string
  // will be lengthened to include those new characters, resulting in a more
  // stable fuzzer than picking the length of a string independently from
  // picking its contents.
  std::string result;

  // Reserve the anticipated capaticity to prevent several reallocations.
  result.reserve(std::min(max_length, remaining_bytes_));
  for (size_t i = 0; i < max_length && remaining_bytes_ != 0; ++i) {
    char next = ConvertUnsignedToSigned<char>(data_ptr_[0]);
    Advance(1);
    if (next == '\\' && remaining_bytes_ != 0) {
      next = ConvertUnsignedToSigned<char>(data_ptr_[0]);
      Advance(1);
      if (next != '\\')
        break;
    }
    result += next;
  }

  result.shrink_to_fit();
  return result;
}

// Returns a std::string of length from 0 to |remaining_bytes_|.
inline std::string FuzzedDataProvider::ConsumeRandomLengthString() {
  return ConsumeRandomLengthString(remaining_bytes_);
}

// Returns a std::string containing all remaining bytes of the input data.
// Prefer using |ConsumeRemainingBytes| unless you actually need a std::string
// object.
inline std::string FuzzedDataProvider::ConsumeRemainingBytesAsString() {
  return ConsumeBytesAsString(remaining_bytes_);
}

// Returns a number in the range [Type's min, Type's max]. The value might
// not be uniformly distributed in the given range. If there's no input data
// left, always returns |min|.
template <typename T> T FuzzedDataProvider::ConsumeIntegral() {
  return ConsumeIntegralInRange(std::numeric_limits<T>::min(),
                                std::numeric_limits<T>::max());
}

// Returns a number in the range [min, max] by consuming bytes from the
// input data. The value might not be uniformly distributed in the given
// range. If there's no input data left, always returns |min|. |min| must
// be less than or equal to |max|.
template <typename T>
T FuzzedDataProvider::ConsumeIntegralInRange(T min, T max) {
  static_assert(std::is_integral<T>::value, "An integral type is required.");
  static_assert(sizeof(T) <= sizeof(uint64_t), "Unsupported integral type.");

  if (min > max)
    abort();

  // Use the biggest type possible to hold the range and the result.
  uint64_t range = static_cast<uint64_t>(max) - min;
  uint64_t result = 0;
  size_t offset = 0;

  while (offset < sizeof(T) * CHAR_BIT && (range >> offset) > 0 &&
         remaining_bytes_ != 0) {
    // Pull bytes off the end of the seed data. Experimentally, this seems to
    // allow the fuzzer to more easily explore the input space. This makes
    // sense, since it works by modifying inputs that caused new code to run,
    // and this data is often used to encode length of data read by
    // |ConsumeBytes|. Separating out read lengths makes it easier modify the
    // contents of the data that is actually read.
    --remaining_bytes_;
    result = (result << CHAR_BIT) | data_ptr_[remaining_bytes_];
    offset += CHAR_BIT;
  }

  // Avoid division by 0, in case |range + 1| results in overflow.
  if (range != std::numeric_limits<decltype(range)>::max())
    result = result % (range + 1);

  return static_cast<T>(min + result);
}

// Returns a floating point value in the range [Type's lowest, Type's max] by
// consuming bytes from the input data. If there's no input data left, always
// returns approximately 0.
template <typename T> T FuzzedDataProvider::ConsumeFloatingPoint() {
  return ConsumeFloatingPointInRange<T>(std::numeric_limits<T>::lowest(),
                                        std::numeric_limits<T>::max());
}

// Returns a floating point value in the given range by consuming bytes from
// the input data. If there's no input data left, returns |min|. Note that
// |min| must be less than or equal to |max|.
template <typename T>
T FuzzedDataProvider::ConsumeFloatingPointInRange(T min, T max) {
  if (min > max)
    abort();

  T range = .0;
  T result = min;
  constexpr T zero(.0);
  if (max > zero && min < zero && max > min + std::numeric_limits<T>::max()) {
    // The diff |max - min| would overflow the given floating point type. Use
    // the half of the diff as the range and consume a bool to decide whether
    // the result is in the first of the second part of the diff.
    range = (max / 2.0) - (min / 2.0);
    if (ConsumeBool()) {
      result += range;
    }
  } else {
    range = max - min;
  }

  return result + range * ConsumeProbability<T>();
}

// Returns a floating point number in the range [0.0, 1.0]. If there's no
// input data left, always returns 0.
template <typename T> T FuzzedDataProvider::ConsumeProbability() {
  static_assert(std::is_floating_point<T>::value,
                "A floating point type is required.");

  // Use different integral types for different floating point types in order
  // to provide better density of the resulting values.
  using IntegralType =
      typename std::conditional<(sizeof(T) <= sizeof(uint32_t)), uint32_t,
                                uint64_t>::type;

  T result = static_cast<T>(ConsumeIntegral<IntegralType>());
  result /= static_cast<T>(std::numeric_limits<IntegralType>::max());
  return result;
}

// Reads one byte and returns a bool, or false when no data remains.
inline bool FuzzedDataProvider::ConsumeBool() {
  return 1 & ConsumeIntegral<uint8_t>();
}

// Returns an enum value. The enum must start at 0 and be contiguous. It must
// also contain |kMaxValue| aliased to its largest (inclusive) value. Such as:
// enum class Foo { SomeValue, OtherValue, kMaxValue = OtherValue };
template <typename T> T FuzzedDataProvider::ConsumeEnum() {
  static_assert(std::is_enum<T>::value, "|T| must be an enum type.");
  return static_cast<T>(
      ConsumeIntegralInRange<uint32_t>(0, static_cast<uint32_t>(T::kMaxValue)));
}

// Returns a copy of the value selected from the given fixed-size |array|.
template <typename T, size_t size>
T FuzzedDataProvider::PickValueInArray(const T (&array)[size]) {
  static_assert(size > 0, "The array must be non empty.");
  return array[ConsumeIntegralInRange<size_t>(0, size - 1)];
}

template <typename T, size_t size>
T FuzzedDataProvider::PickValueInArray(const std::array<T, size> &array) {
  static_assert(size > 0, "The array must be non empty.");
  return array[ConsumeIntegralInRange<size_t>(0, size - 1)];
}

template <typename T>
T FuzzedDataProvider::PickValueInArray(std::initializer_list<const T> list) {
  // TODO(Dor1s): switch to static_assert once C++14 is allowed.
  if (!list.size())
    abort();

  return *(list.begin() + ConsumeIntegralInRange<size_t>(0, list.size() - 1));
}

// Writes |num_bytes| of input data to the given destination pointer. If there
// is not enough data left, writes all remaining bytes. Return value is the
// number of bytes written.
// In general, it's better to avoid using this function, but it may be useful
// in cases when it's necessary to fill a certain buffer or object with
// fuzzing data.
inline size_t FuzzedDataProvider::ConsumeData(void *destination,
                                              size_t num_bytes) {
  num_bytes = std::min(num_bytes, remaining_bytes_);
  CopyAndAdvance(destination, num_bytes);
  return num_bytes;
}

// Private methods.
inline void FuzzedDataProvider::CopyAndAdvance(void *destination,
                                               size_t num_bytes) {
  std::memcpy(destination, data_ptr_, num_bytes);
  Advance(num_bytes);
}

inline void FuzzedDataProvider::Advance(size_t num_bytes) {
  if (num_bytes > remaining_bytes_)
    abort();

  data_ptr_ += num_bytes;
  remaining_bytes_ -= num_bytes;
}

template <typename T>
std::vector<T> FuzzedDataProvider::ConsumeBytes(size_t size, size_t num_bytes) {
  static_assert(sizeof(T) == sizeof(uint8_t), "Incompatible data type.");

  // The point of using the size-based constructor below is to increase the
  // odds of having a vector object with capacity being equal to the length.
  // That part is always implementation specific, but at least both libc++ and
  // libstdc++ allocate the requested number of bytes in that constructor,
  // which seems to be a natural choice for other implementations as well.
  // To increase the odds even more, we also call |shrink_to_fit| below.
  std::vector<T> result(size);
  if (size == 0) {
    if (num_bytes != 0)
      abort();
    return result;
  }

  CopyAndAdvance(result.data(), num_bytes);

  // Even though |shrink_to_fit| is also implementation specific, we expect it
  // to provide an additional assurance in case vector's constructor allocated
  // a buffer which is larger than the actual amount of data we put inside it.
  result.shrink_to_fit();
  return result;
}

template <typename TS, typename TU>
TS FuzzedDataProvider::ConvertUnsignedToSigned(TU value) {
  static_assert(sizeof(TS) == sizeof(TU), "Incompatible data types.");
  static_assert(!std::numeric_limits<TU>::is_signed,
                "Source type must be unsigned.");

  // TODO(Dor1s): change to `if constexpr` once C++17 becomes mainstream.
  if (std::numeric_limits<TS>::is_modulo)
    return static_cast<TS>(value);

  // Avoid using implementation-defined unsigned to signed conversions.
  // To learn more, see https://stackoverflow.com/questions/13150449.
  if (value <= std::numeric_limits<TS>::max()) {
    return static_cast<TS>(value);
  } else {
    constexpr auto TS_min = std::numeric_limits<TS>::min();
    return TS_min + static_cast<TS>(value - TS_min);
  }
}


/*
Piece of code to map uint8_t vectors to int, short, float, double values
*/
template <typename T>
T extract(const std::vector<uint8_t> &v, int pos)
{
  T value;
  std::memcpy(&value, &v[pos], sizeof(T));
  return value;
}

/*
Consume 4 bytes from the input and project these values to the min/max range
*/
jint consumeBytes2Jint(FuzzedDataProvider* fuzzed_data, int min, int max){
    std::vector<uint8_t> int_bytes = fuzzed_data->ConsumeBytes<uint8_t>((size_t)4);
    // check length
    // TODO: allow lower sizes and simply pad out the rest with 0's
    if(int_bytes.size() != 4){
        _exit(-1);
    }
    int int_value = extract<int>(int_bytes, 0);
    return (jint)int_value;
    /*
    // should not happen
    if(min > max){
        exit(1);
    }
    long range = (long)max - min;
    long int_value_modulo = int_value % (range + 1);
    // no negative modulo
    if(int_value_modulo < 0){
        int_value_modulo = int_value_modulo + range;
    }
    return (jint)(int_value_modulo + min);
    */
}

/*
Consume 2 bytes from the input and project these values to the min/max range
*/
jshort consumeBytes2Jshort(FuzzedDataProvider* fuzzed_data, const uint16_t min, const uint16_t max){
    std::vector<uint8_t> short_bytes = fuzzed_data->ConsumeBytes<uint8_t>((size_t)2);
    // check length
    // TODO: allow lower sizes and simply pad out the rest with 0's
    if(short_bytes.size() != 2){
        _exit(1);
    }
    short short_value = extract<short>(short_bytes, 0);
    // TODO: constraints
    return (jshort) short_value;
}

/*
Consume a byte from the input and use the first bit to determine the boolean value
*/
jboolean consumeBytes2Jboolean(FuzzedDataProvider* fuzzed_data){
    std::vector<uint8_t> bool_bytes = fuzzed_data->ConsumeBytes<uint8_t>((size_t)1);
    // check length
    if(bool_bytes.size() != 1){
        _exit(1);
    }
    jboolean bool_value = (jboolean) (bool_bytes[0] & 0x01);
    // TODO: constraints
    return bool_value;
}

/*
Consume a byte from the input and use it to determine the byte value
*/
jbyte consumeBytes2Jbyte(FuzzedDataProvider* fuzzed_data){
    std::vector<uint8_t> bytes = fuzzed_data->ConsumeBytes<uint8_t>((size_t)1);
    // check length
    if(bytes.size() != 1){
        _exit(1);
    }
    jbyte byte_value = (jbyte) bytes[0];
    // TODO: constraints
    return byte_value;
}

/*
Consume a byte from the input and return the corresponding char
*/
jchar consumeBytes2Jchar(FuzzedDataProvider* fuzzed_data){
    std::vector<uint8_t> bytes = fuzzed_data->ConsumeBytes<uint8_t>((size_t)2);
    // check length
    if(bytes.size() != 2){
        _exit(1);
    }
    uint16_t char_value = extract<uint16_t>(bytes, 0);
    // TODO: constraints
    return (jchar) char_value;
}

/*
Consume 8 bytes from the input and return a jlong
*/
jlong consumeBytes2Jlong(FuzzedDataProvider* fuzzed_data, long min, long max){
    std::vector<uint8_t> long_bytes = fuzzed_data->ConsumeBytes<uint8_t>((size_t)8);
    // check length
    // TODO: allow lower sizes and simply pad out the rest with 0's
    if(long_bytes.size() != 8){
        _exit(1);
    }
    long long_value = extract<long>(long_bytes, 0);
    // TODO: constraints
    return (jlong) long_value;
}

/*
Consume 4 bytes from the input and return a jfloat
*/
jfloat consumeBytes2Jfloat(FuzzedDataProvider* fuzzed_data){
    std::vector<uint8_t> float_bytes = fuzzed_data->ConsumeBytes<uint8_t>((size_t)4);
    // check length
    // TODO: allow lower sizes and simply pad out the rest with 0's
    if(float_bytes.size() != 4){
        _exit(1);
    }
    float float_value = extract<float>(float_bytes, 0);
    // TODO: constraints
    return (jfloat) float_value;
}

/*
Consume 8 bytes from the input and return a jdouble
*/
jdouble consumeBytes2Jdouble(FuzzedDataProvider* fuzzed_data){
    std::vector<uint8_t> double_bytes = fuzzed_data->ConsumeBytes<uint8_t>((size_t)8);
    // check length
    // TODO: allow lower sizes and simply pad out the rest with 0's
    if(double_bytes.size() != 8){
        _exit(1);
    }
    double double_value = extract<double>(double_bytes, 0);
    // TODO: constraints
    return (jdouble) double_value;
}

/*
Consume size_bytes bytes to determine the size to be consumed, then consume int(size_bytes) % remaining_bytes bytes
to build the string from that. size_bytes is the number of bytes to be consumed. (up to 4) 
Return the jstring
*/
jstring consumeBytes2JstringLV(FuzzedDataProvider* fuzzed_data,  JNIEnv* penv, unsigned int size_bytes){
    std::vector<uint8_t> len_bytes = fuzzed_data->ConsumeBytes<uint8_t>((size_t) size_bytes);
    // no more bytes remaining exit
    if(len_bytes.size() != size_bytes){
        _exit(1);
    }
    // pad out to ensure correct integer size
    while(len_bytes.size() != 4){
        len_bytes.push_back(0);
    }
    // cast bytes to int and modulo with the remaining number of bytes
    unsigned int str_len = extract<unsigned int>(len_bytes, 0);
    str_len = str_len % (unsigned int)fuzzed_data->remaining_bytes();
    // extract the string
    std::string string_value = fuzzed_data->ConsumeBytesAsString((size_t) str_len);
    return penv->NewStringUTF(string_value.c_str());
}

/*
Consume the remaining bytes as String, return jstring
*/
jstring consumeBytes2Jstring(FuzzedDataProvider* fuzzed_data, JNIEnv* penv){
    std::string string_value = fuzzed_data->ConsumeRemainingBytesAsString();
    return penv->NewStringUTF(string_value.c_str());
}

/*
Consume LV encoded bytes and return a std::string, used for filepath constraints
*/
std::string consumeBytes2StringLV(FuzzedDataProvider* fuzzed_data, unsigned int size_bytes){
    std::vector<uint8_t> len_bytes = fuzzed_data->ConsumeBytes<uint8_t>((size_t) size_bytes);
    // no more bytes remaining exit
    if(len_bytes.size() != size_bytes){
        _exit(1);
    }
    // pad out to ensure correct integer size
    while(len_bytes.size() != 4){
        len_bytes.push_back(0);
    }
    // cast bytes to int and modulo with the remaining number of bytes
    unsigned int str_len = extract<unsigned int>(len_bytes, 0);
    str_len = str_len % (unsigned int)fuzzed_data->remaining_bytes();
    // extract the string
    std::string string_value = fuzzed_data->ConsumeBytesAsString((size_t) str_len);
    return string_value;
}

/*
Consume size_bytes bytes to determine the size to be consumed, then consume int(size_bytes) % remaining_bytes bytes
to build the string from that. size_bytes is the number of bytes to be consumed. (up to 4) 
Return the jbytearray
*/
jbyteArray consumeBytes2JbyteArrayLV(FuzzedDataProvider* fuzzed_data, JNIEnv* penv, unsigned int size_bytes){
    std::vector<uint8_t> len_bytes = fuzzed_data->ConsumeBytes<uint8_t>((size_t) size_bytes);
    // no more bytes remaining exit
    if(len_bytes.size() != size_bytes){
        _exit(1);
    }
    // pad out to ensure correct integer size
    while(len_bytes.size() != 4){
        len_bytes.push_back(0);
    }
    // cast bytes to int and modulo with the remaining number of bytes
    unsigned int bytearray_len = extract<unsigned int>(len_bytes, 0);
    bytearray_len = bytearray_len % (unsigned int)fuzzed_data->remaining_bytes();
    // consume the data from the bytearray
    std::vector<uint8_t> bytes = fuzzed_data->ConsumeBytes<uint8_t>((size_t) bytearray_len);
    // generate the input bytes
    uint8_t* bytes_native = (uint8_t *) calloc(bytes.size(), sizeof(uint8_t));
	memcpy(bytes_native, &bytes[0], bytes.size() * sizeof(uint8_t));
	jbyteArray jinput = penv->NewByteArray(bytes.size());
	penv->SetByteArrayRegion(jinput, 0,  bytes.size(), (jbyte *)bytes_native);
    return jinput;
}

/*
Consume the remaining bytes
*/
jbyteArray consumeBytes2JbyteArray(FuzzedDataProvider* fuzzed_data, JNIEnv* penv){
    // consume the remaining bytes from the input bytes
    std::vector<uint8_t> bytes = fuzzed_data->ConsumeRemainingBytes<uint8_t>();
    // ensure that at least one byte was read
    if(bytes.size() == 0){
        _exit(1);
    }
    // generate the bytearray
    uint8_t* bytes_native = (uint8_t *) calloc(bytes.size(), sizeof(uint8_t));
	memcpy(bytes_native, &bytes[0], bytes.size() * sizeof(uint8_t));
	jbyteArray jinput = penv->NewByteArray(bytes.size());
	penv->SetByteArrayRegion(jinput, 0,  bytes.size(), (jbyte *)bytes_native);
    return jinput;
}

/*
Consume size_bytes bytes to determine the size to be consumed, then consume int(size_bytes) % remaining_bytes bytes
to build the string from that. size_bytes is the number of bytes to be consumed. (up to 4) 
Return the jbytearray
*/
jobject consumeBytes2ByteBufferLV(FuzzedDataProvider* fuzzed_data, JNIEnv* penv, unsigned int size_bytes){
    // extract the L bytes
    std::vector<uint8_t> len_bytes = fuzzed_data->ConsumeBytes<uint8_t>((size_t) size_bytes);
    // no more bytes remaining exit
    if(len_bytes.size() != size_bytes){
        _exit(1);
    }
    // pad out to ensure correct integer size
    while(len_bytes.size() != 4){
        len_bytes.push_back(0);
    }
     // cast bytes to int and modulo with the remaining number of bytes
    unsigned int bytes_len = extract<unsigned int>(len_bytes, 0);
    bytes_len = bytes_len % (unsigned int)fuzzed_data->remaining_bytes();
    // consume the data from the input bytes
    std::vector<uint8_t> bytes = fuzzed_data->ConsumeBytes<uint8_t>((size_t) bytes_len);
    // generate the bytebuffer
    uint8_t* bytes_native = (uint8_t *) calloc(bytes.size(), sizeof(uint8_t));
	memcpy(bytes_native, &bytes[0], bytes.size() * sizeof(uint8_t));
    jobject jinput = penv->NewDirectByteBuffer(bytes_native, bytes.size() * sizeof(uint8_t));
    return jinput;
}

/*
Consume the remaining bytes to a byteBuffer
*/
jobject consumeBytes2ByteBuffer(FuzzedDataProvider* fuzzed_data, JNIEnv* penv){
    // consume the remaining bytes from the input bytes
    std::vector<uint8_t> bytes = fuzzed_data->ConsumeRemainingBytes<uint8_t>();
    // ensure that at least one byte was read
    if(bytes.size() == 0){
        _exit(1);
    }
    // generate the bytebuffer
    uint8_t* bytes_native = (uint8_t *) calloc(bytes.size(), sizeof(uint8_t));
	memcpy(bytes_native, &bytes[0], bytes.size() * sizeof(uint8_t));
    jobject jinput = penv->NewDirectByteBuffer(bytes_native, bytes.size() * sizeof(uint8_t));
    return jinput;
}


