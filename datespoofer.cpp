#include <cstddef>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <vector>
#include <windows.h> // DWORD, BYTE, etc.
#include <winnt.h>   // IMAGE_DOS_HEADER

constexpr int IMAGE_NT_SIGNATURE_ = IMAGE_NT_SIGNATURE;
// cannot get address of macro so i have
// to define a constant with the same value

namespace Status {
constexpr int OK = 0;
constexpr int INVALID_ARGS = 1;
constexpr int WRONG_DATA_FORMAT = 2;
constexpr int FILE_ERROR = 3;
constexpr int NOT_PE_ERROR = 4;
}; // namespace Status

int main(int argc, char **argv) {
  if (argc != 3) {
    fputs("Usage: datespoofer.exe <executable> <date> (e.g. \"5.09.2020 "
          "20:20:31\")\n",
          stderr);
    return Status::INVALID_ARGS;
  }

  const char *filename = argv[1];
  const char *date = argv[2];

  int day, month, year, hour, minute, second;
  if (sscanf(date, "%d.%d.%d %d:%d:%d", &day, &month, &year, &hour, &minute,
             &second) < 0) {
    fputs("Couldn't parse time data\n", stderr);
    return Status::WRONG_DATA_FORMAT;
  }

  tm ttime;
  memset(&ttime, 0, sizeof(tm));
  ttime.tm_sec = second;
  ttime.tm_min = minute;
  ttime.tm_hour = hour;
  ttime.tm_mday = day;
  ttime.tm_mon = month - 1;
  ttime.tm_year = year - 1900;

  time_t seconds = mktime(&ttime) - timezone; // GMT+0
  if (seconds < 0) {
    fputs("Couldn't parse time data\n", stderr);
    return Status::WRONG_DATA_FORMAT;
  }

  std::ifstream input_file(filename, std::fstream::binary);
  if (input_file.good() == false) {
    fputs("Couldn't load given file\n", stderr);
    return Status::FILE_ERROR;
  }

  input_file.seekg(0, std::fstream::end);
  unsigned int size = input_file.tellg();
  input_file.seekg(0, std::fstream::beg);

  std::vector<std::byte> buffer(size);
  input_file.read((char *)buffer.data(), size);
  input_file.close();

  // perform number of checks to see if input is PE file
  if (buffer.size() < sizeof(IMAGE_DOS_HEADER)) {
    fputs("Invalid PE file\n", stderr);
    return Status::NOT_PE_ERROR;
  }
  IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)buffer.data();
  unsigned int required_size = dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS);
  if (buffer.size() < required_size) {
    fputs("Invalid PE file\n", stderr);
    return Status::NOT_PE_ERROR;
  }

  IMAGE_NT_HEADERS *nt_headers =
      (IMAGE_NT_HEADERS *)&(buffer.data()[dos_header->e_lfanew]);
  if (memcmp(&nt_headers->Signature, &IMAGE_NT_SIGNATURE_,
             sizeof(IMAGE_NT_SIGNATURE_)) != 0) {
    fputs("Invalid PE file\n", stderr);
    return Status::NOT_PE_ERROR;
  }
  IMAGE_FILE_HEADER *file_header = &nt_headers->FileHeader;
  memcpy((DWORD *)(&file_header->TimeDateStamp), &seconds, sizeof(DWORD));

  std::ofstream output_file(filename, std::fstream::binary);
  if (output_file.good() == false) {
    fputs("Couldn't write changed time\n", stderr);
    return Status::FILE_ERROR;
  }
  output_file.write((const char *)buffer.data(), size);
  output_file.close();

  return Status::OK;
}
