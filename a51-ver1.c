#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

#define ROL(x, y) (((x) << (y)) | ((x) >> (32 - (y))))
#define A5_STEP(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

#define A51_BLOCK_SIZE 8
#define A51_KEY_SIZE 8

void a5_1_encrypt(unsigned char *key, int key_len, unsigned char *msg, int msg_len, unsigned char *out) {
  unsigned int R1 = 0, R2 = 0, R3 = 0;
  for (int i = 0; i < 64; i++) {
    int feedback = ((key[i % key_len] >> (i / 8)) & 1) ^ ((R1 >> 18) & 1) ^ ((R2 >> 21) & 1) ^ ((R3 >> 22) & 1);
    R1 = (R1 << 1) | feedback;
    R2 = (R2 << 1) | ((R1 >> 8) & 1);
    R3 = (R3 << 1) | ((R2 >> 10) & 1);
  }
  for (int i = 0; i < msg_len; i++) {
    int feedback = A5_STEP((R1 >> 8) & 1, (R2 >> 10) & 1, (R3 >> 10) & 1);
    unsigned char key_byte = 0;
    for (int j = 0; j < 8; j++) {
      int bit = A5_STEP((R1 >> 18) & 1, (R2 >> 21) & 1, (R3 >> 22) & 1) ^ feedback;
      key_byte |= bit << j;
      R1 = (R1 << 1) | bit;
      R2 = (R2 << 1) | ((R1 >> 8) & 1);
      R3 = (R3 << 1) | ((R2 >> 10) & 1);
    }
    out[i] = msg[i] ^ key_byte;
  }
}

void a5_1_decrypt(unsigned char *key, int key_len, unsigned char *cipher, int cipher_len, unsigned char *out) {
  unsigned int R1 = 0, R2 = 0, R3 = 0;
  for (int i = 0; i < 64; i++) {
    int feedback = ((key[i % key_len] >> (i / 8)) & 1) ^ ((R1 >> 18) & 1) ^ ((R2 >> 21) & 1) ^ ((R3 >> 22) & 1);
    R1 = (R1 << 1) | feedback;
    R2 = (R2 << 1) | ((R1 >> 8) & 1);
    R3 = (R3 << 1) | ((R2 >> 10) & 1);
  }
  for (int i = 0; i < cipher_len; i++) {
    int feedback = A5_STEP((R1 >> 8) & 1, (R2 >> 10) & 1, (R3 >> 10) & 1);
    unsigned char key_byte = 0;
    for (int j = 0; j < 8; j++) {
      int bit = A5_STEP((R1 >> 18) & 1, (R2 >> 21) & 1, (R3 >> 22) & 1) ^ feedback;
      key_byte |= bit << j;
      R1 = (R1 << 1) | bit;
      R2 = (R2 << 1) | ((R1 >> 8) & 1);
      R3 = (R3 << 1) | ((R2 >> 10) & 1);
    }
    out[i] = cipher[i] ^ key_byte;
  }
}

void add_padding(HANDLE fh) {
  LARGE_INTEGER fs;
  GetFileSizeEx(fh, &fs);

  size_t paddingS = A51_BLOCK_SIZE - (fs.QuadPart % A51_BLOCK_SIZE);
  if (paddingS != A51_BLOCK_SIZE) {
    SetFilePointer(fh, 0, NULL, FILE_END);
    for (size_t i = 0; i < paddingS; ++i) {
      char paddingB = static_cast<char>(paddingS);
      WriteFile(fh, &paddingB, 1, NULL, NULL);
    }
  }
}

void remove_padding(HANDLE fileHandle) {
  LARGE_INTEGER fileSize;
  GetFileSizeEx(fileHandle, &fileSize);

  DWORD paddingSize;
  SetFilePointer(fileHandle, -1, NULL, FILE_END);
  ReadFile(fileHandle, &paddingSize, 1, NULL, NULL);

  if (paddingSize <= A51_BLOCK_SIZE && paddingSize > 0) {
    SetFilePointer(fileHandle, -paddingSize, NULL, FILE_END);

    BYTE* padding = (BYTE*)malloc(paddingSize);
    DWORD bytesRead;
    if (ReadFile(fileHandle, padding, paddingSize, &bytesRead, NULL) && bytesRead == paddingSize) {
      for (size_t i = 0; i < paddingSize; ++i) {
        if (padding[i] != static_cast<char>(paddingSize)) {
          printf("invalid padding found in the file.\n");
          free(padding);
          return;
        }
      }
      SetEndOfFile(fileHandle);
    } else {
      printf("error reading padding bytes from the file.\n");
    }
    free(padding);
  } else {
    printf("invalid padding size: %d\n", paddingSize);
  }
}

void encrypt_file(const char* inputFile, const char* outputFile, const char* key) {
  HANDLE ifh = CreateFileA(inputFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  HANDLE ofh = CreateFileA(outputFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

  if (ifh == INVALID_HANDLE_VALUE || ofh == INVALID_HANDLE_VALUE) {
    printf("error opening file.\n");
    return;
  }

  LARGE_INTEGER fileSize;
  GetFileSizeEx(ifh, &fileSize);

  unsigned char* fileData = (unsigned char*)malloc(fileSize.LowPart);
  DWORD bytesRead;
  ReadFile(ifh, fileData, fileSize.LowPart, &bytesRead, NULL);

  unsigned char keyData[A51_KEY_SIZE];
  memcpy(keyData, key, A51_KEY_SIZE);

  size_t paddingSize = (A51_BLOCK_SIZE - (fileSize.LowPart % A51_BLOCK_SIZE)) % A51_BLOCK_SIZE;

  size_t paddedSize = fileSize.LowPart + paddingSize;
  unsigned char* paddedData = (unsigned char*)malloc(paddedSize);
  memcpy(paddedData, fileData, fileSize.LowPart);
  memset(paddedData + fileSize.LowPart, static_cast<char>(paddingSize), paddingSize);

  for (size_t i = 0; i < paddedSize; i += A51_BLOCK_SIZE) {
    a5_1_encrypt(keyData, A51_KEY_SIZE, paddedData + i, A51_BLOCK_SIZE, paddedData + i);
  }

  DWORD bw;
  WriteFile(ofh, paddedData, paddedSize, &bw, NULL);

  printf("a5/1 encryption successful for file %s\n", inputFile);

  CloseHandle(ifh);
  CloseHandle(ofh);
  free(fileData);
  free(paddedData);
}

void decrypt_file(const char* inputFile, const char* outputFile, const char* key) {
  HANDLE ifh = CreateFileA(inputFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  HANDLE ofh = CreateFileA(outputFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

  if (ifh == INVALID_HANDLE_VALUE || ofh == INVALID_HANDLE_VALUE) {
    printf("error opening file.\n");
    return;
  }

  LARGE_INTEGER fileSize;
  GetFileSizeEx(ifh, &fileSize);

  unsigned char* fileData = (unsigned char*)malloc(fileSize.LowPart);
  DWORD bytesRead;
  ReadFile(ifh, fileData, fileSize.LowPart, &bytesRead, NULL);

  unsigned char keyData[A51_KEY_SIZE];
  memcpy(keyData, key, A51_KEY_SIZE);

  for (DWORD i = 0; i < fileSize.LowPart; i += A51_BLOCK_SIZE) {
    a5_1_decrypt(keyData, A51_KEY_SIZE, fileData + i, A51_BLOCK_SIZE, fileData + i);
  }

  size_t paddingSize = fileData[fileSize.LowPart - 1];

  if (paddingSize <= A51_BLOCK_SIZE && paddingSize > 0) {
    size_t originalSize = fileSize.LowPart - paddingSize;
    unsigned char* originalData = (unsigned char*)malloc(originalSize);
    memcpy(originalData, fileData, originalSize);

    DWORD bw;
    WriteFile(ofh, originalData, originalSize, &bw, NULL);

    printf("a5/1 decryption successful for file %s\n", inputFile);

    CloseHandle(ifh);
    CloseHandle(ofh);
    free(fileData);
    free(originalData);
  } else {
    printf("invalid padding size: %d\n", paddingSize);

    CloseHandle(ifh);
    CloseHandle(ofh);
    free(fileData);
  }
}

void process_directory(const char* directory, const char* key, int encrypt) {
  char searchPath[MAX_PATH];
  snprintf(searchPath, MAX_PATH, "%s\\*.*", directory);

  WIN32_FIND_DATAA findData;
  HANDLE hFind = FindFirstFileA(searchPath, &findData);

  if (hFind == INVALID_HANDLE_VALUE) {
    printf("error finding files in directory.\n");
    return;
  }

  do {
    if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
      char inputFile[MAX_PATH];
      snprintf(inputFile, MAX_PATH, "%s\\%s", directory, findData.cFileName);

      char outputFile[MAX_PATH];
      if (encrypt) {
        snprintf(outputFile, MAX_PATH, "%s\\%s.a51", directory, findData.cFileName);
        encrypt_file(inputFile, outputFile, key);
      } else {
        snprintf(outputFile, MAX_PATH, "%s\\%s.decrypted", directory, findData.cFileName);
        decrypt_file(inputFile, outputFile, key);
      }
    }
  } while (FindNextFileA(hFind, &findData) != 0);

  FindClose(hFind);
}

int main() {
  char directory[MAX_PATH];
  GetCurrentDirectoryA(MAX_PATH, directory);

  const char* key = "\x6d\x65\x6f\x77\x6d\x65\x6f\x77";

  process_directory(directory, key, 1); // encrypt files
  process_directory(directory, key, 0); // decrypt files

  return 0;
}
