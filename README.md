for compilation I have used the following command: 
  x86_64-w64-mingw32-g++ a51-ver1.c -o a51-ver1.exe -I/usr/share/mingw-w64/include/ -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc -fpermissive
  compiled binary tested on Windows
Usage: 
  Traversal function operates on the files found on the same directory where the executable is placed. 
  
