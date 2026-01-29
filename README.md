# anon1
-Classical Version-
Dependencies; OpenSSL, MCL and their respective dependencies.
After cloning the repo and building the MCL library in the extern folder (follow https://github.com/herumi/mcl instructions)
Simply run the following to build on your system (tested on Ubuntu Mate 24.04 LTS Linux)
(It will run an auto benchmark harness and all system tests)
For memory usage tracking please use Valgrind
For Proof or Verify Times or Size, the harness should output metrics with increasing degree of polynomial.
From root directory:
rm -rf build
mkdir build && cd build
cmake ..
make -j
./kupcom

Note: MacOS and Windows may not run this code so please use a Linux OS or Virtual Machine.
