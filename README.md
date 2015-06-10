# libfins
Library implementing FINS protocol over TCP

Compiling
=======
Use qmake to compile the library.
Create a build directory:

mkdir build
cd build

and run:

qmake ../src/fins.pro
make

Using
=======
See example.c for usage.
Compile example like this:

cd build
gcc -c -I ../src ../example.c
gcc -o example example.o -lfins -L.

