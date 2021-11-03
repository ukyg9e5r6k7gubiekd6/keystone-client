keystone-client
===============

C client for OpenStack Keystone authentication service

Depends on libcurl and libjson-c.

Build and launch on Ubuntu
==========================
$ sudo apt install libcurl4-openssl-dev libjson-c-dev

$ gcc -g3 -c -pedantic -Wall -fpic keystone-client.c -lcurl -ljson-c && \
gcc -shared -o libkeystone-client.so keystone-client.o

$ gcc -g3 -L<PATH_TO_REPO> -Wall -o test tests.c \
-lkeystone-client -lcurl -ljson-c

$ export LD_LIBRARY_PATH=<PATH_TO_REPO>:$LD_LIBRARY_PATH

$ ./test
