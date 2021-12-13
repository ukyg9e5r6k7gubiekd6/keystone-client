keystone-client
===============

C client for OpenStack Keystone authentication service

Depends on libcurl.

Build library
=============
$ sudo apt install libcurl4-openssl-dev

$ gcc -g3 -c -pedantic -Wall -Wextra -Wformat-security -std=c18 -fpic \
keystone-client.c -lcurl \
&& gcc -shared -o libkeystone-client.so keystone-client.o

Build and run smoke test
========================
$ cd tests
$ gcc -g3 -L<PATH_TO_REPO> -Wall -Wextra -Wformat-security -std=c18 -o \
smoke_test smoke_test.c -lkeystone-client -lcurl

$ export KSTEST_ADMIN_URL=http://<IP_ADDRESS>/identity
$ export OS_PROJECT_NAME=admin
$ export KSTEST_ADMIN_USERNAME=admin
$ export KSTEST_ADMIN_PASSWORD=secret

$ export LD_LIBRARY_PATH=<PATH_TO_REPO>:$LD_LIBRARY_PATH

$ ./smoke_test
