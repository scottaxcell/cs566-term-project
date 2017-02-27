
all:
	/usr/local/Cellar/gcc/5.3.0/bin/g++-5 -std=c++11 -o rsaTester rsaTester.cpp -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lssl -lcrypto
	/usr/local/Cellar/gcc/5.3.0/bin/g++-5 -std=c++11 -o chatTester chatTester.cpp -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lssl -lcrypto

clean:
	rm -f rsaTester
	rm -f chatTester
