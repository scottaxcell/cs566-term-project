all:
	gcc -Wall -g -D_POSIX_SOURCE -std=c99 -o awget awget.c
	gcc -Wall -g -pthread -D_POSIX_SOURCE -std=c99 -o ss ss.c
dbg:
	gcc -Wall -g -D_POSIX_SOURCE -std=c99 -o awget awget.c
awget:
	gcc -Wall -g -D_POSIX_SOURCE -std=c99 -o awget awget.c
ss:
	gcc -Wall -g -pthread -D_POSIX_SOURCE -std=c99 -o ss ss.c
clean:
	rm -f awget ss
