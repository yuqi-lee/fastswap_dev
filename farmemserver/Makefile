.PHONY: clean

CFLAGS := -Wall -O0 -g -ggdb -Werror
LDLIBS := ${LDLIBS} -lrdmacm -libverbs -lpthread
CC := g++ -O0 -g

APPS := rmserver

all: ${APPS}

clean:
	rm -f ${APPS}
