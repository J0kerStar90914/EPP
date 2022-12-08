appname := dropcatch

CXX := gcc
CFLAGS = -Wall
LDLIBS = -I/usr/include/cppconn -L/usr/lib -lmysqlcppconn -lssl -lcrypto -lsystemd -lstdc++ `pkg-config --libs libconfig++` -pthread
RM := rm -f
SRCS:=dropcatch.cpp
OBJS:=$(subst .cc,.o,$(SRCS))
all: $(appname)

$(appname): $(OBJS)
	$(CXX) $(CFLAGS) -o $(appname) $(OBJS) $(LDLIBS)

clean:
	$(RM) *.o *.d *.log *.save *.back
