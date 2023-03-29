include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = test

# all source are stored in SRCS-y
SRCS-y := netfamily.c
SRCS-y += common.c
SRCS-y += tcp.c
SRCS-y += udp.c
CFLAGS += -Wall -g
# CFLAGS += -D ENABLE_SINGLE_EPOLL
CFLAGS += -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast -Wformat=0
LDLIBS += -lpthread

INC += $(sort $(wildcard *.h))

include $(RTE_SDK)/mk/rte.extapp.mk

