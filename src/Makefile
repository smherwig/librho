# == CHANGE THE SETTINGS BELOW TO SUIT YOUR ENVIRONMENT

# Your platform. 
# choose: "frebsd" "linux", "macos", "netbsd", or "openbsd"
#----------------------------------------------------------
PLAT= linux


# Cryptographic backend
# choose: "none", "openssl", or "bearssl"
#----------------------------------------------------------
CRYPTO= openssl


# Compiler options
#----------------------------------------------------------
CC= gcc -std=gnu99

ifeq ($(PLAT),freebsd) 
	SYSCFLAGS= -DRHO_PLAT_FREEBSD 
endif
ifeq ($(PLAT),linux)
	SYSCFLAGS= -DRHO_PLAT_LINUX
endif
ifeq ($(PLAT),macos)
	SYSCFLAGS= -DRHO_PLAT_MACOS
endif
ifeq ($(PLAT),netbsd)
	SYSCFLAGS= -DRHO_PLAT_NETBSD
endif
ifeq ($(PLAT),openbsd)
	SYSCFLAGS= -DRHO_PLAT_NETBSD
endif

# the -Wno-deprecated-declarations is for OpenSSL
CFLAGS = -Wall -Werror -Wextra -Wno-deprecated-declarations -I. \
		 $(SYSCFLAGS) $(MYCFLAGS)

# Utilities
#----------------------------------------------------------
AR= ar rcu
RANLIB= ranlib
RM= rm -f
MKDIR= mkdir -p
INSTALL= install -p
INSTALL_EXEC= $(INSTALL) -m 0755
INSTALL_DATA= $(INSTALL) -m 0644

# If you don't have install, you can use "cp" instead.
# 
# INSTALL= cp -p
# INSTALL_EXEC= $(INSTALL)
# INSTALL_DATA= $(INSTALL)


# Install Location
# See, also, the local target
#----------------------------------------------------------
INSTALL_TOP= /usr/local
INSTALL_INC= $(INSTALL_TOP)/include/rho
INSTALL_LIB= $(INSTALL_TOP)/lib


# == END OF USER SETTINGS -- NO NEED TO CHANGE ANYTHING BELOW THIS LINE =======

# Headers to intsall
#----------------------------------------------------------
TO_INC=  \
	rho_array.h \
	rho_atomic.h \
	rho_base32.h \
	rho_base64.h \
	rho_binascii.h \
	rho_bitmap.h \
	rho_bitops.h \
	rho_buf.h \
	rho_crypto.h \
	rho_daemon.h \
	rho_decls.h \
	rho_der.h \
	rho_dns.h \
	rho_endian.h \
	rho_event.h \
	rho_fd.h \
	rho_file.h \
	rho.h \
	rho_log.h \
	rho_mem.h \
	rho_misc.h \
	rho_path.h \
	rho_pem.h \
	rho_queue.h \
	rho_rand.h \
	rho_sock.h \
	rho_ssl.h \
	rho_str.h \
	rho_sys.h \
	rho_term.h \
	rho_thread.h \
	rho_time.h \
	rho_timeout.h \
	rho_tree.h \
	rho_url.h \
	rho_vector.h 

# Library to install
#----------------------------------------------------------
TO_LIB= librho.a librho-pic.a

RHO_A= librho.a
RHO_PIC_A= librho-pic.a

RHO_CORE_OBJS= \
		  rho_base32.o \
		  rho_base64.o \
		  rho_binascii.o \
		  rho_bitmap.o \
		  rho_buf.o \
		  rho_daemon.o \
		  rho_der.o \
		  rho_dns.o \
		  rho_event.o \
		  rho_fd.o \
		  rho_file.o \
		  rho_log.o \
		  rho_mem.o \
		  rho_path.o \
		  rho_pem.o \
		  rho_rand.o \
		  rho_ssl_common.o \
		  rho_sock.o \
		  rho_str.o \
		  rho_sys.o \
		  rho_term.o \
		  rho_thread.o \
		  rho_time.o \
		  rho_timeout.o \
		  rho_url.o \
		  rho_vector.o

RHO_OPENSSL_OBJS= $(addprefix openssl/, \
	rho_crypto.o \
	rho_ssl.o  \
	rho_openssl.o \
	)

RHO_BEARSSL_OBJS= $(addprefix bearssl/, \
	rho_crypto.o \
	rho_ssl.o \
	rho_bearssl_cert.o \
	rho_bearssl_error.o \
	rho_bearssl_key.o \
	rho_bearssl_pem.o \
	rho_bearssl_ta.o \
	)

ifeq ($(CRYPTO),openssl)
	RHO_OBJS= $(RHO_CORE_OBJS) $(RHO_OPENSSL_OBJS)
else
ifeq ($(CRYPTO),bearssl)
	RHO_OBJS= $(RHO_CORE_OBJS) $(RHO_BEARSSL_OBJS)
else
	RHO_OBJS= $(RHO_CORE_OBJS)
endif
endif

RHO_PIC_OBJS= $(addsuffix .do, $(basename $(RHO_OBJS)))

%.do : %.c
	$(CC) -c $(CFLAGS) -fPIC -fvisibility=hidden $(CPPFLAGS) -o $@ $<

# Targets start here
#----------------------------------------------------------
all: $(RHO_A) $(RHO_PIC_A)

$(RHO_A): $(RHO_OBJS)
	$(AR) $@ $(RHO_OBJS)
	$(RANLIB) $@

$(RHO_PIC_A): $(RHO_PIC_OBJS)
	$(AR) $@ $(RHO_PIC_OBJS)
	$(RANLIB) $@

install:
	$(MKDIR) $(INSTALL_INC) $(INSTALL_LIB)
	$(INSTALL_DATA) $(TO_INC) $(INSTALL_INC)
	$(INSTALL_DATA) $(TO_LIB) $(INSTALL_LIB)

uninstall:
	cd $(INSTALL_INC) && $(RM) $(TO_INC)
	cd $(INSTALL_LIB) && $(RM) $(TO_LIB)

local:
	$(MAKE) install INSTALL_TOP=../install

clean:
	$(RM) $(RHO_CORE_OBJS) $(RHO_OPENSSL_OBJS) $(RHO_BEARSSL_OBJS) $(RHO_A) \
		$(RHO_PIC_OBJS) $(RHO_PIC_A)

echo:
	@echo "PLAT= $(PLAT)"
	@echo "CRYPTO=$(CRYPTO)"
	@echo "CC= $(CC)"
	@echo "CFLAGS= $(CFLAGS)"
	@echo "AR= $(AR)"
	@echo "RANLIB= $(RANLIB)"
	@echo "RM= $(RM)"
	@echo "MKDIR= $(MKDIR)"
	@echo "INSTALL= $(INSTALL)"
	@echo "INSTALL_EXEC= $(INSTALL_EXEC)"
	@echo "INSTALL_DATA= $(INSTALL_DATA)"
	@echo "TO_INC= $(TO_INC)"
	@echo "TO_LIB= $(TO_LIB)"
	@echo "INSTALL_TOP= $(INSTALL_TOP)"
	@echo "INSTALL_INC= $(INSTALL_INC)"
	@echo "INSTALL_LIB= $(INSTALL_LIB)"


# DO NOT DELETE

$(addprefix rho_base32.,o do): rho_base32.c rho_base32.h rho_log.h
$(addprefix rho_base64.,o do): rho_base64.c rho_base64.h rho_log.h
$(addprefix rho_binascii.,o do): rho_binascii.c rho_binascii.h rho_log.h
$(addprefix rho_bitmap.,o do): rho_bitmap.c rho_bitmap.h rho_log.h rho_mem.h
$(addprefix rho_buf.,o do): rho_buf.c rho_buf.h rho_log.h rho_mem.h
$(addprefix rho_daemon.,o do): rho_daemon.c rho_daemon.h rho_fd.h rho_log.h \
	rho_path.h
$(addprefix rho_der.,o do): rho_der.c rho_der.h
$(addprefix rho_dns., o do): rho_dns.c rho_dns.h rho_log.h
$(addprefix rho_event., o do): rho_event.c rho_event.h rho_log.h rho_mem.h \
	rho_queue.h rho_time.h
$(addprefix rho_fd.,o do): rho_fd.c rho_fd.h
$(addprefix rho_file.,o do): rho_file.c rho_file.h rho_log.h
$(addprefix rho_log.,o do): rho_log.c rho_log.h
$(addprefix rho_mem.,o do): rho_mem.c rho_mem.h rho_log.h
$(addprefix rho_path.,o do): rho_path.c rho_log.h rho_path.h
$(addprefix rho_pem.,o do): rho_pem.c rho_mem.h rho_pem.h
$(addprefix rho_rand.,o do): rho_rand.c rho_rand.h
$(addprefix rho_ssl_common.,o do): rho_ssl_common.c rho_mem.h rho_ssl.h
$(addprefix rho_sock.,o do): rho_sock.c rho_buf.h rho_fd.h rho_log.h rho_mem.h \
	rho_sock.h rho_timeout.h
$(addprefix rho_str.,o do): rho_str.c rho_log.h rho_str.h
$(addprefix rho_sys.,o do): rho_sys.c rho_log.h rho_sys.h
$(addprefix rho_term.,o do): rho_term.c rho_log.h rho_term.h
$(addprefix rho_thread.,o do): rho_thread.c rho_log.h rho_thread.h
$(addprefix rho_time.,o do): rho_time.c rho_log.h rho_time.h 
$(addprefix rho_timeout.,o do): rho_timeout.c rho_mem.h rho_time.h rho_timeout.h
$(addprefix rho_url.,o do): rho_url.c rho_buf.h rho_mem.h rho_url.h
$(addprefix rho_vector.,o do): rho_vector.c rho_mem.h rho_vector.h

$(addprefix openssl/rho_crypto.,o do): openssl/rho_crypto.c rho_crypto.h \
	rho_log.h rho_mem.h rho_ssl.h openssl/rho_openssl.h
$(addprefix openssl/rho_ssl.,o do): openssl/rho_ssl.c rho_buf.h rho_log.h \
	rho_mem.h rho_sock.h rho_ssl.h openssl/rho_openssl.h
$(addprefix openssl/rho_openssl.,o do): openssl/rho_openssl.c \
	openssl/rho_openssl.h

$(addprefix bearssl/rho_crypto.,o do): bearssl/rho_crypto.c rho_crypto.h \
	rho_mem.h rho_log.h
$(addprefix bearssl/rho_ssl.,o do): bearssl/rho_ssl.c rho_log.h rho_mem.h \
	rho_sock.h rho_ssl.h rho_vector.h
$(addprefix bearssl/rho_bearssl_cert.,o do): bearssl/rho_bearssl_cert.c
$(addprefix bearssl/rho_bearssl_error.,o do): bearssl/rho_bearssl_error.c
$(addprefix bearssl/rho_bearssl_key.,o do): bearssl/rho_bearssl_key.c
$(addprefix bearssl/rho_bearssl_pem.,o do): bearssl/rho_bearssl_pem.c
$(addprefix bearssl/rho_bearssl_ta.,o do): bearssl/rho_bearssl_ta.c

.PHONY: all clean echo install local uninstall
