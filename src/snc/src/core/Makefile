#
#loading path
#--------------------------------------------------------------------------------------------------------------------------------------------------
CXX := g++
TARGET := libsnc_ping.so

CXXFLAGS := -std=c++11\
        -Werror\
        -fstack-protector-strong\
        -fPIC\
        -O2\
        -g

LDFLAGS := -s\
        -shared\
        -Wl,-z,relro\
        -Wl,-z,now\
        -Wl,-z,noexecstack\
        -Wl,--copy-dt-needed-entries

HCCL_INC_DIR = ${ASCEND_DIR}/include
HCCL_LIB_DIR = ${ASCEND_DIR}/lib64
ACL_INC_DIR = ${ASCEND_DIR}/include
ACL_LIB_DIR = ${ASCEND_DIR}/lib64
#
#paths
#--------------------------------------------------------------------------------------------------------------------------------------------------
SRC_DIR := src
INC_DIR := include
DEPENDS_DIR := depends
LOG_DIR := log
LIB_DIR := lib
BIN_DIR := bin
#
#library flags
#--------------------------------------------------------------------------------------------------------------------------------------------------
LIBS = -L$(HCCL_LIB_DIR) -lhccl_plf\
        -L$(ACL_LIB_DIR) -lascendcl
INCLUDEDIRS = -I$(INC_DIR)\
                -I$(SRC_DIR)\
                -I$(DEPENDS_DIR)\
                -I$(LOG_DIR)\
                -I$(ACL_INC_DIR)\
                -I$(ACL_INC_DIR)/acl\
                -I$(HCCL_INC_DIR)
#
#make
#--------------------------------------------------------------------------------------------------------------------------------------------------
.PHONY: all clean
all:
	@mkdir -p $(LIB_DIR) $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(SRC_DIR)/snc_ping.cc $(LOG_DIR)/snc_ping_log.cc $(INCLUDEDIRS) $(LDFLAGS) -o ./$(LIB_DIR)/$(TARGET) $(LIBS)
	@printf "\nSNC Ping shared library compile completed\n"

clean:
	rm -rf ./$(LIB_DIR)/* ./$(BIN_DIR)/*
