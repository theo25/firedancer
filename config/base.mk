SHELL:=/bin/bash
CPPFLAGS:=
CC:=/home/theo/builds/gcc/inst-12.2.0/bin/gcc
CFLAGS:=-std=c17 -fprofile-arcs -ftest-coverage
CXX:=/home/theo/builds/gcc/inst-12.2.0/bin/g++
CXXFLAGS:=-std=c++17 -fprofile-arcs -ftest-coverage
LD:=/home/theo/builds/gcc/inst-12.2.0/bin/g++
LDFLAGS:=-lm -L/home/theo/builds/gcc/inst-12.2.0/lib64 -Wl,-rpath -Wl,/home/theo/builds/gcc/inst-12.2.0/lib64 -lgcov --coverage
AR:=ar
ARFLAGS:=rv
RANLIB:=ranlib
CP:=cp -pv
RM:=rm -fv
MKDIR:=mkdir -pv
RMDIR:=rm -rfv
SED:=sed
FIND:=find
SCRUB:=$(FIND) . -type f -name "*~" -o -name "\#*" | xargs $(RM)
