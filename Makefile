CXX = g++
CC = gcc
CXXFLAGS = -Wall -Wextra -fPIC -O2 -std=c++17
LDFLAGS = -shared -ldl -lpcap -pthread

PYTHON = python3

all: libnetspy.so

# Generate C++ bindings header from JSON
generated_bindings_header.hpp: network_functions.json generate_bindings.py
	$(PYTHON) generate_bindings.py $< header > $@

# Generate C++ bindings implementation from JSON
generated_bindings_impl.hpp: network_functions.json generate_bindings.py
	$(PYTHON) generate_bindings.py $< implementation > $@

# Generate final source from template and generated bindings
netspy.cpp: netspy.cpp.in generated_bindings_header.hpp generated_bindings_impl.hpp
	cp $< $@

# Compile the library
libnetspy.so: netspy.cpp network_interceptor.hpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f libnetspy.so *.o *.pcap generated_bindings_*.hpp netspy.cpp

.PHONY: all clean
