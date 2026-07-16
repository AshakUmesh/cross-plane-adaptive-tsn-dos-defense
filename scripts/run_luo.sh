#!/bin/bash
for i in $(seq 0 19); do
  ./out/clang-release/luo2021 \
    -u Cmdenv \
    -n .:/home/ashakumesh/research/omnetpp-6.4.0/samples/inet/src \
    -l /home/ashakumesh/research/omnetpp-6.4.0/samples/inet/src/libINET.so \
    -c BenignDiverse -r $i \
    omnetpp.ini
done
