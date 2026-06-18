#!/bin/bash

./out/clang-release/luo2021 \
-u Cmdenv \
-c ThresholdEvasionAttack \
-n .:/home/ashakumesh/research/omnetpp-6.4.0/samples/inet/src \
-l /home/ashakumesh/research/omnetpp-6.4.0/samples/inet/src/libINET.so \
omnetpp.ini
