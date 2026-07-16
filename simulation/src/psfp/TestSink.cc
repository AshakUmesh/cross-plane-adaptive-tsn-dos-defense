#include "TestSink.h"

Define_Module(TestSink);

void TestSink::handleMessage(cMessage *msg)
{
   std::cout << "Packet reached sink" << std::endl; 

    delete msg;
}
