#include "uwotp-module.h"

UwOTPModule::UwOTPModule()
	: uwApplicationModule()
{

}

UwOTPModule::~UwOTPModule()
{

}

int 
UwOTPModule::command(int argc, const char* const* argv)
{
	return uwApplicationModule::command(argc, argv);
}

// void
// recv(Packet* p)
// {
// 	uwApplicationModule::recv(p);
// }