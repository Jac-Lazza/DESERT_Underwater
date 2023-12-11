#include "uwotp-module.h"

static class UwOTPModuleClass : public TclClass
{
	public:
		UwOTPModuleClass()
			: TclClass("Module/UW/OTP")
		{
		}

		TclObject*
		create(int, const char* const*)
		{
			return (new UwOTPModule());
		}
} class_module_uwotp;

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