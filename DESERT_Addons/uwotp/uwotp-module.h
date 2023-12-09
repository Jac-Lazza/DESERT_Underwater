#ifndef UWOTP_MODULE_H
#define UWOTP_MODULE_H

#include "uwApplication_cmn_header.h"
#include "uwApplication_module.h"

class UwOTPModule;

class UwOTPModule : public uwApplicationModule
{
	public:
		UwOTPModule();
		virtual ~UwOTPModule();

		virtual int command(int argc, const char* const* argv) override;
		// virtual void recv(Packet* p) override;
};

#endif /* UWOTP_MODULE_H */