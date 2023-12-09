#include <tclcl.h>

extern EmbeddedTcl UwotpTclCode;

extern "C" int
Uwotp_Init()
{
	UwotpTclCode.load();
	return 0;
}