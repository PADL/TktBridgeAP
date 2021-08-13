// TktBridgeAP.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "TktBridgeAP.h"


// This is an example of an exported variable
TKTBRIDGEAP_API int nTktBridgeAP=0;

// This is an example of an exported function.
TKTBRIDGEAP_API int fnTktBridgeAP(void)
{
    return 0;
}

// This is the constructor of a class that has been exported.
CTktBridgeAP::CTktBridgeAP()
{
    return;
}
