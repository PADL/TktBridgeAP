// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the TKTBRIDGEAP_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// TKTBRIDGEAP_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef TKTBRIDGEAP_EXPORTS
#define TKTBRIDGEAP_API __declspec(dllexport)
#else
#define TKTBRIDGEAP_API __declspec(dllimport)
#endif

// This class is exported from the dll
class TKTBRIDGEAP_API CTktBridgeAP {
public:
	CTktBridgeAP(void);
	// TODO: add your methods here.
};

extern TKTBRIDGEAP_API int nTktBridgeAP;

TKTBRIDGEAP_API int fnTktBridgeAP(void);
