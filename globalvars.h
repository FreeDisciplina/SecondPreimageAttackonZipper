#ifndef GLOBALVAR_H__
#define GLOBALVAR_H__

#include "declares.h"

extern u64 n;

extern IppsAESSpec * pCtx1;
extern IppsSMS4Spec * pCtx2;

extern u8 m[16];

extern u64 functionCall;

#define initfunc(CIPHER, pCtx)                                                                                                                                        \
{																																									  \
	status = ipps##CIPHER##GetSize(&ctxSize);																														  \
	pCtx = (Ipps##CIPHER##Spec *)malloc(ctxSize);																													  \
	status = ipps##CIPHER##Init(pKey, keylen, pCtx, ctxSize);																										  \
	switch (status)																																					  \
	{																																								  \
	case ippStsNoErr: /*cout << "ippStsNoErr: Indicates no error." << endl;*/ break;																				  \
	case ippStsNullPtrErr: cout << "ippStsNullPtrErr: Indicates an error condition if the pCtx pointer is NULL." << endl; break;									  \
	case ippStsLengthErr: cout << "ippStsLengthErr: Returns an error condition if keyLen is not equal to 16, 24, or 32." << endl; break;							  \
	case ippStsMemAllocErr: cout << "ippStsMemAllocErr: Indicates an error condition if the allocated memory is insufficient for the operation." << endl; break;	  \
	default: break;																																					  \
	}																																								  \
}

#define endfunc(pCtx)            \
{								 \
	if (pCtx != NULL)			 \
	{							 \
		free(pCtx);				 \
	}							 \
}

data_t f1(data_t x);
data_t f2(data_t x);

data_t h1(data_t x, u8 mblock[16]);
data_t h2(data_t x, u8 mblock[16]);

typedef data_t(*func_t)(data_t x);
typedef data_t(*comp_t)(data_t x, u8 mblock[16]);

#endif