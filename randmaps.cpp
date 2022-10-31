#include "globalvars.h"

data_t f1(data_t x)
{
	functionCall++;

	IppStatus status;
	int srclen;
	srclen = 16;
	Ipp8u pSrc[16];
	Ipp8u pDst[16];

	x &= mask;
	data_t y;
	for (size_t i = 0; i < 16; i++)
	{
		pSrc[i] = 0;
		pDst[i] = 0;
	}
	memcpy(pSrc, &x, sizeof(data_t));
	status = ippsAESEncryptECB(pSrc, pDst, srclen, pCtx1);
	switch (status)
	{
	case ippStsNoErr: /*cout << "ippStsNoErr: Indicates no error." << endl;*/ break;
	case ippStsNullPtrErr: cout << "ippStsNullPtrErr: Indicates an error condition if the specified  pointer is NULL." << endl; break;
	case ippStsLengthErr: cout << "ippStsLengthErr: Indicates an error condition if the input data stream length is less than or equal to zero." << endl; break;
	case ippStsUnderRunErr: cout << "ippStsUnderRunErr: Indicates an error condition if srclen is not divisible by cipher block size." << endl; break;
	case ippStsContextMatchErr: cout << "ippStsContextMatchErr: Indicates an error condition if the context parameter does not match the operation." << endl; break;
	default: break;
	}
	memcpy(&y, pDst, sizeof(data_t));
	return (y & mask);
}

data_t f2(data_t x)
{
	functionCall++;

	IppStatus status;
	Ipp8u pSrc[16];
	Ipp8u pDst[16];
	int srclen;
	srclen = 16;

	x &= mask;
	data_t y;
	for (size_t i = 0; i < 16; i++)
	{
		pSrc[i] = 0;
		pDst[i] = 0;
	}
	memcpy(pSrc, &x, sizeof(data_t));
	status = ippsSMS4DecryptECB(pSrc, pDst, srclen, pCtx2);
	switch (status)
	{
	case ippStsNoErr: /*cout << "ippStsNoErr: Indicates no error." << endl;*/ break;
	case ippStsNullPtrErr: cout << "ippStsNullPtrErr: Indicates an error condition if the specified  pointer is NULL." << endl; break;
	case ippStsLengthErr: cout << "ippStsLengthErr: Indicates an error condition if the input data stream length is less than or equal to zero." << endl; break;
	case ippStsUnderRunErr: cout << "ippStsUnderRunErr: Indicates an error condition if srclen is not divisible by cipher block size." << endl; break;
	case ippStsContextMatchErr: cout << "ippStsContextMatchErr: Indicates an error condition if the context parameter does not match the operation." << endl; break;
	default: break;
	}
	memcpy(&y, pDst, sizeof(data_t));
	return (y & mask);
}

data_t h1(data_t x, u8 mblock[16])
{
	functionCall++;

	IppStatus status;
	int keylen;
	int ctxSize;
	Ipp8u pKey[16];
	IppsAESSpec * pCtx;

	memcpy(pKey, mblock, sizeof(pKey));
	keylen = 16;
	initfunc(AES, pCtx);

	int srclen;
	srclen = 16;
	Ipp8u pSrc[16];
	Ipp8u pDst[16];

	x &= mask;
	data_t y;
	for (size_t i = 0; i < 16; i++)
	{
		pSrc[i] = 0;
		pDst[i] = 0;
	}
	memcpy(pSrc, &x, sizeof(data_t));
	status = ippsAESEncryptECB(pSrc, pDst, srclen, pCtx);
	switch (status)
	{
	case ippStsNoErr: /*cout << "ippStsNoErr: Indicates no error." << endl;*/ break;
	case ippStsNullPtrErr: cout << "ippStsNullPtrErr: Indicates an error condition if the specified  pointer is NULL." << endl; break;
	case ippStsLengthErr: cout << "ippStsLengthErr: Indicates an error condition if the input data stream length is less than or equal to zero." << endl; break;
	case ippStsUnderRunErr: cout << "ippStsUnderRunErr: Indicates an error condition if srclen is not divisible by cipher block size." << endl; break;
	case ippStsContextMatchErr: cout << "ippStsContextMatchErr: Indicates an error condition if the context parameter does not match the operation." << endl; break;
	default: break;
	}
	memcpy(&y, pDst, sizeof(data_t));

	endfunc(pCtx);
	return (y & mask);
}

data_t h2(data_t x, u8 mblock[16])
{
	functionCall++;

	IppStatus status;
	int keylen;
	int ctxSize;
	Ipp8u pKey[16];
	IppsSMS4Spec * pCtx;

	memcpy(pKey, mblock, sizeof(pKey));
	keylen = 16;
	initfunc(SMS4, pCtx);

	Ipp8u pSrc[16];
	Ipp8u pDst[16];
	int srclen;
	srclen = 16;

	x &= mask;
	data_t y;
	for (size_t i = 0; i < 16; i++)
	{
		pSrc[i] = 0;
		pDst[i] = 0;
	}
	memcpy(pSrc, &x, sizeof(data_t));
	status = ippsSMS4DecryptECB(pSrc, pDst, srclen, pCtx);
	switch (status)
	{
	case ippStsNoErr: /*cout << "ippStsNoErr: Indicates no error." << endl;*/ break;
	case ippStsNullPtrErr: cout << "ippStsNullPtrErr: Indicates an error condition if the specified  pointer is NULL." << endl; break;
	case ippStsLengthErr: cout << "ippStsLengthErr: Indicates an error condition if the input data stream length is less than or equal to zero." << endl; break;
	case ippStsUnderRunErr: cout << "ippStsUnderRunErr: Indicates an error condition if srclen is not divisible by cipher block size." << endl; break;
	case ippStsContextMatchErr: cout << "ippStsContextMatchErr: Indicates an error condition if the context parameter does not match the operation." << endl; break;
	default: break;
	}
	memcpy(&y, pDst, sizeof(data_t));
	endfunc(pCtx);
	return (y & mask);
}
