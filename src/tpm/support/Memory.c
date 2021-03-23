/******************************************************************************************************************/
/*                                                                                                                */
/*                                                                                                                */
/*  Licenses and Notices                                                                                          */
/*     Copyright Licenses:                                                                                        */
/*     ·  Trusted Computing Group (TCG) grants to the user of the source code in this specification (the         */
/*     "Source Code") a worldwide, irrevocable, nonexclusive, royalty free, copyright license to                  */
/*     reproduce, create derivative works, distribute, display and perform the Source Code and                    */
/*     derivative works thereof, and to grant others the rights granted herein.                                   */
/*     ·  The TCG grants to the user of the other parts of the specification (other than the Source Code)        */
/*     the rights to reproduce, distribute, display, and perform the specification solely for the purpose of      */
/*     developing products based on such documents.                                                               */
/*     Source Code Distribution Conditions:                                                                       */
/*     ·  Redistributions of Source Code must retain the above copyright licenses, this list of conditions       */
/*     and the following disclaimers.                                                                             */
/*     ·  Redistributions in binary form must reproduce the above copyright licenses, this list of conditions    */
/*     and the following disclaimers in the documentation and/or other materials provided with the                */
/*     distribution.                                                                                              */
/*     Disclaimers:                                                                                               */
/*     ·  THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF                                    */
/*     LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH                                      */
/*     RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)                                      */
/*     THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.                                        */
/*     Contact TCG Administration (admin@trustedcomputinggroup.org) for information on specification              */
/*     licensing rights available through TCG membership agreements.                                              */
/*     ·  THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED WARRANTIES                           */
/*     WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR FITNESS FOR A                                     */
/*     PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR NONINFRINGEMENT OF                                          */
/*     INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY OTHERWISE ARISING OUT OF                                     */
/*     ANY PROPOSAL, SPECIFICATION OR SAMPLE.                                                                     */
/*     ·  Without limitation, TCG and its members and licensors disclaim all liability, including liability for  */
/*     infringement of any proprietary rights, relating to use of information in this specification and to the    */
/*     implementation of this specification, and TCG disclaims all liability for cost of procurement of           */
/*     substitute goods or services, lost profits, loss of use, loss of data or any incidental, consequential,    */
/*     direct, indirect, or special damages, whether under contract, tort, warranty or otherwise, arising in      */
/*     any way out of use or reliance upon this specification or any information herein.                          */
/*     Any marks and brands contained herein are the property of their respective owners.                         */
/*                                                                                                                */
/******************************************************************************************************************/

// 9.12.1 Description
// This file contains a set of miscellaneous memory manipulation routines. Many of the functions have the
// same semantics as functions defined in string.h. Those functions are not used directly in the
// TPM
// because they are not safe
// This version uses string.h after adding guards. This is because the math libraries invariably use those
// functions so it is not practical to prevent those library functions from being pulled into the build.
// 9.12.2 Includes and Data Definitions
#include "Tpm.h"
#include "Memory_fp.h"
#ifndef INLINE_FUNCTIONS
void
MemoryCopy(
    void *dest,
    const void *src,
    int sSize
)
{
    memmove(dest, src, sSize);
}
#endif     // INLINE_FUNCTIONS
BOOL
MemoryEqual(
    const void *buffer1,              // IN: compare buffer1
    const void *buffer2,              // IN: compare buffer2
    unsigned int size                // IN: size of bytes being compared
)
{
    BYTE equal = 0;
    const BYTE *b1 = (BYTE *)buffer1;
    const BYTE *b2 = (BYTE *)buffer2;
//
    // Compare all bytes so that there is no leakage of information
    // due to timing differences.
    for(; size > 0; size--)
        equal |= (*b1++ ^ *b2++);
    return (equal == 0);
}
LIB_EXPORT INT16
MemoryCopy2B(
    TPM2B *dest,               // OUT: receiving TPM2B
    const TPM2B *source,             // IN: source TPM2B
    unsigned int dSize                // IN: size of the receiving buffer
)
{
    pAssert(dest != NULL);
    if(source == NULL)
        dest->size = 0;
    else
    {
        pAssert(source->size <= dSize);
        MemoryCopy(dest->buffer, source->buffer, source->size);
        dest->size = source->size;
    }
    return dest->size;
}
void
MemoryConcat2B(
    TPM2B *aInOut,             // IN/OUT: destination 2B
    TPM2B *bIn,                // IN: second 2B
    unsigned int aMaxSize             // IN: The size of aInOut.buffer (max values for
    // aInOut.size)
)
{
    pAssert(bIn->size <= aMaxSize - aInOut->size);
    MemoryCopy(&aInOut->buffer[aInOut->size], &bIn->buffer, bIn->size);
    aInOut->size = aInOut->size + bIn->size;
    return;
}
BOOL
MemoryEqual2B(
    const TPM2B *aIn,               // IN: compare value
    const TPM2B *bIn                // IN: compare value
)
{
    if(aIn->size != bIn->size)
        return FALSE;
    return MemoryEqual(aIn->buffer, bIn->buffer, aIn->size);
}
#ifndef INLINE_FUNCTIONS
void
MemorySet(
    void *dest,
    int value,
    size_t size
)
{
    memset(dest, value, size);
}
#endif     // INLINE_FUNCTIONS
#ifndef INLINE_FUNCTIONS
void
MemoryPad2B(
    TPM2B *b,
    UINT16 newSize
)
{
    MemorySet(&b->buffer[b->size], 0, newSize - b->size);
    b->size = newSize;
}
#endif     // INLINE_FUNCTIONS
#ifndef INLINE_FUNCTIONS
void
Uint16ToByteArray(
    UINT16 i,
    BYTE *a
)
{
    a[1] = (BYTE)(i);
    i >>= 8;
    a[0] = (BYTE)(i);
}
#endif    // INLINE_FUNCTIONS
#ifndef INLINE_FUNCTIONS
void
Uint32ToByteArray(
    UINT32 i,
    BYTE *a
)
{
    a[3] = (BYTE)(i);
    i >>= 8;
    a[2] = (BYTE)(i);
    i >>= 8;
    a[1] = (BYTE)(i);
    i >>= 8;
    a[0] = (BYTE)(i);
}
#endif    // INLINE_FUNCTIONS
#ifndef INLINE_FUNCTIONS
void
Uint64ToByteArray(
    UINT64 i,
    BYTE *a
)
{
    a[7] = (BYTE)(i);
    i >>= 8;
    a[6] = (BYTE)(i);
    i >>= 8;
    a[5] = (BYTE)(i);
    i >>= 8;
    a[4] = (BYTE)(i);
    i >>= 8;
    a[3] = (BYTE)(i);
    i >>= 8;
    a[2] = (BYTE)(i);
    i >>= 8;
    a[1] = (BYTE)(i);
    i >>= 8;
    a[0] = (BYTE)(i);
}
#endif    // INLINE_FUNCTIONS
#ifndef INLINE_FUNCTIONS
UINT16
ByteArrayToUint16(
    BYTE *a
)
{
    UINT16 retVal;
    retVal = a[0];
    retVal <<= 8;
    retVal += a[1];
    return retVal;
}
#endif   // INLINE_FUNCTIONS
#ifndef INLINE_FUNCTIONS
UINT32
ByteArrayToUint32(
    BYTE *a
)
{
    UINT32 retVal;
    retVal = a[0];
    retVal <<= 8;
    retVal += a[1];
    retVal <<= 8;
    retVal += a[2];
    retVal <<= 8;
    retVal += a[3];
    return retVal;
}
#endif   // INLINE_FUNCTIONS
#ifndef INLINE_FUNCTIONS
UINT64
ByteArrayToUint64(
    BYTE *a
)
{
    UINT64 retVal;
    retVal = a[0];
    retVal <<= 8;
    retVal += a[1];
    retVal <<= 8;
    retVal += a[2];
    retVal <<= 8;
    retVal += a[3];
    retVal <<= 8;
    retVal += a[4];
    retVal <<= 8;
    retVal += a[5];
    retVal <<= 8;
    retVal += a[6];
    retVal <<= 8;
    retVal += a[7];
    return retVal;
}
#endif   // INLINE_FUNCTIONS
