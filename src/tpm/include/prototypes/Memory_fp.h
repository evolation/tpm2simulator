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

#ifndef _MEMORY_FP_H_
#define _MEMORY_FP_H_

#ifndef INLINE_FUNCTIONS
void
MemoryCopy(
    void *dest,
    const void *src,
    int sSize
);

#endif     // INLINE_FUNCTIONS
BOOL
MemoryEqual(
    const void *buffer1,              // IN: compare buffer1
    const void *buffer2,              // IN: compare buffer2
    unsigned int size                // IN: size of bytes being compared
);

LIB_EXPORT INT16
MemoryCopy2B(
    TPM2B *dest,               // OUT: receiving TPM2B
    const TPM2B *source,             // IN: source TPM2B
    unsigned int dSize                // IN: size of the receiving buffer
);

void
MemoryConcat2B(
    TPM2B *aInOut,             // IN/OUT: destination 2B
    TPM2B *bIn,                // IN: second 2B
    unsigned int aMaxSize             // IN: The size of aInOut.buffer (max values for
    // aInOut.size)
);

BOOL
MemoryEqual2B(
    const TPM2B *aIn,               // IN: compare value
    const TPM2B *bIn                // IN: compare value
);

#ifndef INLINE_FUNCTIONS
void
MemorySet(
    void *dest,
    int value,
    size_t size
);

#endif     // INLINE_FUNCTIONS
#ifndef INLINE_FUNCTIONS
void
MemoryPad2B(
    TPM2B *b,
    UINT16 newSize
);

#endif     // INLINE_FUNCTIONS
#ifndef INLINE_FUNCTIONS
void
Uint16ToByteArray(
    UINT16 i,
    BYTE *a
);

#endif    // INLINE_FUNCTIONS
#ifndef INLINE_FUNCTIONS
void
Uint32ToByteArray(
    UINT32 i,
    BYTE *a
);

#endif    // INLINE_FUNCTIONS
#ifndef INLINE_FUNCTIONS
void
Uint64ToByteArray(
    UINT64 i,
    BYTE *a
);

#endif    // INLINE_FUNCTIONS
#ifndef INLINE_FUNCTIONS
UINT16
ByteArrayToUint16(
    BYTE *a
);

#endif   // INLINE_FUNCTIONS
#ifndef INLINE_FUNCTIONS
UINT32
ByteArrayToUint32(
    BYTE *a
);

#endif   // INLINE_FUNCTIONS
#ifndef INLINE_FUNCTIONS
UINT64
ByteArrayToUint64(
    BYTE *a
);

#endif   // INLINE_FUNCTIONS
#endif  // _MEMORY_FP_H_
