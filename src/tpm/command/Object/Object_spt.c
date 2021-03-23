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

// 7.6.1 Includes
#include "Tpm.h"
#include "Object_spt_fp.h"
static UINT16
GetIV2BSize(
    OBJECT *protector                 // IN: the protector handle
)
{
    TPM_ALG_ID symAlg;
    UINT16 keyBits;
    // Determine the symmetric algorithm and size of key
    if(protector == NULL)
    {
        // Use the context encryption algorithm and key size
        symAlg = CONTEXT_ENCRYPT_ALG;
        keyBits = CONTEXT_ENCRYPT_KEY_BITS;
    }
    else
    {
        symAlg = protector->publicArea.parameters.asymDetail.symmetric.algorithm;
        keyBits = protector->publicArea.parameters.asymDetail.symmetric.keyBits.sym;
    }
    // The IV size is a UINT16 size field plus the block size of the symmetric
    // algorithm
    return sizeof(UINT16) + CryptGetSymmetricBlockSize(symAlg, keyBits);
}
static void
ComputeProtectionKeyParms(
    OBJECT *protector,                // IN: the protector object
    TPM_ALG_ID hashAlg,                // IN: hash algorithm for KDFa
    TPM2B *name,                     // IN: name of the object
    TPM2B *seedIn,                   // IN: optional seed for duplication blob.
    // For non duplication blob, this
    // parameter should be NULL
    TPM_ALG_ID *symAlg,                   // OUT: the symmetric algorithm
    UINT16 *keyBits,                  // OUT: the symmetric key size in bits
    TPM2B_SYM_KEY *symKey                    // OUT: the symmetric key
)
{
    const TPM2B *seed = seedIn;
    // Determine the algorithms for the KDF and the encryption/decryption
    // For TPM_RH_NULL, using context settings
    if(protector == NULL)
    {
        // Use the context encryption algorithm and key size
        *symAlg = CONTEXT_ENCRYPT_ALG;
        symKey->t.size = CONTEXT_ENCRYPT_KEY_BYTES;
        *keyBits = CONTEXT_ENCRYPT_KEY_BITS;
    }
    else
    {
        TPMT_SYM_DEF_OBJECT *symDef;
        symDef = &protector->publicArea.parameters.asymDetail.symmetric;
        *symAlg = symDef->algorithm;
        *keyBits = symDef->keyBits.sym;
        symKey->t.size = (*keyBits + 7)  / 8;
    }
    // Get seed for KDF
    if(seed == NULL)
        seed = GetSeedForKDF(protector);
    // KDFa to generate symmetric key and IV value
    CryptKDFa(hashAlg, seed, STORAGE_KEY, name, NULL,
              symKey->t.size * 8, symKey->t.buffer, NULL, FALSE);
    return;
}
static void
ComputeOuterIntegrity(
    TPM2B *name,                            // IN: the name of the object
    OBJECT *protector,                       // IN: the object that
    // provides protection. For an object,
    // it is a parent. For a credential, it
    // is the encrypt object. For
    // a Temporary Object, it is NULL
    TPMI_ALG_HASH hashAlg,                          // IN: algorithm to use for integrity
    TPM2B *seedIn,                          // IN: an external seed may be provided for
    // duplication blob. For non duplication
    // blob, this parameter should be NULL
    UINT32 sensitiveSize,                    // IN: size of the marshaled sensitive data
    BYTE *sensitiveData,                   // IN: sensitive area
    TPM2B_DIGEST *integrity                        // OUT: integrity
)
{
    HMAC_STATE hmacState;
    TPM2B_DIGEST hmacKey;
    const TPM2B *seed = seedIn;
//
    // Get seed for KDF
    if(seed == NULL)
        seed = GetSeedForKDF(protector);
    // Determine the HMAC key bits
    hmacKey.t.size = CryptHashGetDigestSize(hashAlg);
    // KDFa to generate HMAC key
    CryptKDFa(hashAlg, seed, INTEGRITY_KEY, NULL, NULL,
              hmacKey.t.size * 8, hmacKey.t.buffer, NULL, FALSE);
    // Start HMAC and get the size of the digest which will become the integrity
    integrity->t.size = CryptHmacStart2B(&hmacState, hashAlg, &hmacKey.b);
    // Adding the marshaled sensitive area to the integrity value
    CryptDigestUpdate(&hmacState.hashState, sensitiveSize, sensitiveData);
    // Adding name
    CryptDigestUpdate2B(&hmacState.hashState, name);
    // Compute HMAC
    CryptHmacEnd2B(&hmacState, &integrity->b);
    return;
}
static void
ComputeInnerIntegrity(
    TPM_ALG_ID hashAlg,             // IN: hash algorithm for inner wrap
    TPM2B *name,                 // IN: the name of the object
    UINT16 dataSize,            // IN: the size of sensitive data
    BYTE *sensitiveData,        // IN: sensitive data
    TPM2B_DIGEST *integrity             // OUT: inner integrity
)
{
    HASH_STATE hashState;
    // Start hash and get the size of the digest which will become the integrity
    integrity->t.size = CryptHashStart(&hashState, hashAlg);
    // Adding the marshaled sensitive area to the integrity value
    CryptDigestUpdate(&hashState, dataSize, sensitiveData);
    // Adding name
    CryptDigestUpdate2B(&hashState, name);
    // Compute hash
    CryptHashEnd2B(&hashState, &integrity->b);
    return;
}
static UINT16
ProduceInnerIntegrity(
    TPM2B *name,                 // IN: the name of the object
    TPM_ALG_ID hashAlg,             // IN: hash algorithm for inner wrap
    UINT16 dataSize,            // IN: the size of sensitive data, excluding the
    // leading integrity buffer size
    BYTE *innerBuffer           // IN/OUT: inner buffer with sensitive data in
    // it. At input, the leading bytes of this
    // buffer is reserved for integrity
)
{
    BYTE *sensitiveData;        // pointer to the sensitive data
    TPM2B_DIGEST integrity;
    UINT16 integritySize;
    BYTE *buffer;               // Auxiliary buffer pointer
    // sensitiveData points to the beginning of sensitive data in innerBuffer
    integritySize = sizeof(UINT16) + CryptHashGetDigestSize(hashAlg);
    sensitiveData = innerBuffer + integritySize;
    ComputeInnerIntegrity(hashAlg, name, dataSize, sensitiveData, &integrity);
    // Add integrity at the beginning of inner buffer
    buffer = innerBuffer;
    TPM2B_DIGEST_Marshal(&integrity, &buffer, NULL);
    return dataSize + integritySize;
}

// E r
// M e
// TPM_RC_INTEGRITY
// unmarshal errors

static TPM_RC
CheckInnerIntegrity(
    TPM2B *name,                 // IN: the name of the object
    TPM_ALG_ID hashAlg,            // IN: hash algorithm for inner wrap
    UINT16 dataSize,           // IN: the size of sensitive data, including the
    // leading integrity buffer size
    BYTE *innerBuffer           // IN/OUT: inner buffer with sensitive data in
    // it
)
{
    TPM_RC result;
    TPM2B_DIGEST integrity;
    TPM2B_DIGEST integrityToCompare;
    BYTE *buffer;                           // Auxiliary buffer pointer
    INT32 size;
    // Unmarshal integrity
    buffer = innerBuffer;
    size = (INT32)dataSize;
    result = TPM2B_DIGEST_Unmarshal(&integrity, &buffer, &size);
    if(result == TPM_RC_SUCCESS)
    {
        // Compute integrity to compare
        ComputeInnerIntegrity(hashAlg, name, (UINT16)size, buffer,
                              &integrityToCompare);
        // Compare outer blob integrity
        if(!MemoryEqual2B(&integrity.b, &integrityToCompare.b))
            result = TPM_RC_INTEGRITY;
    }
    return result;
}
BOOL
AdjustAuthSize(
    TPM2B_AUTH *auth,                  // IN/OUT: value to adjust
    TPMI_ALG_HASH nameAlg                 // IN:
)
{
    UINT16 digestSize;
    // If there is no nameAlg, then this is a LoadExternal and the authVale can
    // be any size up to the maximum allowed by the
    digestSize = (nameAlg == TPM_ALG_NULL) ? sizeof(TPMU_HA)
                 : CryptHashGetDigestSize(nameAlg);
    if(digestSize < MemoryRemoveTrailingZeros(auth))
        return FALSE;
    else if(digestSize > auth->t.size)
        MemoryPad2B(&auth->b, digestSize);
    auth->t.size = digestSize;
    return TRUE;
}
BOOL
ObjectIsParent(
    OBJECT *parentObject              // IN: parent handle
)
{
    return parentObject->attributes.isParent;
}

// E r
// M e
// TPM_RC_ATTRIBUTES
// other

TPM_RC
CreateChecks(
    OBJECT *parentObject,
    TPMT_PUBLIC *publicArea
)
{
    TPMA_OBJECT attributes = publicArea->objectAttributes;
    TPM_RC result = TPM_RC_SUCCESS;
    switch(publicArea->type)
    {
    case TPM_ALG_SYMCIPHER:
        // A restricted key must have sensitiveDataOrigin SET unless it has
        // fixedParent and fixedTPM CLEAR.
        if(attributes.restricted)
            if(!attributes.sensitiveDataOrigin)
                if(attributes.fixedParent || attributes.fixedTPM)
                    result = TPM_RCS_ATTRIBUTES;
        break;
    case TPM_ALG_KEYEDHASH:
        // if this is a data object (sign == decrypt == CLEAR) then the
        // TPM cannot be the data source.
        if(!attributes.sign && !attributes.decrypt
                && attributes.sensitiveDataOrigin)
            result = TPM_RC_ATTRIBUTES;
        break;
    default:      // Asymmetric keys cannot have the sensitive portion provided
        if(!attributes.sensitiveDataOrigin)
            result = TPM_RCS_ATTRIBUTES;
        break;
    }
    if(TPM_RC_SUCCESS == result)
    {
        result = PublicAttributesValidation(parentObject, publicArea);
    }
    return result;
}
TPM_RC
SchemeChecks(
    OBJECT *parentObject,          // IN: parent (null if primary seed)
    TPMT_PUBLIC *publicArea             // IN: public area of the object
)
{
    TPMT_SYM_DEF_OBJECT *symAlgs = NULL;
    TPM_ALG_ID scheme = TPM_ALG_NULL;
    TPMA_OBJECT attributes = publicArea->objectAttributes;
    TPMU_PUBLIC_PARMS *parms = &publicArea->parameters;
    switch(publicArea->type)
    {
    case TPM_ALG_SYMCIPHER:
        symAlgs = &parms->symDetail.sym;
        break;
    case TPM_ALG_KEYEDHASH:
        scheme = parms->keyedHashDetail.scheme.scheme;
        // if both sign and decrypt
        if(attributes.sign == attributes.decrypt)
        {
            // if both sign and decrypt are set or clear, then need
            // TPM_ALG_NULL as scheme
            if(scheme != TPM_ALG_NULL)
                return TPM_RCS_SCHEME;
        }
        else if(attributes.sign && scheme != TPM_ALG_HMAC)
            return TPM_RCS_SCHEME;
        else if(attributes.decrypt)
        {
            if(scheme != TPM_ALG_XOR)
                return TPM_RCS_SCHEME;
            // If this is a derivation parent, then the KDF needs to be
            // SP800-108 for this implementation. This is the only derivation
            // supported by this implementation. Other implementations could
            // support additional schemes. There is no default.
            if(attributes.restricted)
            {
                if(parms->keyedHashDetail.scheme.details.xor.kdf
                        != TPM_ALG_KDF1_SP800_108)
                    return TPM_RCS_SCHEME;
                // Must select a digest.
                if(CryptHashGetDigestSize(
                            parms->keyedHashDetail.scheme.details.xor.hashAlg) == 0)
                    return TPM_RCS_HASH;
            }
        }
        break;
    default:               // handling for asymmetric
        scheme = parms->asymDetail.scheme.scheme;
        symAlgs = &parms->asymDetail.symmetric;
        // if the key is both sign and decrypt, then the scheme must be
        // TPM_ALG_NULL because there is no way to specify both a sign and a
        // decrypt scheme in the key.
        if(attributes.sign == attributes.decrypt)
        {
            // scheme must be TPM_ALG_NULL
            if(scheme != TPM_ALG_NULL)
                return TPM_RCS_SCHEME;
        }
        else if(attributes.sign)
        {
            // If this is a signing key, see if it has a signing scheme
            if(CryptIsAsymSignScheme(publicArea->type, scheme))
            {
                // if proper signing scheme then it needs a proper hash
                if(parms->asymDetail.scheme.details.anySig.hashAlg
                        == TPM_ALG_NULL)
                    return TPM_RCS_SCHEME;
            }
            else
            {
                // signing key that does not have a proper signing scheme.
                // This is OK if the key is not restricted and its scheme
                // is TPM_ALG_NULL
                if(attributes.restricted || scheme != TPM_ALG_NULL)
                    return TPM_RCS_SCHEME;
            }
        }
        else if(attributes.decrypt)
        {
            if(attributes.restricted)
            {
                // for a restricted decryption key (a parent), scheme
                // is required to be TPM_ALG_NULL
                if(scheme != TPM_ALG_NULL)
                    return TPM_RCS_SCHEME;
            }
            else
            {
                // For an unrestricted decryption key, the scheme has to
                // be a valid scheme or TPM_ALG_NULL
                if(scheme != TPM_ALG_NULL &&
                        !CryptIsAsymDecryptScheme(publicArea->type, scheme))
                    return TPM_RCS_SCHEME;
            }
        }
        if(!attributes.restricted || !attributes.decrypt)
        {
            // For an asymmetric key that is not a parent, the symmetric
            // algorithms must be TPM_ALG_NULL
            if(symAlgs->algorithm != TPM_ALG_NULL)
                return TPM_RCS_SYMMETRIC;
        }
        // Special checks for an ECC key
#ifdef TPM_ALG_ECC
        if(publicArea->type == TPM_ALG_ECC)
        {
            TPM_ECC_CURVE curveID;
            const TPMT_ECC_SCHEME *curveScheme;
            curveID = publicArea->parameters.eccDetail.curveID;
            curveScheme = CryptGetCurveSignScheme(curveID);
            // The curveId must be valid or the unmarshaling is busted.
            pAssert(curveScheme != NULL);
            // If the curveID requires a specific scheme, then the key must
            // select the same scheme
            if(curveScheme->scheme != TPM_ALG_NULL)
            {
                TPMS_ECC_PARMS *ecc = &publicArea->parameters.eccDetail;
                if(scheme != curveScheme->scheme)
                    return TPM_RCS_SCHEME;
                // The scheme can allow any hash, or not...
                if(curveScheme->details.anySig.hashAlg != TPM_ALG_NULL
                        && (ecc->scheme.details.anySig.hashAlg
                            != curveScheme->details.anySig.hashAlg))
                    return TPM_RCS_SCHEME;
            }
            // For now, the KDF must be TPM_ALG_NULL
            if(publicArea->parameters.eccDetail.kdf.scheme != TPM_ALG_NULL)
                return TPM_RCS_KDF;
        }
#endif
        break;
    }
    // If this is a restricted decryption key with symmetric algorithms, then it
    // is an ordinary parent (not a derivation parent). It needs to specific
    // symmetric algorithms other than TPM_ALG_NULL
    if(symAlgs != NULL && attributes.restricted && attributes.decrypt)
    {
        if(symAlgs->algorithm == TPM_ALG_NULL)
            return TPM_RCS_SYMMETRIC;
        // If this parent is not duplicable, then the symmetric algorithms
        // (encryption and hash) must match those of its parent
        if(attributes.fixedParent && (parentObject != NULL))
        {
            if(publicArea->nameAlg != parentObject->publicArea.nameAlg)
                return TPM_RCS_HASH;
            if(!MemoryEqual(symAlgs, &parentObject->publicArea.parameters,
                            sizeof(TPMT_SYM_DEF_OBJECT)))
                return TPM_RCS_SYMMETRIC;
        }
    }
    return TPM_RC_SUCCESS;
}

// E r
// M e
// TPM_RC_ATTRIBUTES




// TPM_RC_HASH
// TPM_RC_SIZE

// other

TPM_RC
PublicAttributesValidation(
    OBJECT *parentObject,               // IN: input parent object
    TPMT_PUBLIC *publicArea                  // IN: public area of the object
)
{
    TPMA_OBJECT attributes = publicArea->objectAttributes;
    TPMA_OBJECT parentAttributes = {0};
    if(parentObject != NULL)
        parentAttributes = parentObject->publicArea.objectAttributes;
    if(publicArea->nameAlg == TPM_ALG_NULL)
        return TPM_RCS_HASH;
    // If there is an authPolicy, it needs to be the size of the digest produced
    // by the nameAlg of the object
    if((publicArea->authPolicy.t.size != 0
            && (publicArea->authPolicy.t.size
                != CryptHashGetDigestSize(publicArea->nameAlg))))
        return TPM_RCS_SIZE;
    // If the parent is fixedTPM (including a Primary Object) the object must have
    // the same value for fixedTPM and fixedParent
    if(parentObject == NULL || parentAttributes.fixedTPM == SET)
    {
        if(attributes.fixedParent != attributes.fixedTPM)
            return TPM_RCS_ATTRIBUTES;
    }
    else
    {
        // The parent is not fixedTPM so the object can't be fixedTPM
        if(attributes.fixedTPM == SET)
            return TPM_RCS_ATTRIBUTES;
    }
    // See if sign and decrypt are the same
    if(attributes.sign == attributes.decrypt)
    {
        // a restricted key cannot have both SET or both CLEAR
        if(attributes.restricted)
            return TPM_RC_ATTRIBUTES;
        // only a data object may have both sign and decrypt CLEAR
        // BTW, since we know that decrypt==sign, no need to check both
        if(publicArea->type != TPM_ALG_KEYEDHASH && !attributes.sign)
            return TPM_RC_ATTRIBUTES;
    }
    // If the object can't be duplicated (directly or indirectly) then there
    // is no justification for having encryptedDuplication SET
    if(attributes.fixedTPM == SET && attributes.encryptedDuplication == SET)
        return TPM_RCS_ATTRIBUTES;
    // If a parent object has fixedTPM CLEAR, the child must have the
    // same encryptedDuplication value as its parent.
    // Primary objects are considered to have a fixedTPM parent (the seeds).
    if(parentObject != NULL && parentAttributes.fixedTPM == CLEAR)
    {
        if(attributes.encryptedDuplication != parentAttributes.encryptedDuplication)
            return TPM_RCS_ATTRIBUTES;
    }
    // Special checks for derived objects
    if((parentObject != NULL) && (parentObject->attributes.derivation == SET))
    {
        // A derived object has the same settings for fixedTPM as its parent
        if(attributes.fixedTPM != parentAttributes.fixedTPM)
            return TPM_RCS_ATTRIBUTES;
        // A derived object is required to be fixedParent
        if(!attributes.fixedParent)
            return TPM_RCS_ATTRIBUTES;
    }
    return SchemeChecks(parentObject, publicArea);
}
void
FillInCreationData(
    TPMI_DH_OBJECT parentHandle,         // IN: handle of parent
    TPMI_ALG_HASH nameHashAlg,          // IN: name hash algorithm
    TPML_PCR_SELECTION *creationPCR,             // IN: PCR selection
    TPM2B_DATA *outsideData,             // IN: outside data
    TPM2B_CREATION_DATA *outCreation,             // OUT: creation data for output
    TPM2B_DIGEST *creationDigest           // OUT: creation digest
)
{
    BYTE creationBuffer[sizeof(TPMS_CREATION_DATA)];
    BYTE *buffer;
    HASH_STATE hashState;
    // Fill in TPMS_CREATION_DATA in outCreation
    // Compute PCR digest
    PCRComputeCurrentDigest(nameHashAlg, creationPCR,
                            &outCreation->creationData.pcrDigest);
    // Put back PCR selection list
    outCreation->creationData.pcrSelect = *creationPCR;
    // Get locality
    outCreation->creationData.locality
        = LocalityGetAttributes(_plat__LocalityGet());
    outCreation->creationData.parentNameAlg = TPM_ALG_NULL;
    // If the parent is either a primary seed or TPM_ALG_NULL, then the Name
    // and QN of the parent are the parent's handle.
    if(HandleGetType(parentHandle) == TPM_HT_PERMANENT)
    {
        buffer = &outCreation->creationData.parentName.t.name[0];
        outCreation->creationData.parentName.t.size =
            TPM_HANDLE_Marshal(&parentHandle, &buffer, NULL);
        // For a primary or temporary object, the parent name (a handle) and the
        // parent's QN are the same
        outCreation->creationData.parentQualifiedName
            = outCreation->creationData.parentName;
    }
    else                    // Regular object
    {
        OBJECT *parentObject = HandleToObject(parentHandle);
        // Set name algorithm
        outCreation->creationData.parentNameAlg =
            parentObject->publicArea.nameAlg;
        // Copy parent name
        outCreation->creationData.parentName = parentObject->name;
        // Copy parent qualified name
        outCreation->creationData.parentQualifiedName =
            parentObject->qualifiedName;
    }
    // Copy outside information
    outCreation->creationData.outsideInfo = *outsideData;
    // Marshal creation data to canonical form
    buffer = creationBuffer;
    outCreation->size = TPMS_CREATION_DATA_Marshal(&outCreation->creationData,
                        &buffer, NULL);
    // Compute hash for creation field in public template
    creationDigest->t.size = CryptHashStart(&hashState, nameHashAlg);
    CryptDigestUpdate(&hashState, outCreation->size, creationBuffer);
    CryptHashEnd2B(&hashState, &creationDigest->b);
    return;
}
const TPM2B *
GetSeedForKDF(
    OBJECT *protector                       // IN: the protector handle
)
{
    // Get seed for encryption key. Use input seed if provided.
    // Otherwise, using protector object's seedValue. TPM_RH_NULL is the only
    // exception that we may not have a loaded object as protector. In such a
    // case, use nullProof as seed.
    if(protector == NULL)
        return &gr.nullProof.b;
    else
        return &protector->sensitive.seedValue.b;
}
UINT16
ProduceOuterWrap(
    OBJECT *protector,               // IN: The handle of the object that provides
    // protection. For object, it is parent
    // handle. For credential, it is the handle
    // of encrypt object.
    TPM2B *name,                           // IN: the name of the object
    TPM_ALG_ID hashAlg,                     // IN: hash algorithm for outer wrap
    TPM2B *seed,                           // IN: an external seed may be provided for
    // duplication blob. For non duplication
    // blob, this parameter should be NULL
    BOOL useIV,                       // IN: indicate if an IV is used
    UINT16 dataSize,                    // IN: the size of sensitive data, excluding the
    // leading integrity buffer size or the
    // optional iv size
    BYTE *outerBuffer                     // IN/OUT: outer buffer with sensitive data in
    // it
)
{
    TPM_ALG_ID symAlg;
    UINT16 keyBits;
    TPM2B_SYM_KEY symKey;
    TPM2B_IV ivRNG;                           // IV from RNG
    TPM2B_IV *iv = NULL;
    UINT16 ivSize = 0;            // size of iv area, including the size field
    BYTE *sensitiveData;                  // pointer to the sensitive data
    TPM2B_DIGEST integrity;
    UINT16 integritySize;
    BYTE *buffer;                         // Auxiliary buffer pointer
    // Compute the beginning of sensitive data. The outer integrity should
    // always exist if this function is called to make an outer wrap
    integritySize = sizeof(UINT16) + CryptHashGetDigestSize(hashAlg);
    sensitiveData = outerBuffer + integritySize;
    // If iv is used, adjust the pointer of sensitive data and add iv before it
    if(useIV)
    {
        ivSize = GetIV2BSize(protector);
        // Generate IV from RNG. The iv data size should be the total IV area
        // size minus the size of size field
        ivRNG.t.size = ivSize - sizeof(UINT16);
        CryptRandomGenerate(ivRNG.t.size, ivRNG.t.buffer);
        // Marshal IV to buffer
        buffer = sensitiveData;
        TPM2B_IV_Marshal(&ivRNG, &buffer, NULL);
        // adjust sensitive data starting after IV area
        sensitiveData += ivSize;
        // Use iv for encryption
        iv = &ivRNG;
    }
    // Compute symmetric key parameters for outer buffer encryption
    ComputeProtectionKeyParms(protector, hashAlg, name, seed,
                              &symAlg, &keyBits, &symKey);
    // Encrypt inner buffer in place
    CryptSymmetricEncrypt(sensitiveData, symAlg, keyBits,
                          symKey.t.buffer, iv, TPM_ALG_CFB, dataSize,
                          sensitiveData);
    // Compute outer integrity. Integrity computation includes the optional IV
    // area
    ComputeOuterIntegrity(name, protector, hashAlg, seed, dataSize + ivSize,
                          outerBuffer + integritySize, &integrity);
    // Add integrity at the beginning of outer buffer
    buffer = outerBuffer;
    TPM2B_DIGEST_Marshal(&integrity, &buffer, NULL);
    // return the total size in outer wrap
    return dataSize + integritySize + ivSize;
}

// E r
// M e
// TPM_RCS_INSUFFICIENT
// TPM_RCS_INTEGRITY
// TPM_RCS_SIZE
// TPM_RCS_VALUE

TPM_RC
UnwrapOuter(
    OBJECT *protector,               // IN: The object that provides
    // protection. For object, it is parent
    // handle. For credential, it is the
    // encrypt object.
    TPM2B *name,                    // IN: the name of the object
    TPM_ALG_ID hashAlg,                  // IN: hash algorithm for outer wrap
    TPM2B *seed,                    // IN: an external seed may be provided for
    // duplication blob. For non duplication
    // blob, this parameter should be NULL.
    BOOL useIV,                    // IN: indicates if an IV is used
    UINT16 dataSize,                 // IN: size of sensitive data in outerBuffer,
    // including the leading integrity buffer
    // size, and an optional iv area
    BYTE *outerBuffer              // IN/OUT: sensitive data
)
{
    TPM_RC result;
    TPM_ALG_ID symAlg = TPM_ALG_NULL;
    TPM2B_SYM_KEY symKey;
    UINT16 keyBits = 0;
    TPM2B_IV ivIn;                         // input IV retrieved from input buffer
    TPM2B_IV *iv = NULL;
    BYTE *sensitiveData;               // pointer to the sensitive data
    TPM2B_DIGEST integrityToCompare;
    TPM2B_DIGEST integrity;
    INT32 size;
    // Unmarshal integrity
    sensitiveData = outerBuffer;
    size = (INT32)dataSize;
    result = TPM2B_DIGEST_Unmarshal(&integrity, &sensitiveData, &size);
    if(result == TPM_RC_SUCCESS)
    {
        // Compute integrity to compare
        ComputeOuterIntegrity(name, protector, hashAlg, seed,
                              (UINT16)size, sensitiveData,
                              &integrityToCompare);
        // Compare outer blob integrity
        if(!MemoryEqual2B(&integrity.b, &integrityToCompare.b))
            return TPM_RCS_INTEGRITY;
        // Get the symmetric algorithm parameters used for encryption
        ComputeProtectionKeyParms(protector, hashAlg, name, seed,
                                  &symAlg, &keyBits, &symKey);
        // Retrieve IV if it is used
        if(useIV)
        {
            result = TPM2B_IV_Unmarshal(&ivIn, &sensitiveData, &size);
            if(result == TPM_RC_SUCCESS)
            {
                // The input iv size for CFB must match the encryption algorithm
                // block size
                if(ivIn.t.size != CryptGetSymmetricBlockSize(symAlg, keyBits))
                    result = TPM_RC_VALUE;
                else
                    iv = &ivIn;
            }
        }
    }
    // If no errors, decrypt private in place. Since this function uses CFB,
    // CryptSymmetricDecrypt() will not return any errors (it may fail but it will
    // not return an error.
    if(result == TPM_RC_SUCCESS)
        CryptSymmetricDecrypt(sensitiveData, symAlg, keyBits,
                              symKey.t.buffer, iv, TPM_ALG_CFB,
                              (UINT16)size, sensitiveData);
    return result;
}
static UINT16
MarshalSensitive(
    BYTE *buffer,                      // OUT: receiving buffer
    TPMT_SENSITIVE *sensitive,                   // IN: the sensitive area to marshal
    TPMI_ALG_HASH nameAlg                       // IN:
)
{
    BYTE *sizeField = buffer;
    UINT16 retVal;
    // Pad the authValue if needed
    MemoryPad2B(&sensitive->authValue.b, CryptHashGetDigestSize(nameAlg));
    buffer += 2;
    // Marshal the structure
    retVal = TPMT_SENSITIVE_Marshal(sensitive, &buffer, NULL);
    // Marshal the size
    retVal = (UINT16)(retVal + UINT16_Marshal(&retVal, &sizeField, NULL));
    return retVal;
}
void
SensitiveToPrivate(
    TPMT_SENSITIVE *sensitive,                 // IN: sensitive structure
    TPM2B *name,                      // IN: the name of the object
    OBJECT *parent,                    // IN: The parent object
    TPM_ALG_ID nameAlg,                    // IN: hash algorithm in public area. This
    // parameter is used when parentHandle is
    // NULL, in which case the object is
    // temporary.
    TPM2B_PRIVATE *outPrivate            // OUT: output private structure
)
{
    BYTE *sensitiveData;            // pointer to the sensitive data
    UINT16 dataSize;                  // data blob size
    TPMI_ALG_HASH hashAlg;                   // hash algorithm for integrity
    UINT16 integritySize;
    UINT16 ivSize;
//
    pAssert(name != NULL && name->size != 0);
    // Find the hash algorithm for integrity computation
    if(parent == NULL)
    {
        // For Temporary Object, using self name algorithm
        hashAlg = nameAlg;
    }
    else
    {
        // Otherwise, using parent's name algorithm
        hashAlg = ObjectGetNameAlg(parent);
    }
    // Starting of sensitive data without wrappers
    sensitiveData = outPrivate->t.buffer;
    // Compute the integrity size
    integritySize = sizeof(UINT16) + CryptHashGetDigestSize(hashAlg);
    // Reserve space for integrity
    sensitiveData += integritySize;
    // Get iv size
    ivSize = GetIV2BSize(parent);
    // Reserve space for iv
    sensitiveData += ivSize;
    // Marshal the sensitive area including authValue size adjustments.
    dataSize = MarshalSensitive(sensitiveData, sensitive, nameAlg);
    //Produce outer wrap, including encryption and HMAC
    outPrivate->t.size = ProduceOuterWrap(parent, name, hashAlg, NULL,
                                          TRUE, dataSize, outPrivate->t.buffer);
    return;
}

// E r
// M e
// TPM_RCS_INTEGRITY
// TPM_RC_SENSITIVE

// TPM_RCS_SIZE
// TPM_RCS_VALUE

TPM_RC
PrivateToSensitive(
    TPM2B *inPrivate,            // IN: input private structure
    TPM2B *name,                 // IN: the name of the object
    OBJECT *parent,                 // IN: parent object
    TPM_ALG_ID nameAlg,                 // IN: hash algorithm in public area. It is
    // passed separately because we only pass
    // name, rather than the whole public area
    // of the object. This parameter is used in
    // the following two cases: 1. primary
    // objects. 2. duplication blob with inner
    // wrap. In other cases, this parameter
    // will be ignored
    TPMT_SENSITIVE *sensitive               // OUT: sensitive structure
)
{
    TPM_RC result;
    BYTE *buffer;
    INT32 size;
    BYTE *sensitiveData;          // pointer to the sensitive data
    UINT16 dataSize;
    UINT16 dataSizeInput;
    TPMI_ALG_HASH hashAlg;                 // hash algorithm for integrity
    UINT16 integritySize;
    UINT16 ivSize;
//
    // Make sure that name is provided
    pAssert(name != NULL && name->size != 0);
    // Find the hash algorithm for integrity computation
    if(parent == NULL)
    {
        // For Temporary Object, using self name algorithm
        hashAlg = nameAlg;
    }
    else
    {
        // Otherwise, using parent's name algorithm
        hashAlg = ObjectGetNameAlg(parent);
    }
    // unwrap outer
    result = UnwrapOuter(parent, name, hashAlg, NULL, TRUE,
                         inPrivate->size, inPrivate->buffer);
    if(result != TPM_RC_SUCCESS)
        return result;
    // Compute the inner integrity size.
    integritySize = sizeof(UINT16) + CryptHashGetDigestSize(hashAlg);
    // Get iv size
    ivSize = GetIV2BSize(parent);
    // The starting of sensitive data and data size without outer wrapper
    sensitiveData = inPrivate->buffer + integritySize + ivSize;
    dataSize = inPrivate->size - integritySize - ivSize;
    // Unmarshal input data size
    buffer = sensitiveData;
    size = (INT32)dataSize;
    result = UINT16_Unmarshal(&dataSizeInput, &buffer, &size);
    if(result == TPM_RC_SUCCESS)
    {
        if((dataSizeInput + sizeof(UINT16)) != dataSize)
            result = TPM_RC_SENSITIVE;
        else
        {
            // Unmarshal sensitive buffer to sensitive structure
            result = TPMT_SENSITIVE_Unmarshal(sensitive, &buffer, &size);
            if(result != TPM_RC_SUCCESS || size != 0)
            {
                result = TPM_RC_SENSITIVE;
            }
        }
    }
    return result;
}
void
SensitiveToDuplicate(
    TPMT_SENSITIVE *sensitive,              // IN: sensitive structure
    TPM2B *name,                   // IN: the name of the object
    OBJECT *parent,                 // IN: The new parent object
    TPM_ALG_ID nameAlg,                 // IN: hash algorithm in public area. It
    // is passed separately because we
    // only pass name, rather than the
    // whole public area of the object.
    TPM2B *seed,                   // IN: the external seed. If external
    // seed is provided with size of 0,
    // no outer wrap should be applied
    // to duplication blob.
    TPMT_SYM_DEF_OBJECT *symDef,                 // IN: Symmetric key definition. If the
    // symmetric key algorithm is NULL,
    // no inner wrap should be applied.
    TPM2B_DATA *innerSymKey,            // IN/OUT: a symmetric key may be
    // provided to encrypt the inner
    // wrap of a duplication blob. May
    // be generated here if needed.
    TPM2B_PRIVATE *outPrivate              // OUT: output private structure
)
{
    BYTE *buffer;                  // Auxiliary buffer pointer
    BYTE *sensitiveData;           // pointer to the sensitive data
    TPMI_ALG_HASH outerHash = TPM_ALG_NULL;// The hash algorithm for outer wrap
    TPMI_ALG_HASH innerHash = TPM_ALG_NULL;// The hash algorithm for inner wrap
    UINT16 dataSize;                 // data blob size
    BOOL doInnerWrap = FALSE;
    BOOL doOuterWrap = FALSE;
//
    // Make sure that name is provided
    pAssert(name != NULL && name->size != 0);
    // Make sure symDef and innerSymKey are not NULL
    pAssert(symDef != NULL && innerSymKey != NULL);
    // Starting of sensitive data without wrappers
    sensitiveData = outPrivate->t.buffer;
    // Find out if inner wrap is required
    if(symDef->algorithm != TPM_ALG_NULL)
    {
        doInnerWrap = TRUE;
        // Use self nameAlg as inner hash algorithm
        innerHash = nameAlg;
        // Adjust sensitive data pointer
        sensitiveData += sizeof(UINT16) + CryptHashGetDigestSize(innerHash);
    }
    // Find out if outer wrap is required
    if(seed->size != 0)
    {
        doOuterWrap = TRUE;
        // Use parent nameAlg as outer hash algorithm
        outerHash = ObjectGetNameAlg(parent);
        // Adjust sensitive data pointer
        sensitiveData += sizeof(UINT16) + CryptHashGetDigestSize(outerHash);
    }
    // Marshal sensitive area, leaving the leading 2 bytes for size
    buffer = sensitiveData + sizeof(UINT16);
    dataSize = TPMT_SENSITIVE_Marshal(sensitive, &buffer, NULL);
    // Adding size before the data area
    buffer = sensitiveData;
    UINT16_Marshal(&dataSize, &buffer, NULL);
    // Adjust the dataSize to include the size field
    dataSize += sizeof(UINT16);
    dataSize = MarshalSensitive(sensitiveData, sensitive, nameAlg);
    // Apply inner wrap for duplication blob. It includes both integrity and
    // encryption
    if(doInnerWrap)
    {
        BYTE *innerBuffer = NULL;
        BOOL symKeyInput = TRUE;
        innerBuffer = outPrivate->t.buffer;
        // Skip outer integrity space
        if(doOuterWrap)
            innerBuffer += sizeof(UINT16) + CryptHashGetDigestSize(outerHash);
        dataSize = ProduceInnerIntegrity(name, innerHash, dataSize,
                                         innerBuffer);
        // Generate inner encryption key if needed
        if(innerSymKey->t.size == 0)
        {
            innerSymKey->t.size = (symDef->keyBits.sym + 7)   / 8;
            CryptRandomGenerate(innerSymKey->t.size, innerSymKey->t.buffer);
            // TPM generates symmetric encryption. Set the flag to FALSE
            symKeyInput = FALSE;
        }
        else
        {
            // assume the input key size should matches the symmetric definition
            pAssert(innerSymKey->t.size == (symDef->keyBits.sym + 7)  / 8);
        }
        // Encrypt inner buffer in place
        CryptSymmetricEncrypt(innerBuffer, symDef->algorithm,
                              symDef->keyBits.sym, innerSymKey->t.buffer, NULL,
                              TPM_ALG_CFB, dataSize, innerBuffer);
        // If the symmetric encryption key is imported, clear the buffer for
        // output
        if(symKeyInput)
            innerSymKey->t.size = 0;
    }
    // Apply outer wrap for duplication blob. It includes both integrity and
    // encryption
    if(doOuterWrap)
    {
        dataSize = ProduceOuterWrap(parent, name, outerHash, seed, FALSE,
                                    dataSize, outPrivate->t.buffer);
    }
    // Data size for output
    outPrivate->t.size = dataSize;
    return;
}

// E r
// M e
// TPM_RC_INSUFFICIENT
// TPM_RC_INTEGRITY
// TPM_RC_SIZE

TPM_RC
DuplicateToSensitive(
    TPM2B *inPrivate,             // IN: input private structure
    TPM2B *name,                  // IN: the name of the object
    OBJECT *parent,                // IN: the parent
    TPM_ALG_ID nameAlg,                // IN: hash algorithm in public area.
    TPM2B *seed,                  // IN: an external seed may be provided.
    // If external seed is provided with
    // size of 0, no outer wrap is
    // applied
    TPMT_SYM_DEF_OBJECT *symDef,                // IN: Symmetric key definition. If the
    // symmetric key algorithm is NULL,
    // no inner wrap is applied
    TPM2B *innerSymKey,           // IN: a symmetric key may be provided
    // to decrypt the inner wrap of a
    // duplication blob.
    TPMT_SENSITIVE *sensitive              // OUT: sensitive structure
)
{
    TPM_RC result;
    BYTE *buffer;
    INT32 size;
    BYTE *sensitiveData;         // pointer to the sensitive data
    UINT16 dataSize;
    UINT16 dataSizeInput;
    // Make sure that name is provided
    pAssert(name != NULL && name->size != 0);
    // Make sure symDef and innerSymKey are not NULL
    pAssert(symDef != NULL && innerSymKey != NULL);
    // Starting of sensitive data
    sensitiveData = inPrivate->buffer;
    dataSize = inPrivate->size;
    // Find out if outer wrap is applied
    if(seed->size != 0)
    {
        // Use parent nameAlg as outer hash algorithm
        TPMI_ALG_HASH outerHash = parent->publicArea.nameAlg;
        result = UnwrapOuter(parent, name, outerHash, seed, FALSE,
                             dataSize, sensitiveData);
        if(result != TPM_RC_SUCCESS)
            return result;
        // Adjust sensitive data pointer and size
        sensitiveData += sizeof(UINT16) + CryptHashGetDigestSize(outerHash);
        dataSize -= sizeof(UINT16) + CryptHashGetDigestSize(outerHash);
    }
    // Find out if inner wrap is applied
    if(symDef->algorithm != TPM_ALG_NULL)
    {
        // assume the input key size matches the symmetric definition
        pAssert(innerSymKey->size == (symDef->keyBits.sym + 7)    / 8);
        // Decrypt inner buffer in place
        CryptSymmetricDecrypt(sensitiveData, symDef->algorithm,
                              symDef->keyBits.sym, innerSymKey->buffer, NULL,
                              TPM_ALG_CFB, dataSize, sensitiveData);
        // Check inner integrity
        result = CheckInnerIntegrity(name, nameAlg, dataSize, sensitiveData);
        if(result != TPM_RC_SUCCESS)
            return result;
        // Adjust sensitive data pointer and size
        sensitiveData += sizeof(UINT16) + CryptHashGetDigestSize(nameAlg);
        dataSize -= sizeof(UINT16) + CryptHashGetDigestSize(nameAlg);
    }
    // Unmarshal input data size
    buffer = sensitiveData;
    size = (INT32)dataSize;
    result = UINT16_Unmarshal(&dataSizeInput, &buffer, &size);
    if(result == TPM_RC_SUCCESS)
    {
        if((dataSizeInput + sizeof(UINT16)) != dataSize)
            result = TPM_RC_SIZE;
        else
        {
            // Unmarshal sensitive buffer to sensitive structure
            result = TPMT_SENSITIVE_Unmarshal(sensitive, &buffer, &size);
            // if the results is OK make sure that all the data was unmarshaled
            if(result == TPM_RC_SUCCESS && size != 0)
                result = TPM_RC_SIZE;
        }
    }
    return result;
}
void
SecretToCredential(
    TPM2B_DIGEST *secret,                   // IN: secret information
    TPM2B *name,                     // IN: the name of the object
    TPM2B *seed,                     // IN: an external seed.
    OBJECT *protector,                // IN: the protector
    TPM2B_ID_OBJECT *outIDObject               // OUT: output credential
)
{
    BYTE *buffer;                   // Auxiliary buffer pointer
    BYTE *sensitiveData;            // pointer to the sensitive data
    TPMI_ALG_HASH outerHash;                 // The hash algorithm for outer wrap
    UINT16 dataSize;                  // data blob size
    pAssert(secret != NULL && outIDObject != NULL);
    // use protector's name algorithm as outer hash
    outerHash = ObjectGetNameAlg(protector);
    // Marshal secret area to credential buffer, leave space for integrity
    sensitiveData = outIDObject->t.credential
                    + sizeof(UINT16) + CryptHashGetDigestSize(outerHash);
// Marshal secret area
    buffer = sensitiveData;
    dataSize = TPM2B_DIGEST_Marshal(secret, &buffer, NULL);
    // Apply outer wrap
    outIDObject->t.size = ProduceOuterWrap(protector,
                                           name,
                                           outerHash,
                                           seed,
                                           FALSE,
                                           dataSize,
                                           outIDObject->t.credential);
    return;
}

// E r
// M e
// TPM_RC_INSUFFICIENT
// TPM_RC_INTEGRITY
// TPM_RC_SIZE
// TPM_RC_VALUE

TPM_RC
CredentialToSecret(
    TPM2B *inIDObject,         // IN: input credential blob
    TPM2B *name,               // IN: the name of the object
    TPM2B *seed,               // IN: an external seed.
    OBJECT *protector,          // IN: the protector
    TPM2B_DIGEST *secret              // OUT: secret information
)
{
    TPM_RC result;
    BYTE *buffer;
    INT32 size;
    TPMI_ALG_HASH outerHash;           // The hash algorithm for outer wrap
    BYTE *sensitiveData;      // pointer to the sensitive data
    UINT16 dataSize;
    // use protector's name algorithm as outer hash
    outerHash = ObjectGetNameAlg(protector);
    // Unwrap outer, a TPM_RC_INTEGRITY error may be returned at this point
    result = UnwrapOuter(protector, name, outerHash, seed, FALSE,
                         inIDObject->size, inIDObject->buffer);
    if(result == TPM_RC_SUCCESS)
    {
        // Compute the beginning of sensitive data
        sensitiveData = inIDObject->buffer
                        + sizeof(UINT16) + CryptHashGetDigestSize(outerHash);
        dataSize = inIDObject->size
                   - (sizeof(UINT16) + CryptHashGetDigestSize(outerHash));
        // Unmarshal secret buffer to TPM2B_DIGEST structure
        buffer = sensitiveData;
        size = (INT32)dataSize;
        result = TPM2B_DIGEST_Unmarshal(secret, &buffer, &size);
        // If there were no other unmarshaling errors, make sure that the
        // expected amount of data was recovered
        if(result == TPM_RC_SUCCESS && size != 0)
            return TPM_RC_SIZE;
    }
    return result;
}
UINT16
MemoryRemoveTrailingZeros(
    TPM2B_AUTH *auth                       // IN/OUT: value to adjust
)
{
    while((auth->t.size > 0) && (auth->t.buffer[auth->t.size - 1] == 0))
        auth->t.size--;
    return auth->t.size;
}
TPM_RC
SetLabelAndContext(
    TPMT_PUBLIC *publicArea,             // IN/OUT: the public area containing
    // the unmarshaled template
    TPM2B_SENSITIVE_DATA *sensitive               // IN: the sensitive data
)
{
    TPM_RC result;
    INT32 size;
    BYTE *buff;
    TPM2B_LABEL label;
    // Unmarshal a TPMS_DERIVE from the TPM2B_SENSITIVE_DATA buffer
    size = sensitive->t.size;
    // If there is something to unmarshal...
    if(size != 0)
    {
        buff = sensitive->t.buffer;
        result = TPM2B_LABEL_Unmarshal(&label, &buff, &size);
        if(result != TPM_RC_SUCCESS)
            return result;
        // If there is a label in the publicArea, it overrides
        if(publicArea->unique.derive.label.t.size == 0)
            MemoryCopy2B(&publicArea->unique.derive.label.b, &label.b,
                         sizeof(publicArea->unique.derive.label.t.buffer));
        result = TPM2B_LABEL_Unmarshal(&label, &buff, &size);
        if(result != TPM_RC_SUCCESS)
            return result;
        if(publicArea->unique.derive.context.t.size == 0)
            MemoryCopy2B(&publicArea->unique.derive.context.b, &label.b,
                         sizeof(publicArea->unique.derive.context.t.buffer));
    }
    return TPM_RC_SUCCESS;
}
TPM_RC
UnmarshalToPublic(
    TPMT_PUBLIC *tOut,                // OUT: output
    TPM2B_TEMPLATE *tIn,                 // IN:
    BOOL derivation            // IN: indicates if this is for a derivation
)
{
    BYTE *buffer = tIn->t.buffer;
    INT32 size = tIn->t.size;
    TPM_RC result;
//
    // make sure that tOut is zeroed so that there are no remnants from previous
    // uses
    MemorySet(tOut, 0, sizeof(TPMT_PUBLIC));
    // Unmarshal a TPMT_PUBLIC but don't allow a nameAlg of TPM_ALG_NULL
    result = TPMT_PUBLIC_Unmarshal(tOut, &buffer, &size, FALSE);
    if((result == TPM_RC_SUCCESS) && (derivation == TRUE))
    {
#if ALG_ECC
        // If we just unmarshaled an ECC public key, then the label value is in the
        // correct spot but the context value is in the wrong place if the
        // maximum ECC parameter size is larger than 32 bytes. So, move it. This
        if(tOut->type == ALG_ECC_VALUE)
        {
            // This could probably be a direct copy because we are moving data
            // to lower addresses but, just to be safe...
            TPM2B_LABEL context;
            MemoryCopy2B(&context.b, &tOut->unique.ecc.y.b,
                         sizeof(context.t.buffer));
            MemoryCopy2B(&tOut->unique.derive.context.b, &context.b,
                         sizeof(tOut->unique.derive.context.t.buffer));
        }
        else
#endif
            // For object types other than ECC, should have completed unmarshaling
            // with data left in the buffer so try to unmarshal the remainder as a
            // TPM2B_LABEL into the context
            result = TPM2B_LABEL_Unmarshal(&tOut->unique.derive.context,
                                           &buffer, &size);
    }
    return result;
}
void
ObjectSetHierarchy(
    OBJECT *object,
    TPM_HANDLE parentHandle,
    OBJECT *parent
)
{
    if(parent == NULL)
    {
        switch(parentHandle)
        {
        case TPM_RH_ENDORSEMENT:
            object->attributes.epsHierarchy = SET;
            break;
        case TPM_RH_OWNER:
            object->attributes.spsHierarchy = SET;
            break;
        case TPM_RH_PLATFORM:
            object->attributes.ppsHierarchy = SET;
            break;
        default:
            break;
        }
    }
    else
    {
        object->attributes.epsHierarchy = parent->attributes.epsHierarchy;
        object->attributes.spsHierarchy = parent->attributes.spsHierarchy;
        object->attributes.ppsHierarchy = parent->attributes.ppsHierarchy;
    }
}
void
ObjectSetExternal(
    OBJECT *object
)
{
    object->attributes.external = SET;
}
