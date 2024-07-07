//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef WINTLS_DETAIL_SSPI_COMPAT_HPP
#define WINTLS_DETAIL_SSPI_COMPAT_HPP

// for SCH_CREDENTIALS
#ifndef SCHANNEL_USE_BLACKLISTS
#define SCHANNEL_USE_BLACKLISTS
#define WINTLS_SCHANNEL_USE_BLACKLISTS_DEFINED
#endif // SCHANNEL_USE_BLACKLISTS

#include <sdkddkver.h>
#include <SubAuth.h>
#include <schannel.h>

#if (WDK_NTDDI_VERSION < NTDDI_WIN10_19H1)
typedef enum _eTlsAlgorithmUsage
{
    TlsParametersCngAlgUsageKeyExchange,
    TlsParametersCngAlgUsageSignature,
    TlsParametersCngAlgUsageCipher,
    TlsParametersCngAlgUsageDigest,
    TlsParametersCngAlgUsageCertSig
} eTlsAlgorithmUsage;

typedef struct _CRYPTO_SETTINGS
{
    eTlsAlgorithmUsage  eAlgorithmUsage;
    UNICODE_STRING      strCngAlgId;
    DWORD               cChainingModes;
    PUNICODE_STRING     rgstrChainingModes;
    DWORD               dwMinBitLength;
    DWORD               dwMaxBitLength;
} CRYPTO_SETTINGS, * PCRYPTO_SETTINGS;

typedef struct _TLS_PARAMETERS
{
    DWORD               cAlpnIds;
    PUNICODE_STRING     rgstrAlpnIds;
    DWORD               grbitDisabledProtocols;
    DWORD               cDisabledCrypto;
    PCRYPTO_SETTINGS    pDisabledCrypto;
    DWORD               dwFlags;
} TLS_PARAMETERS, * PTLS_PARAMETERS;

typedef struct _SCH_CREDENTIALS
{
    DWORD               dwVersion;
    DWORD               dwCredFormat;
    DWORD               cCreds;
    PCCERT_CONTEXT* paCred;
    HCERTSTORE          hRootStore;

    DWORD               cMappers;
    struct _HMAPPER **aphMappers;

    DWORD               dwSessionLifespan;
    DWORD               dwFlags;
    DWORD               cTlsParameters;
    PTLS_PARAMETERS     pTlsParameters;
} SCH_CREDENTIALS, * PSCH_CREDENTIALS;
#endif // (NTDDI_VERSION < NTDDI_WIN10_19H1)

#ifdef WINTLS_SCHANNEL_USE_BLACKLISTS_DEFINED
#undef SCHANNEL_USE_BLACKLISTS
#endif // WINTLS_SCHANNEL_USE_BLACKLISTS_DEFINED

#endif // WINTLS_DETAIL_SSPI_COMPAT_HPP
