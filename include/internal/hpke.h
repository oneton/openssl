/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_INTERNAL_HPKE_H
#define OPENSSL_INTERNAL_HPKE_H
#pragma once

#include <openssl/hpke.h>
#include "hpke_util.h"

/**
 * @brief sender or receiver context
 */
struct ossl_hpke_ctx_st {
    OSSL_LIB_CTX *libctx; /* library context */
    char *propq; /* properties */
    int mode; /* HPKE mode */
    OSSL_HPKE_SUITE suite; /* suite */
    const OSSL_HPKE_KEM_INFO *kem_info;
    const OSSL_HPKE_KDF_INFO *kdf_info;
    const OSSL_HPKE_AEAD_INFO *aead_info;
    EVP_CIPHER *aead_ciph;
    int role; /* sender(0) or receiver(1) */
    uint64_t seq; /* aead sequence number */
    unsigned char *shared_secret; /* KEM output, zz */
    size_t shared_secretlen;
    unsigned char *key; /* final aead key */
    size_t keylen;
    unsigned char *nonce; /* aead base nonce */
    size_t noncelen;
    unsigned char *exportersec; /* exporter secret */
    size_t exporterseclen;
    char *pskid; /* PSK stuff */
    unsigned char *psk;
    size_t psklen;
    EVP_PKEY *authpriv; /* sender's authentication private key */
    unsigned char *authpub; /* auth public key */
    size_t authpublen;
    unsigned char *ikme; /* IKM for sender deterministic key gen */
    size_t ikmelen;
};

int ossl_hpke_ctx_get0_shared_secret(const OSSL_HPKE_CTX *ctx,
    unsigned char **out, size_t *outlen);

#endif /* OPENSSL_INTERNAL_HPKE_H */
