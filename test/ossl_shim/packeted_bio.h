/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_TEST_SHIM_PACKETED_BIO_H
#define OSSL_TEST_SHIM_PACKETED_BIO_H

#include <functional>

#include <openssl/base.h>

#if defined(OPENSSL_WINDOWS)
#include <winsock2.h>
#else
#include <sys/time.h>
#endif


// PacketedBioCreate creates a filter BIO which implements a reliable in-order
// blocking datagram socket. It uses the value of |*clock| as the clock.
//
// During a |BIO_read|, the peer may interrupt the filter BIO to perform
// operations on |ssl|, such as handling timeouts or updating the MTU. In this
// case, the |BIO_read| operation will fail with a retryable error, which should
// be surfaced from |ssl| as |SSL_ERROR_WANT_READ|. The caller must then call
// |PacketedBioHasInterrupt| and |PacketedBioHandleInterrupt| to handle the
// interrupt.
//
// Pending operations are deferred so that they are not triggered reentrantly in
// the middle of an operation on |ssl|.
bssl::UniquePtr<BIO> PacketedBioCreate(timeval *clock, SSL *ssl);

// PacketedBioHasInterrupt returns whether |bio| has a pending interrupt. If it
// returns true, the caller must call |PacketedBioHandleInterrupt| to handle it.
bool PacketedBioHasInterrupt(BIO *bio);

// PacketedBioHandleInterrupt handles the pending interrupt on |bio|. It returns
// true on success, in which case the caller should retry the operation, and
// false on error.
bool PacketedBioHandleInterrupt(BIO *bio);

// PacketedBioAdvanceClock advances the clock by |microseconds| and handles the
// timeout on the |SSL| object. It returns true on success and false on error.
bool PacketedBioAdvanceClock(BIO *bio, uint64_t microseconds);

#endif  // OSSL_TEST_SHIM_PACKETED_BIO_H
