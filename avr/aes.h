/* aes.h */
/*
 This file is part of the AVR-Crypto-Lib.
 Copyright (C) 2008  Daniel Otte (daniel.otte@rub.de)

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
/**
 * \file     aes.h
 * \email    daniel.otte@rub.de
 * \author   Daniel Otte
 * \date     2008-12-30
 * \license  GPLv3 or later
 *
 */
#ifndef AES_H_
#define AES_H_

#include <stdint.h>
#include <stdlib.h>

#include "aes_types.h"
#include "aes128_enc.h"
#include "aes128_dec.h"
#include "aes_keyschedule.h"

#define AES_ENCRYPT     1
#define AES_DECRYPT     0

typedef aes128_ctx_t aes_context;

/* These functions provide the same interface as the generic code, but
 * call the avr-specific asm versions instead (except aes_crypt_ctr,
 * which still just uses the generic implementation). */
inline int aes_setkey_enc( aes_context *ctx, const unsigned char *key, unsigned int keysize ) {
	if (keysize != 128)
		return -1;

	aes128_init(key, ctx);
	return 0;
}

inline int aes_setkey_dec( aes_context *ctx, const unsigned char *key, unsigned int keysize ) {
	aes_setkey_enc( ctx, key, keysize);
}

inline int aes_crypt_ecb( aes_context *ctx,
                    int mode,
                    const unsigned char input[16],
                    unsigned char output[16] ) {

	memcpy(output, input, sizeof(output));
	if (mode == AES_ENCRYPT)
		aes128_enc(output, ctx);
	else
		aes128_dec(output, ctx);
	return 0;
}


inline int aes_crypt_ctr( aes_context *ctx,
                       size_t length,
                       size_t *nc_off,
                       unsigned char nonce_counter[16],
                       unsigned char stream_block[16],
                       const unsigned char *input,
                       unsigned char *output );

#endif
