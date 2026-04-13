
/***************************************************************************
 * Crypto.h -- The Crypto Class contains miscellaneous methods and helpers *
 * that may be used to provide properties such as authentication, integrity*
 * or confidentiality.                                                     *
 *                                                                         *
 ***********************IMPORTANT KMAP LICENSE TERMS************************
 *
 * The Kmap Security Scanner is (C) 1996-2026 Kmap Software LLC ("The Kmap
 * Project"). Kmap is also a registered trademark of the Kmap Project.
 *
 * This program is distributed under the terms of the Kmap Public Source
 * License (NPSL). The exact license text applying to a particular Kmap
 * release or source code control revision is contained in the LICENSE
 * file distributed with that version of Kmap or source code control
 * revision. More Kmap copyright/legal information is available from
 * https://github.com/YurilLAB/Kmap/blob/master/LICENSE, and further information on the
 * NPSL license itself can be found at https://github.com/YurilLAB/Kmap/blob/master/LICENSE . This
 * header summarizes some key points from the Kmap license, but is no
 * substitute for the actual license text.
 *
 * Kmap is generally free for end users to download and use themselves,
 * including commercial use. It is available from https://github.com/YurilLAB/Kmap.
 *
 * The Kmap license generally prohibits companies from using and
 * redistributing Kmap in commercial products, but we sell a special Kmap
 * OEM Edition with a more permissive license and special features for
 * this purpose. See https://github.com/YurilLAB/Kmap
 *
 * If you have received a written Kmap license agreement or contract
 * stating terms other than these (such as an Kmap OEM license), you may
 * choose to use and redistribute Kmap under those terms instead.
 *
 * The official Kmap Windows builds include the Npcap software
 * (https://npcap.com) for packet capture and transmission. It is under
 * separate license terms which forbid redistribution without special
 * permission. So the official Kmap Windows builds may not be redistributed
 * without special permission (such as an Kmap OEM license).
 *
 * Source is provided to this software because we believe users have a
 * right to know exactly what a program is going to do before they run it.
 * This also allows you to audit the software for security holes.
 *
 * Source code also allows you to port Kmap to new platforms, fix bugs, and
 * add new features. You are highly encouraged to submit your changes as a
 * Github PR at https://github.com/YurilLAB/Kmap for possible incorporation
 * into the main distribution. Unless you specify otherwise, it
 * is understood that you are offering us very broad rights to use your
 * submissions as described in the Kmap Public Source License Contributor
 * Agreement. This is important because we fund the project by selling licenses
 * with various terms, and also because the inability to relicense code has
 * caused devastating problems for other Free Software projects (such as KDE
 * and NASM).
 *
 * The free version of Kmap is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
 * indemnification and commercial support are all available through the
 * Kmap project -- see https://github.com/YurilLAB/Kmap
 *
 ***************************************************************************/

#ifndef __CRYPTO_H__
#define __CRYPTO_H__ 1
#include "nping.h"

#define HMAC_SHA256_CODE_LEN 32
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 16
#define SHA256_HASH_LEN 32

class Crypto {

    public:

        Crypto();
        ~Crypto();
        void reset();

        static int hmac_sha256(u8 *inbuff, size_t inlen, u8 *dst_buff, u8 *key, size_t key_len);
        static int aes128_cbc_encrypt(u8 *inbuff, size_t inlen, u8 *dst_buff, u8 *key, size_t key_len, u8 *iv);
        static int aes128_cbc_decrypt(u8 *inbuff, size_t inlen, u8 *dst_buff, u8 *key, size_t key_len, u8 *iv);
        static int generateNonce(u8 *dst_buff, size_t bufflen);
        static u8 *deriveKey(const u8 *from, size_t fromlen, size_t *final_len);
};

#endif /* __CRYPTO_H__ */
