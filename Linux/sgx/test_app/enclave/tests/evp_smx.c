/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/ec.h"
#include "openssl/pem.h" /* openssl library */

#ifndef SAFE_FREE
#define SAFE_FREE(ptr, size) do {if (NULL != (ptr)) {memset_s(ptr, size, 0, size); free(ptr); (ptr)=NULL;}} while(0);
#endif

// default sm2_user_id defined by openssl
unsigned char sm2_user_id[] = "1234567812345678";
unsigned int sm2_user_id_len = sizeof(sm2_user_id)-1;

// create key pair including private key and public key
int create_key_pair_sm2(EC_GROUP* ec_group, char** private_key, char** public_key)
{
    int ret = 0;
    EC_KEY *ec_key = NULL;
    BIO *pri_bio = NULL, *pub_bio = NULL;
    size_t pri_len = 0, pub_len = 0;

    do {
        // 1. Create a new EC key
        ec_key = EC_KEY_new();
        if (ec_key == NULL) {
            printf("Error: fail to create a new EC key\n");
            ret = -1;
            break;
        }

        // 2. Set the new EC key's curve
        if (EC_KEY_set_group(ec_key, ec_group) != 1) {
            printf("Error: fail to set the new EC key's curve\n");
            ret = -2;
            break;
        }

        // 3. Generate key pair based on the curve
        if (!EC_KEY_generate_key(ec_key)) {
            printf("Error: fail to generate key pair based on the curve\n");
            ret = -3;
            break;
        }

        // 4. Generate SM2 private key based on the curve
        pri_bio = BIO_new(BIO_s_mem());
        if (pri_bio == NULL) {
            printf("Error: fail to create a BIO for private key\n");
            ret = -4;
            break;			
        }
        if (!PEM_write_bio_ECPrivateKey(pri_bio, ec_key, NULL, NULL, 0, NULL, NULL)) {
            printf("Error: fail to write private key from ec_key to the BIO\n");
            ret = -5;
            break;			
        }
        pri_len = BIO_pending(pri_bio);
        if (pri_len == 0) {
            printf("Error: fail to get size of the BIO for private key\n");
            ret = -6;
            break;				
        }
        *private_key = (char*)malloc(pri_len);
        if (BIO_read(pri_bio, *private_key, pri_len) <= 0) {
            printf("Error: fail to read private key from the BIO\n");
            SAFE_FREE(*private_key, sizeof(*private_key));
            ret = -7;
            break;			
        }
        (*private_key)[pri_len-1] = '\0';

        // 5. Generate SM2 public key based on the curve
        pub_bio = BIO_new(BIO_s_mem());
        if (pub_bio == NULL) {
            printf("Error: fail to create a BIO for public key\n");
            ret = -8;
            break;			
        }
        if (!PEM_write_bio_EC_PUBKEY(pub_bio, ec_key)) {
            printf("Error: fail to write public key from ec_key to the BIO\n");
            ret = -9;
            break;			
        }
        pub_len = BIO_pending(pub_bio);
        if (pub_len == 0) {
            printf("Error: fail to get size of the BIO for public key\n");
            ret = -10;
            break;				
        }
        *public_key = (char*)malloc(pub_len);
        if (BIO_read(pub_bio, *public_key, pub_len) <= 0) {
            printf("Error: fail to read public key from the BIO\n");
            SAFE_FREE(*public_key, sizeof(*public_key));
            ret = -11;
            break;			
        }
        (*public_key)[pub_len-1] = '\0';

    } while(0);

    // 6. Finalize
    EC_KEY_free(ec_key);
    BIO_free_all(pri_bio);
    BIO_free_all(pub_bio);

    return ret;
}

// sign the message
int sign_sm2(const char* private_key, char* data, size_t data_size, unsigned char** signature, size_t* sign_len)
{ 
    int ret = 0;
    BIO *pri_bio = NULL;
    EC_KEY *ec_key = NULL;
    EVP_PKEY* evp_pkey = NULL;
    EVP_MD_CTX *evp_md_ctx = NULL;
    EVP_PKEY_CTX* evp_pkey_ctx = NULL;

    do {
        // 1. Generate EC_KEY from private key 
        pri_bio = BIO_new_mem_buf(private_key, -1);
        ec_key = PEM_read_bio_ECPrivateKey(pri_bio, NULL, NULL, NULL);
        if (ec_key == NULL) {
            printf("Error: fail to generate EC_KEY from private key\n");
            ret = -1;
            break;
        }

        // 2. Modify an EVP_PKEY to use SM2
        evp_pkey = EVP_PKEY_new();
        if (evp_pkey == NULL) {
            printf("Error: fail to create a EVP_PKEY\n");
            ret = -2;
            break;
        }
        if (EVP_PKEY_set1_EC_KEY(evp_pkey, ec_key) != 1) {
            printf("Error: fail to set the EVP_PKEY by EC_KEY\n");
            ret = -3;
            break;
        }
        if (EVP_PKEY_set_alias_type(evp_pkey, EVP_PKEY_SM2) != 1) {
            printf("Error: fail to modify the EVP_PKEY to use SM2\n");
            ret = -4;
            break;
        }

        // 3. Sign
        evp_md_ctx = EVP_MD_CTX_new();
        if (evp_md_ctx == NULL) {
            printf("Error: fail to create a EVP_MD_CTX\n");
            ret = -5;
            break;
        }
        if (EVP_MD_CTX_init(evp_md_ctx) != 1) {
            printf("Error: fail to initialize the EVP_MD_CTX\n");
            ret = -6;
            break;	
        }

        evp_pkey_ctx = EVP_PKEY_CTX_new(evp_pkey, NULL);
        if (evp_pkey_ctx == NULL) {
            printf("Error: fail to create a EVP_PKEY_CTX\n");
            ret = -7;
            break;
        }
        if (EVP_PKEY_CTX_set1_id(evp_pkey_ctx, sm2_user_id, sm2_user_id_len) != 1) {
            printf("Error: fail to set user_id to the EVP_PKEY_CTX\n");
            ret = -8;
            break;
        }
        EVP_MD_CTX_set_pkey_ctx(evp_md_ctx, evp_pkey_ctx);

        if (EVP_DigestSignInit(evp_md_ctx, NULL, EVP_sm3(), NULL, evp_pkey) != 1) {
            printf("Error: fail to initialize digest sign\n");
            ret = -9;
            break;			
        }
        if (EVP_DigestSignUpdate(evp_md_ctx, data, data_size) != 1) {
            printf("Error: fail to update digest sign\n");
            ret = -10;
            break;			
        }
        if (EVP_DigestSignFinal(evp_md_ctx, NULL, sign_len) != 1) {
            printf("Error: fail to finalize digest sign\n");
            ret = -11;
            break;			
        }
        if (EVP_DigestSignFinal(evp_md_ctx, *signature, sign_len) != 1) {
            printf("Error: fail to finalize digest sign\n");
            ret = -12;
            break;			
        }

    } while(0);

    // 4. Finalize
    BIO_free(pri_bio);
    EC_KEY_free(ec_key);
    EVP_PKEY_free(evp_pkey);
    EVP_MD_CTX_free(evp_md_ctx);
    EVP_PKEY_CTX_free(evp_pkey_ctx);

    return ret;
}

// verify the signature
int verify_sm2(const char* public_key, char* data, size_t data_size, unsigned char* signature, size_t sign_len)
{
    int ret = 0;
    BIO *pub_bio = NULL;
    EC_KEY *ec_key = NULL;
    EVP_PKEY* evp_pkey = NULL;
    EVP_MD_CTX *evp_md_ctx = NULL;
    EVP_PKEY_CTX* evp_pkey_ctx = NULL;

    do {
        // 1. Generate EC_KEY from public key 
        pub_bio = BIO_new_mem_buf(public_key, -1);
        ec_key = PEM_read_bio_EC_PUBKEY(pub_bio, NULL, NULL, NULL);
        if (ec_key == NULL) {
            printf("Error: fail to generate EC_KEY from public key \n");
            ret = -1;
            break;
        }

        // 2. Modify an EVP_PKEY to use SM2
        evp_pkey = EVP_PKEY_new();
        if (evp_pkey == NULL) {
            printf("Error: fail to create a EVP_PKEY\n");
            ret = -2;
            break;
        }
        if (EVP_PKEY_set1_EC_KEY(evp_pkey, ec_key) != 1) {
            printf("Error: fail to set the EVP_PKEY by EC_KEY\n");
            ret = -3;
            break;
        }
        if (EVP_PKEY_set_alias_type(evp_pkey, EVP_PKEY_SM2) != 1) {
            printf("Error: fail to modify the EVP_PKEY to use SM2\n");
            ret = -4;
            break;
        }

        // 3. Verify
        evp_md_ctx = EVP_MD_CTX_new();
        if (evp_md_ctx == NULL) {
            printf("Error: fail to create a EVP_MD_CTX\n");
            ret = -5;
            break;
        }
        if (EVP_MD_CTX_init(evp_md_ctx) != 1) {
            printf("Error: fail to initialize the EVP_MD_CTX\n");
            ret = -6;
            break;
        }

        evp_pkey_ctx = EVP_PKEY_CTX_new(evp_pkey, NULL);
        if (evp_pkey_ctx == NULL) {
            printf("Error: fail to create a EVP_PKEY_CTX\n");
            ret = -7;
            break;
        }
        if (EVP_PKEY_CTX_set1_id(evp_pkey_ctx, sm2_user_id, sm2_user_id_len) != 1) {
            printf("Error: fail to set user_id to the EVP_PKEY_CTX\n");
            ret = -8;
            break;
        }
        EVP_MD_CTX_set_pkey_ctx(evp_md_ctx, evp_pkey_ctx);		

        if (EVP_DigestVerifyInit(evp_md_ctx, NULL, EVP_sm3(), NULL, evp_pkey) != 1) {
            printf("Error: fail to intialize digest verify\n");
            ret = -9;
            break;
        }	
        if (EVP_DigestVerifyUpdate(evp_md_ctx, data, data_size) != 1) {
            printf("Error: fail to update digest verify\n");
            ret = -10;
            break; 
        }	
        if (EVP_DigestVerifyFinal(evp_md_ctx, signature, sign_len) != 1) {
            printf("Error: fail to finalize digest verify\n");
            ret = -11;
            break;
        }

    } while(0);

    // 4. Finalize
    BIO_free(pub_bio);	
    EC_KEY_free(ec_key);	
    EVP_PKEY_free(evp_pkey);
    EVP_MD_CTX_free(evp_md_ctx);
    EVP_PKEY_CTX_free(evp_pkey_ctx);

    return ret;
}

/* Signing and verification using ECC context for SM2 */
int ecall_sm2(void)
{
    EC_GROUP *ec_group = NULL;
    char* private_key = NULL;
    char* public_key = NULL;
    char* data = "context need to be signed";
    size_t data_size = strlen(data);
    unsigned char* signature = (unsigned char*)malloc(1024);
    size_t sign_len = 0;
    int ret = 0;

    do {
        // 1. Init
        // Create an EC_GROUP object with a curve specified by SM2 NID
        ec_group = EC_GROUP_new_by_curve_name(NID_sm2);
        if (ec_group == NULL) {
            printf("Error: fail to create an EC_GROUP object for SM2\n");
            ret = -1;
            break;
        }

        // 2. Create key pair
        if (create_key_pair_sm2(ec_group, &private_key, &public_key) != 0) {
            printf("Error: fail to create key pair\n");
            ret = -2;
            break;
        }

        // 3. Sign
        if (sign_sm2(private_key, data, data_size, &signature, &sign_len) != 0) {
            printf("Error: fail to sign\n");
            ret = -3;
            break;
        }

        // 4. Verify
        if (verify_sm2(public_key, data, data_size, signature, sign_len) != 0) {
            printf("Error: fail to verify\n");
            ret = -4;
            break;
        }

    } while(0);

    // 5. Finalize
    EC_GROUP_free(ec_group);
    SAFE_FREE(private_key, sizeof(private_key));
    SAFE_FREE(public_key, sizeof(public_key));
    SAFE_FREE(signature, sizeof(signature));

    return ret;
}

/* Compute a SM3 digest of a message. */
int ecall_sm3(void)
{
    EVP_MD_CTX* evp_ctx = NULL;
    const EVP_MD* sm3_md = NULL;
    unsigned char msg[] = "this is a test message";
    uint8_t hash[32] = "";
    unsigned int hash_len = 0;
    int ret = 0;

    do {
        // 1. Init
        // Initialize a digest context
        evp_ctx = EVP_MD_CTX_new();
        if (evp_ctx == NULL) {
            printf("Error: fail to initialize a digest context\n");
            ret = -1;
            break;
        }

        // Initialize a struct for SM3 digest
        sm3_md = EVP_sm3();
        if (sm3_md == NULL) {
            printf("Error: fail to initialize a struct for SM3 digest\n");
            ret = -2;
            break;
        }

        // Set up the digest context to use the SM3 digest
        if (EVP_DigestInit_ex(evp_ctx, sm3_md, NULL) != 1) {
            printf("Error: fail to set up the digest context to use the SM3 digest\n");
            ret = -3;
            break;
        }

        // 2. Update
        // Hash msg_len bytes of data at msg into SM3 digest context
        if(EVP_DigestUpdate(evp_ctx, msg, strlen((char*)msg)) != 1) {
            printf("Error: fail to hash msg_len bytes of data at msg into SM3 digest context\n");
            ret = -4;
            break;
        }

        // 3. Finalize
        // Retrieve digest value from SM3 digest context and place it in hash
        if ((EVP_DigestFinal_ex(evp_ctx, (unsigned char *)hash, &hash_len) != 1) || (hash_len != 32)) {
            printf("Error: fail to retrieve digest value from SM3 digest context and place it in hash\n");
            ret = -5;
            break;
        }

    } while(0);

    // 4. Clean up and return
    EVP_MD_CTX_free(evp_ctx);
    //this function is not realized in openssl 1.1.1k, but realized in openssl 3.0.0
    //EVP_MD_free(sm3_md);

    return ret;
}

/* SM4 block cipher mode(cbc) of operation. */
int ecall_sm4_cbc(void)
{	
    // Plain text
    unsigned char plainText[16] = { 0xAA,0xAA,0xAA,0xAA,0xBB,0xBB,0xBB,0xBB,0xCC,0xCC,0xCC,0xCC,0xDD,0xDD,0xDD,0xDD };
    // Secret key
    unsigned char key[16] = { 0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10 };
	// Initialization vector for CBC mode
    unsigned char iv[16] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F };

    unsigned char encryptedText[16] = {};
    unsigned char decryptedText[16] = {};

    int len = 0;
    EVP_CIPHER_CTX* evp_ctx = NULL;
    int ret = 0;

    do { 
        // 1. Create and initialize ctx
        if (!(evp_ctx = EVP_CIPHER_CTX_new())) {
            printf("Error: fail to initialize EVP_CIPHER_CTX\n");
            ret = -1;
            break;
        }

        // 2. Initialize encrypt, key and iv
        if (EVP_EncryptInit_ex(evp_ctx, EVP_sm4_cbc(), NULL, (unsigned char*)key, iv) != 1) {
            printf("Error: fail to initialize encrypt, key and iv\n");
            ret = -2;
            break;
        }

        // 3. Encrypt the plaintext and obtain the encrypted output
        if (EVP_EncryptUpdate(evp_ctx, encryptedText, &len, plainText, sizeof(plainText)) != 1) {
            printf("Error: fail to encrypt the plaintext\n");
            ret = -3;
            break;
        }

        // 4. Finalize the encryption
        if (EVP_EncryptFinal_ex(evp_ctx, encryptedText + len, &len) != 1) {
            printf("Error: fail to finalize the encryption\n");
            ret = -4;
            break;
        }

        // 5. Initialize decrypt, key and IV
        if (!EVP_DecryptInit_ex(evp_ctx, EVP_sm4_cbc(), NULL, (unsigned char*)key, iv)) {
            printf("Error: fail to initialize decrypt, key and IV\n");
            ret = -5;
            break;
        }

        // 6. Decrypt the ciphertext and obtain the decrypted output
        if (!EVP_DecryptUpdate(evp_ctx, decryptedText, &len, encryptedText, sizeof(encryptedText))) {
            printf("fail to decrypt the ciphertext\n");
            ret = -6;
            break;
        }

        // 7. Finalize the decryption:
        // If length of decrypted data is integral multiple of 16, do not execute EVP_DecryptFinal_ex(), or it will fail to decrypt
        // - A positive return value indicates success;
        // - Anything else is a failure - the plaintext is not trustworthy.
        if (sizeof(decryptedText) % 16 != 0) {
            if (EVP_DecryptFinal_ex(evp_ctx, decryptedText + len, &len) <= 0) {
                printf("Error: fail to finalize the decryption\n");
                ret = -7;
                break;
            }
        }

        // 8. Compare original and decrypted text
        if (memcmp(plainText, decryptedText, sizeof(plainText)) != 0) {
            printf("Error: original and decrypted text is different\n");
            ret = -8;
            break;
        }

    } while(0);

    // 9. Clean up and return
    EVP_CIPHER_CTX_free(evp_ctx);

    return ret;
}

/* SM4 counter mode(ctr) of operation. */
int ecall_sm4_ctr(void)
{
    // Secret key
    unsigned char key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15";
    // Message to be encrypted
    unsigned char msg[] = "the message to be encrypted";
    // Initial counter
    unsigned char ctr[] = "\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00";

    unsigned char encryptedText[sizeof(msg)];
    unsigned char decryptedText[sizeof(encryptedText)];

    int len = 0;
    EVP_CIPHER_CTX* evp_ctx = NULL;
    int ret = 0;

    do {
        // 1. Create and initialize ctx
        if (!(evp_ctx = EVP_CIPHER_CTX_new())) {
            printf("Error: fail to initialize EVP_CIPHER_CTX\n");
            ret = -1;
            break;
        }

        // 2. Initialize encrypt, key and ctr
        if (EVP_EncryptInit_ex(evp_ctx, EVP_sm4_ctr(), NULL, (unsigned char*)key, ctr) != 1) {
            printf("Error: fail to initialize encrypt, key and ctr\n");
            ret = -2;
            break;
        }

        // 3. Encrypt the plaintext and obtain the encrypted output
        if (EVP_EncryptUpdate(evp_ctx, encryptedText, &len, msg, sizeof(msg)) != 1) {
            printf("Error: fail to encrypt the plaintext\n");
            ret = -3;
            break;
        }

        // 4. Finalize the encryption
        if (EVP_EncryptFinal_ex(evp_ctx, encryptedText + len, &len) != 1) {
            printf("Error: fail to finalize the encryption\n");
            ret = -4;
            break;
        }

        // 5. Initialize decrypt, key and ctr
        if (!EVP_DecryptInit_ex(evp_ctx, EVP_sm4_ctr(), NULL, (unsigned char*)key, ctr)) {
            printf("Error: fail to initialize decrypt, key and ctr\n");
            ret = -5;
            break;
        }

        // 6. Decrypt the ciphertext and obtain the decrypted output
        if (!EVP_DecryptUpdate(evp_ctx, decryptedText, &len, encryptedText, sizeof(encryptedText))) {
            printf("Error: fail to decrypt the ciphertext\n");
            ret = -6;
            break;
        }

        // 7. Finalize the decryption:
        // - A positive return value indicates success;
        // - Anything else is a failure - the msg is not trustworthy.
        if (EVP_DecryptFinal_ex(evp_ctx, decryptedText + len, &len) <= 0) {
            printf("Error: fail to finalize the decryption\n");
            ret = -7;
            break;
        }

        // 8. Compare original and decrypted text
        if (memcmp(msg, decryptedText, sizeof(msg)) != 0) {
            printf("Error: original and decrypted text is different");
            ret = -8;
            break;
        }

    } while(0);

    // 9. Clean up and return
    EVP_CIPHER_CTX_free(evp_ctx);

    return ret;
}
