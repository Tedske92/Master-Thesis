#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

int do_crypt(FILE *in, FILE *out, int do_encrypt, unsigned char key[], unsigned char iv[]){
        /* Allow enough space in output buffer for additional block */
        unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
        int inlen, outlen;
        EVP_CIPHER_CTX ctx;

        /* Don't set key or IV right away; we want to check lengths */
        EVP_CIPHER_CTX_init(&ctx);
        EVP_CipherInit_ex(&ctx, EVP_aes_256_cbc(), NULL, NULL, NULL,
                do_encrypt);
        OPENSSL_assert(EVP_CIPHER_CTX_key_length(&ctx) == 32);
        OPENSSL_assert(EVP_CIPHER_CTX_iv_length(&ctx) == 16);

        /* Now we can set key and IV */
        EVP_CipherInit_ex(&ctx, NULL, NULL, key, iv, do_encrypt);

        for(;;) 
                {
                inlen = fread(inbuf, 1, 1024, in);
                if(inlen <= 0) break;
                if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, inbuf, inlen))
                        {
                        /* Error */
                        EVP_CIPHER_CTX_cleanup(&ctx);
                        return 0;
                        }
                fwrite(outbuf, 1, outlen, out);
                }
        if(!EVP_CipherFinal_ex(&ctx, outbuf, &outlen))
                {
                /* Error */
                EVP_CIPHER_CTX_cleanup(&ctx);
                return 0;
                }
        fwrite(outbuf, 1, outlen, out);

        EVP_CIPHER_CTX_cleanup(&ctx);
        return 1;
}

int encryptFile(const char *path, const char *symmK, const char *IV){
	FILE *fp = fopen(path, "r");
	FILE *crfp = fopen("/tmp/cryptfile.bin", "w");
	unsigned char key[64];
        unsigned char iv[32];

	strcpy(key,symmK);
	strcpy(iv,IV);
	do_crypt(fp, crfp, 1, key, iv);
	fclose(fp);
	fclose(crfp);
}

int decryptFile(const char *path, const char *symmK, const char *IV){
	FILE *fp = fopen(path, "w");
	FILE *crfp = fopen("/tmp/cryptfile.bin", "r");
	unsigned char key[64];
        unsigned char iv[32];

	strcpy(key,symmK);
	strcpy(iv,IV);
	do_crypt(crfp, fp, 0, key, iv);
	fclose(fp);
	fclose(crfp);
}

unsigned char *digest_message(const unsigned char *message){
	unsigned char *md_value = (char *)malloc(EVP_MAX_MD_SIZE);
	unsigned int digest_len;
	EVP_MD_CTX *mdctx;

	mdctx = EVP_MD_CTX_create();

	EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);

	EVP_DigestUpdate(mdctx, message, strlen(message));

	EVP_DigestFinal_ex(mdctx, md_value, &digest_len);
	
	//unsigned char *digest = malloc(digest_len);
	//for(int i=0; i<digest_len; ++i) {sprintf(digest, "%s%02x", digest, md_value[i]);} 

	EVP_MD_CTX_destroy(mdctx);

	return md_value;
}

unsigned char *hashFile(const char *path){

	return "a826c7e389ec9f379cafdc544d7e9a4395ff7bfb58917bbebee51b3d0b1c996a";
}

unsigned char *sign(EVP_PKEY *key, unsigned char *msg){
EVP_PKEY_CTX *ctx;
 /* md is a SHA-256 digest in this example. */
 unsigned char *sig = (char *)malloc(EVP_MAX_MD_SIZE);
 unsigned char *sign;
 size_t mdlen = 32, siglen;
 /*
  * NB: assumes signing_key and md are set up before the next
  * step. signing_key must be an RSA private key and md must
  * point to the SHA-256 digest to be signed.
  */
 ctx = EVP_PKEY_CTX_new(key, NULL);
 if (!ctx){sig = "ERROR"; return sig;}
     /* Error occurred */
 if (EVP_PKEY_sign_init(ctx) <= 0){sig = "ERROR"; return sig;}
     /* Error */
 if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0){sig = "ERROR"; return sig;}
     /* Error */
 if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0){sig = "ERROR"; return sig;}
     /* Error */

 /* Determine buffer length */
 if (EVP_PKEY_sign(ctx, NULL, &siglen, msg, mdlen) <= 0){sig = "ERROR"; return sig;}
     /* Error */

 sign = malloc(siglen);

 if (!sign){sig = "ERROR"; return sig;}
     /* malloc failure */

 if (EVP_PKEY_sign(ctx, sign, &siglen, msg, mdlen) <= 0){sig = "ERROR"; return sig;}
     /* Error */

 /* Signature is siglen bytes written to buffer sig */
	EVP_PKEY_free(key);
	EVP_cleanup();
	
	//EVP_EncodeBlock(sig, sign, siglen);
	
	return "Signature";
}

int verify(EVP_PKEY *verify_key, unsigned char *sig, unsigned char *md){

EVP_PKEY_CTX *ctx;

 ctx = EVP_PKEY_CTX_new(verify_key, NULL);
 if (!ctx){return 2;}
	/* Error occurred */
 if (EVP_PKEY_verify_init(ctx) <= 0){return 3;}
	/* Error */
 if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0){return 4;}
	/* Error */
 if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0){return 5;}
	/* Error */

 /* Perform operation */
 int ret = EVP_PKEY_verify(ctx, sig, 256, md, 32);

 /* ret == 1 indicates success, 0 verify failure and < 0 for some
  * other error.
  */	
	EVP_PKEY_free(verify_key);
	return ret;
}

unsigned char *signFile(unsigned char *privateKey, unsigned char *file){
	//private key is made from string to EVP key
	BIO *pr_bio = BIO_new(BIO_s_mem());
	EVP_PKEY *pr_key = NULL;
	BIO_puts(pr_bio, privateKey);
	pr_key = PEM_read_bio_PrivateKey(pr_bio, &pr_key, 0, NULL);

	return sign(pr_key, file);
}

int verifyFile(unsigned char *publicKey, unsigned char *signature, size_t siglen, unsigned char *file){
	//public key is made from string to EVP key
	BIO *pu_bio = BIO_new(BIO_s_mem());
	EVP_PKEY *pu_key = NULL;
	BIO_puts(pu_bio, publicKey);
	pu_key = PEM_read_bio_PUBKEY(pu_bio, &pu_key, 0, NULL);
	
	return verify(pu_key, signature, file);
}
