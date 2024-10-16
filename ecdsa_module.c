#include "ecdsa_module.h"
#include <crypto/internal/ecc.h> // 
#include <crypto/ecdh.h> // struct ecdh_ctx

// without asn1 encode/decode, test_key = private_key || pubkey.x || pubkey.y

// nist p-256, without asn1 encode/decode
unsigned int key_len = 96;
u8 test_key[] = "\xc9\xaf\xa9\xd8\x45\xba\x75\x16\x6b"
	"\x5c\x21\x57\x67\xb1\xd6\x93\x4e\x50\xc3\xdb\x36\xe8\x9b\x12\x7b"
	"\x8a\x62\x2b\x12\x0f\x67\x21\x60\xfe\xd4\xba\x25\x5a\x9d"
	"\x31\xc9\x61\xeb\x74\xc6\x35\x6d\x68\xc0\x49\xb8\x92\x3b\x61\xfa"
	"\x6c\xe6\x69\x62\x2e\x60\xf2\x9f\xb6\x79\x03\xfe\x10\x08\xb8\xbc"
	"\x99\xa4\x1a\xe9\xe9\x56\x28\xbc\x64\xf2\xf1\xb2\x0c\x2d\x7e\x9f"
	"\x51\x77\xa3\xc2\x94\xd4\x46\x22\x99"; // for nist p256

// nist p-256, with asn1 encode/decode
unsigned int key_len2 = 121;
u8 test_key2[] = "\x30\x77\x02\x01\x01\x04\x20\xc9\xaf\xa9\xd8\x45\xba\x75\x16\x6b"
	"\x5c\x21\x57\x67\xb1\xd6\x93\x4e\x50\xc3\xdb\x36\xe8\x9b\x12\x7b"
	"\x8a\x62\x2b\x12\x0f\x67\x21\xa0\x0a\x06\x08\x2a\x86\x48\xce\x3d"
	"\x03\x01\x07\xa1\x44\x03\x42\x00\x04\x60\xfe\xd4\xba\x25\x5a\x9d"
	"\x31\xc9\x61\xeb\x74\xc6\x35\x6d\x68\xc0\x49\xb8\x92\x3b\x61\xfa"
	"\x6c\xe6\x69\x62\x2e\x60\xf2\x9f\xb6\x79\x03\xfe\x10\x08\xb8\xbc"
	"\x99\xa4\x1a\xe9\xe9\x56\x28\xbc\x64\xf2\xf1\xb2\x0c\x2d\x7e\x9f"
	"\x51\x77\xa3\xc2\x94\xd4\x46\x22\x99"; // for nist p256


u8 m[] = "\x81\x51\x32\x5d\xcd\xba\xe9\xe0\xff\x95\xf9\xf9\x65\x84\x32\xdb"
	"\xed\xfd\xb2\x09";
unsigned int m_size = 20;

int algo = OID_id_ecdsa_with_sha1;

u8 c[] = "\x30\x44\x02\x20\x61\x34\x0c\x88\xc3\xaa\xeb\xeb\x4f\x6d\x66\x7f"
	"\x67\x2c\xa9\x75\x9a\x6c\xca\xa9\xfa\x88\x11\x31\x30\x39\xee\x4a"
	"\x35\x47\x1d\x32\x02\x20\x6d\x7f\x14\x7d\xac\x08\x94\x41\xbb\x2e"
	"\x2f\xe8\xf7\xa3\xfa\x26\x4b\x9c\x47\x50\x98\xfd\xcf\x6e\x00\xd7"
	"\xc9\x96\xe1\xb8\xb7\xeb";
unsigned int c_size = 70;

u8 *signature_result = NULL;

u8 test_key3[192] = {0}; // generated random_key


// sm2 test vectors
// private key: 0x9A6D6579D2AE5BE7385B17A7658895517AD50FFA64C77F97EC1989B5DEF9E4E0
// public key: 0x85E3CFB5FC7FEA7AAA41C2FEAE66BCC61A03524A5C9B2FDC9DA9C8D65D8D340F 0xFD80A28241EE9707612BA12AA8030DF994BACB98041D44299161AEC8BC2F1BC4
u8 sm2_key[] = "\x9A\x6D\x65\x79\xD2\xAE\x5B\xE7\x38\x5B\x17\xA7\x65\x88\x95\x51\x7A\xD5\x0F\xFA\x64\xC7\x7F\x97\xEC\x19\x89\xB5\xDE\xF9\xE4\xE0"
	"\x85\xE3\xCF\xB5\xFC\x7F\xEA\x7A\xAA\x41\xC2\xFE\xAE\x66\xBC\xC6\x1A\x03\x52\x4A\x5C\x9B\x2F\xDC\x9D\xA9\xC8\xD6\x5D\x8D\x34\x0F\xFD\x80"
	"\xA2\x82\x41\xEE\x97\x07\x61\x2B\xA1\x2A\xA8\x03\x0D\xF9\x94\xBA\xCB\x98\x04\x1D\x44\x29\x91\x61\xAE\xC8\xBC\x2F\x1B\xC4";

struct crypto_akcipher *tfm;


static int init_ctx_setkey_no_asn1(u8 *test_key, int key_len)
{
	u8 *key, *ptr;
	int err = -ENOMEM;

	//tfm = crypto_alloc_akcipher("ecdsa-sm2-generic", 0, 0);
	tfm = crypto_alloc_akcipher("ecdsa-nist-p256-generic", 0, 0);

	key = kmalloc(key_len + sizeof(u32) * 2, GFP_KERNEL);
	if (!key)
		return err;

	memcpy(key, test_key, key_len);
	//ptr = key + key_len;
	//ptr = test_pack_u32(ptr, algo);

	//printk("kmalloc\n");
	
	err = crypto_akcipher_set_key_noasn1(tfm, key, key_len);

	if (err)
		goto free_key;

	//printk("crypto_alloc_akcipher\n");
	
	return err;

free_key:
	kfree(key);
	return err;
}

static int init_ctx_setkey_with_asn1(void)
{
	u8 *key, *ptr;
	int err = -ENOMEM;

	tfm = crypto_alloc_akcipher("ecdsa-sm2-generic", 0, 0);
	//tfm = crypto_alloc_akcipher("ecdsa-nist-p256-generic", 0, 0);

	key = kmalloc(key_len2 + sizeof(u32) * 2, GFP_KERNEL);
	if (!key)
		return err;

	memcpy(key, test_key2, key_len2);
	ptr = key + key_len2;
	ptr = test_pack_u32(ptr, algo);

	//printk("kmalloc\n");
	err = crypto_akcipher_set_priv_key(tfm, key, key_len2);
		
	if (err)
		goto free_key;
	
	//printk("crypto_akcipher_set_priv_key\n");

free_key:
	kfree(key);
	return err;
}

/*

#define ECC_CURVE_NIST_P192	0x0001
#define ECC_CURVE_NIST_P256	0x0002
#define ECC_CURVE_NIST_P384	0x0003
#define ECC_CURVE_SM2	0x0004


#define ECC_CURVE_NIST_P192_DIGITS  3
#define ECC_CURVE_NIST_P256_DIGITS  4
#define ECC_CURVE_NIST_P384_DIGITS  6
#define ECC_CURVE_SM2_DIGITS  4
*/

static int init_ctx_randkey(void)
{
	int err = -ENOMEM;

	tfm = crypto_alloc_akcipher("ecdsa-sm2-generic", 0, 0);
	int curve = ECC_CURVE_SM2;

	//tfm = crypto_alloc_akcipher("ecdsa-nist-p256-generic", 0, 0);
	//int curve = ECC_CURVE_NIST_P256; //ECC_CURVE_SM2


	u64 *priv_key = kmalloc(sizeof(u64) * ECC_CURVE_NIST_P256_DIGITS, GFP_KERNEL); // private_key || pubkey.x || pubkey.y
	if (!priv_key)
		goto free_key;
	u64 *pub_key = kmalloc(sizeof(u64) * ECC_CURVE_NIST_P256_DIGITS * 2, GFP_KERNEL); // private_key || pubkey.x || pubkey.y
	if (!pub_key)
		goto free_key;

	
	// use test keys
	// memcpy(priv_key, test_key, sizeof(u64) * ECC_CURVE_NIST_P256_DIGITS); // p-256 test keys 
	memcpy(priv_key, sm2_key, sizeof(u64) * ECC_CURVE_NIST_P256_DIGITS); // sm2 test keys 

	/*err = ecc_gen_privkey(curve, ECC_CURVE_NIST_P256_DIGITS, priv_key);

	if(err)
		goto free_key;
	
	printk("ecc_gen_privkey\n");*/
	
	

	memcpy(test_key3, priv_key, ECC_CURVE_NIST_P256_DIGITS*sizeof(u64));
	err = ecc_make_pub_key(curve, ECC_CURVE_NIST_P256_DIGITS, priv_key, pub_key);

	if(err)
		goto free_key;
	
	printk("ecc_make_pub_key\n");

	memcpy(test_key3 + ECC_CURVE_NIST_P256_DIGITS*sizeof(u64), pub_key, ECC_CURVE_NIST_P256_DIGITS*sizeof(u64)*2);

	//for(int i = 0; i < key_len; i++)
	//	printk("%02x", test_key3[i]);

	err = crypto_akcipher_set_key_noasn1_rawu64bytes(tfm, test_key3, key_len);
	if(err)
		goto free_key;
	
	printk("crypto_akcipher_set_key_noasn1_rawu64bytes\n");
	

free_key:
	if(priv_key) kfree(priv_key);
	if(pub_key) kfree(pub_key);
	return err;
}

static int sign(void)
{
	char *xbuf[XBUFSIZE];
	struct akcipher_request *req;
	void *outbuf_enc = NULL;
	void *outbuf_dec = NULL;
	
	struct crypto_wait wait;
	unsigned int out_len_max, out_len = 0;
	int err = -ENOMEM;
	struct scatterlist src, dst, src_tab[3];

	const char *op;
	
	if (testmgr_alloc_buf(xbuf))
		return err;
	

	req = akcipher_request_alloc(tfm, GFP_KERNEL);

	//printk("akcipher_request_alloc\n");
	
	if (!req)
		goto free_xbuf;

	crypto_init_wait(&wait);
	
	//printk("crypto_init_wait\n");

	err = -ENOMEM;
	out_len_max = crypto_akcipher_maxsize(tfm);
	outbuf_enc = kzalloc(out_len_max, GFP_KERNEL);
	if (!outbuf_enc)
		goto free_xbuf;

	outbuf_dec = kzalloc(out_len_max, GFP_KERNEL);
	if (!outbuf_dec) {
		err = -ENOMEM;
		goto free_all;
	}
	op = "sign";

	if (WARN_ON(m_size > PAGE_SIZE))
		goto free_all;
	memcpy(xbuf[0], m, m_size);

	sg_init_one(&src, xbuf[0], m_size);
	sg_init_one(&dst, outbuf_dec, out_len_max);
	crypto_init_wait(&wait);
	akcipher_request_set_crypt(req, &src, &dst, m_size, out_len_max);
		
	err = crypto_wait_req(crypto_akcipher_sign(req) , &wait);
	if (err) {
		pr_err("alg: akcipher: %s test failed. err %d\n", op, err);
		goto free_all;
	} else {
		printk("alg: akcipher: %s test passed.\n", op);
	}

	out_len = req->dst_len;

	c_size = out_len;
	if (out_len < c_size) {
		pr_err("alg: akcipher: %s test failed. Invalid output len %u\n",
		       op, out_len);
		err = -EINVAL;
		goto free_all;
	}

	printk("out_len: %d\n", out_len);

	signature_result = kmalloc(c_size, GFP_KERNEL);

	memcpy(signature_result, outbuf_dec + out_len - c_size, c_size);
	
	printk("Output generated signature: ");
	for(int i = 0; i < c_size; i++)
		printk("%d: %02x", i, *(char *)(signature_result + i));
	/*
	if(memcmp(signature_result, c, c_size) == 0)
		printk("signature correct!\n");
	else 
		printk("signature incorrect!\n");*/

	err = 0;
	
free_all:
	kfree(outbuf_dec);
	kfree(outbuf_enc);
	akcipher_request_free(req);
free_xbuf:
	testmgr_free_buf(xbuf);

	return err;
}

static int verify(void)
{
	char *xbuf[XBUFSIZE];
	struct akcipher_request *req;
	void *outbuf_enc = NULL;
	void *outbuf_dec = NULL;
	
	struct crypto_wait wait;
	unsigned int out_len_max, out_len = 0;
	int err = -ENOMEM;
	struct scatterlist src, dst, src_tab[3];

	const char *op;


	if (testmgr_alloc_buf(xbuf))
		return err;

	req = akcipher_request_alloc(tfm, GFP_KERNEL);

	//printk("akcipher_request_alloc\n");
	
	if (!req)
		goto free_xbuf;

	crypto_init_wait(&wait);
	
	//printk("crypto_init_wait\n");

	printk("verify: c_size = %d\n", c_size);

	err = -ENOMEM;
	out_len_max = crypto_akcipher_maxsize(tfm);
	outbuf_enc = kzalloc(out_len_max, GFP_KERNEL);
	if (!outbuf_enc)
		goto free_xbuf;

	op = "verify";
	
	err = -E2BIG;
	if (WARN_ON(c_size > PAGE_SIZE))
		goto free_all;

	// signature_result[0] = 0xa; // for test only: generate wrong signature
	memcpy(xbuf[0], signature_result, c_size); // @zhaoyang, 验证方把签名结果作为输入，由于signature_result和c是一样的，所以这里也可以用c

	sg_init_table(src_tab, 3);
	sg_set_buf(&src_tab[0], xbuf[0], 8);
	sg_set_buf(&src_tab[1], xbuf[0] + 8, c_size - 8);
	
	
	if (WARN_ON(m_size > PAGE_SIZE))
		goto free_all;
	memcpy(xbuf[1], m, m_size);
	sg_set_buf(&src_tab[2], xbuf[1], m_size);
	akcipher_request_set_crypt(req, src_tab, NULL, c_size, m_size);
	
	akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				      crypto_req_done, &wait);

	
	err = crypto_wait_req(crypto_akcipher_verify(req) , &wait);
	if (err) {
		pr_err("alg: akcipher: %s test failed. err %d\n", op, err);
		goto free_all;
	} else {
		printk("alg: akcipher: %s test passed.\n", op);
	}
	
	err = 0;

free_all:
	kfree(outbuf_dec);
	kfree(outbuf_enc);
	akcipher_request_free(req);
free_xbuf:
	testmgr_free_buf(xbuf);

	return err;
}


static int __init ecdsa_kernel_module_init(void)
{
	printk(KERN_INFO "Entering ecdsa_module\n");
	int err = -ENOMEM;

	err = init_ctx_randkey(); // use case 1: init random key
	if(err != 0) {
		printk("Init random key failed: %d.\n", err);
		return err;
	}
	printk("Init random key succeed.\n");

	//if(init_ctx_setkey_no_asn1(test_key, key_len) != 0) // use case 2: init key from key buffer without asn1 decoding
	//if(init_ctx_setkey_no_asn1(sm2_key, key_len) != 0) // use case 2: init key from key buffer without asn1 decoding
	//	return err;
	
	//if(init_ctx_setkey_with_asn1() != 0) //设置密钥，发送方和接收方都需要运行这个函数 // use case 3: init key from key buffer with asn1 decoding
	//	return err;
	
	sign(); // 这个函数产生签名的结果，并存在全局变量signature_result里

	verify(); // @zhaoyang, 注意上边的comment，验证方把签名结果作为输入。若已经运行过sign()，则signature_result和c是一样的；否则应该用c
	
    return 0;
}


static void __exit ecdsa_kernel_module_exit(void)
{
    printk(KERN_INFO "Exiting ecdsa_module\n");

	if(signature_result != NULL) kfree(signature_result);
}

module_init(ecdsa_kernel_module_init);
module_exit(ecdsa_kernel_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("zhaoyang");
MODULE_DESCRIPTION("Kernel Crypto API Test");
