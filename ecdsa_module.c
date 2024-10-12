#include "ecdsa_module.h"

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


struct crypto_akcipher *tfm;

/*
static int init_ctx_setkey_no_asn1(void)
{
	u8 *key, *ptr;
	int err = -ENOMEM;

	//tfm = crypto_alloc_akcipher("ecdsa-sm2-generic", 0, 0);
	tfm = crypto_alloc_akcipher("ecdsa-nist-p256-generic", 0, 0);

	key = kmalloc(key_len + sizeof(u32) * 2, GFP_KERNEL);
	if (!key)
		return err;

	memcpy(key, test_key, key_len);
	ptr = key + key_len;
	ptr = test_pack_u32(ptr, algo);

	//printk("kmalloc\n");
	
	err = crypto_akcipher_set_key_noasn1(tfm, key, key_len);

	if (err)
		goto free_key;

	//printk("crypto_alloc_akcipher\n");
	
	return err;

free_key:
	kfree(key);
	return err;
}*/

static int init_ctx_setkey_with_asn1(void)
{
	u8 *key, *ptr;
	int err = -ENOMEM;

	//tfm = crypto_alloc_akcipher("ecdsa-sm2-generic", 0, 0);
	tfm = crypto_alloc_akcipher("ecdsa-nist-p256-generic", 0, 0);

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
	if (out_len < c_size) {
		pr_err("alg: akcipher: %s test failed. Invalid output len %u\n",
		       op, out_len);
		err = -EINVAL;
		goto free_all;
	}

	signature_result = kmalloc(c_size, GFP_KERNEL);

	memcpy(signature_result, outbuf_dec + out_len - c_size, c_size);
	
	/*printk("Output generated signature: ");
	for(int i = 0; i < c_size; i++)
		printk("%02x", *(char *)(signature_result + i));*/
	
	if(memcmp(signature_result, c, c_size) == 0)
		printk("signature correct!\n");
	else 
		printk("signature incorrect!\n");

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

	err = -ENOMEM;
	out_len_max = crypto_akcipher_maxsize(tfm);
	outbuf_enc = kzalloc(out_len_max, GFP_KERNEL);
	if (!outbuf_enc)
		goto free_xbuf;

	op = "verify";
	
	err = -E2BIG;
	if (WARN_ON(c_size > PAGE_SIZE))
		goto free_all;
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

	//if(init_ctx_setkey_no_asn1() != 0)
	if(init_ctx_setkey_with_asn1() != 0) //设置密钥，发送方和接收方都需要运行这个函数
		return err;
	
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
