#include <linux/kernel.h>
#include <linux/module.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/err.h>
#include <linux/fips.h>
#include <linux/module.h>
#include <linux/once.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uio.h>
#include <crypto/rng.h>
#include <crypto/drbg.h>
#include <crypto/akcipher.h>
#include <crypto/kpp.h>
#include <crypto/acompress.h>
#include <crypto/internal/cipher.h>
#include <crypto/internal/simd.h>
#include <linux/oid_registry.h>

#define XBUFSIZE 8

struct akcipher_testvec {
	const unsigned char *key;
	const unsigned char *params;
	const unsigned char *m;
	const unsigned char *c;
	unsigned int key_len;
	unsigned int param_len;
	unsigned int m_size;
	unsigned int c_size;
	bool public_key_vec;
	bool siggen_sigver_test;
	enum OID algo;
};

static void __testmgr_free_buf(char *buf[XBUFSIZE], int order)
{
	int i;

	for (i = 0; i < XBUFSIZE; i++)
		free_pages((unsigned long)buf[i], order);
}

static void testmgr_free_buf(char *buf[XBUFSIZE])
{
	__testmgr_free_buf(buf, 0);
}

static u8 *test_pack_u32(u8 *dst, u32 val)
{
	memcpy(dst, &val, sizeof(val));
	return dst + sizeof(val);
}

static int __testmgr_alloc_buf(char *buf[XBUFSIZE], int order)
{
	int i;

	for (i = 0; i < XBUFSIZE; i++) {
		buf[i] = (char *)__get_free_pages(GFP_KERNEL, order);
		if (!buf[i])
			goto err_free_buf;
	}

	return 0;

err_free_buf:
	while (i-- > 0)
		free_pages((unsigned long)buf[i], order);

	return -ENOMEM;
}

static int testmgr_alloc_buf(char *buf[XBUFSIZE])
{
	return __testmgr_alloc_buf(buf, 0);
}

static void hexdump(unsigned char *buf, unsigned int len)
{
	print_hex_dump(KERN_CONT, "", DUMP_PREFIX_OFFSET,
			16, 1,
			buf, len, false);
}