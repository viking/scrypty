#include <ruby.h>
#include <ruby/io.h>
#include <stdio.h>
#include <errno.h>
#include "scryptenc.h"
#include "scryptenc_cpuperf.h"
#include "memlimit.h"
#include "crypto_scrypt.h"
#include "crypto_aesctr.h"
#include "sha256.h"

VALUE mScrypty;

VALUE eScryptyError;
VALUE eMemoryLimitError;
VALUE eClockTimeError;
VALUE eDerivedKeyError;
VALUE eSaltError;
VALUE eOpenSSLError;
/* Use NoMemoryError */
VALUE eInvalidBlockError;
VALUE eUnrecognizedFormatError;
VALUE eNotEnoughMemoryError;
VALUE eTooMuchTimeError;
VALUE eIncorrectPasswordError;
VALUE eWriteError;
VALUE eReadError;

/**
 * Return codes from scrypt(enc|dec)_(buf|file):
 * 0	success
 * 1	getrlimit or sysctl(hw.usermem) failed
 * 2	clock_getres or clock_gettime failed
 * 3	error computing derived key
 * 4	could not read salt from /dev/urandom
 * 5	error in OpenSSL
 * 6	malloc failed
 * 7	data is not a valid scrypt-encrypted block
 * 8	unrecognized scrypt format
 * 9	decrypting file would take too much memory
 * 10	decrypting file would take too long
 * 11	password is incorrect
 * 12	error writing output file
 * 13	error reading input file
 */
static void
raise_scrypty_error(errorcode)
   int errorcode;
{
  switch (errorcode) {
    case 1:
      rb_raise(eMemoryLimitError, "couldn't get memory limit");
      break;
    case 2:
      rb_raise(eClockTimeError, "couldn't determine CPU speed");
      break;
    case 3:
      rb_raise(eDerivedKeyError, "couldn't compute derived key");
      break;
    case 4:
      rb_raise(eSaltError, "couldn't read salt from /dev/urandom");
      break;
    case 5:
      rb_raise(eOpenSSLError, "OpenSSL error");
      break;
    case 6:
      rb_raise(rb_eNoMemError, "couldn't allocate memory");
      break;
    case 7:
      rb_raise(eInvalidBlockError, "data is not a valid scrypt-encrypted block");
      break;
    case 8:
      rb_raise(eUnrecognizedFormatError, "unrecognized scrypt format");
      break;
    case 9:
      rb_raise(eNotEnoughMemoryError, "decrypting would take too much memory");
      break;
    case 10:
      rb_raise(eTooMuchTimeError, "decrypting would take too long");
      break;
    case 11:
      rb_raise(eIncorrectPasswordError, "password is incorrect");
      break;
    case 12:
      rb_raise(eWriteError, "error writing output file");
      break;
    case 13:
      rb_raise(eReadError, "error reading input file");
      break;
  }
}

static VALUE
scrypty_buffer(rb_obj, rb_data, rb_password, rb_maxmem, rb_maxmemfrac, rb_maxtime, encrypt)
  VALUE rb_obj;
  VALUE rb_data;
  VALUE rb_password;
  VALUE rb_maxmem;
  VALUE rb_maxmemfrac;
  VALUE rb_maxtime;
  int encrypt;
{
  VALUE rb_out;
  char *data, *password, *out;
  size_t data_len, password_len, out_len, maxmem;
  double maxmemfrac, maxtime;
  int errorcode;

  if (TYPE(rb_data) == T_STRING) {
    data = RSTRING_PTR(rb_data);
    data_len = (size_t) RSTRING_LEN(rb_data);
  }
  else {
    rb_raise(rb_eTypeError, "first argument (data) must be a String");
  }

  if (TYPE(rb_password) == T_STRING) {
    password = RSTRING_PTR(rb_password);
    password_len = (size_t) RSTRING_LEN(rb_password);
  }
  else {
    rb_raise(rb_eTypeError, "second argument (password) must be a String");
  }

  if (TYPE(rb_maxmem) == T_FIXNUM) {
    maxmem = FIX2INT(rb_maxmem);
  }
  else {
    rb_raise(rb_eTypeError, "third argument (maxmem) must be a Fixnum");
  }

  if (FIXNUM_P(rb_maxmemfrac) || TYPE(rb_maxmemfrac) == T_FLOAT) {
    maxmemfrac = NUM2DBL(rb_maxmemfrac);
  }
  else {
    rb_raise(rb_eTypeError, "fourth argument (maxmemfrac) must be a Fixnum or Float");
  }

  if (FIXNUM_P(rb_maxtime) || TYPE(rb_maxtime) == T_FLOAT) {
    maxtime = NUM2DBL(rb_maxtime);
  }
  else {
    rb_raise(rb_eTypeError, "fifth argument (maxtime) must be a Fixnum or Float");
  }

  if (encrypt) {
    out_len = data_len + 128;
    rb_out = rb_str_new(NULL, out_len);
    out = RSTRING_PTR(rb_out);

    errorcode = scrypty_scryptenc_buf((const uint8_t *) data, data_len,
        (uint8_t *) out, (const uint8_t *) password, password_len,
        maxmem, maxmemfrac, maxtime);
  }
  else {
    rb_out = rb_str_new(NULL, data_len);
    out = RSTRING_PTR(rb_out);

    errorcode = scrypty_scryptdec_buf((const uint8_t *) data, data_len,
        (uint8_t *) out, &out_len, (const uint8_t *) password, password_len,
        maxmem, maxmemfrac, maxtime);
  }

  if (errorcode) {
    raise_scrypty_error(errorcode);
  }
  rb_str_set_len(rb_out, out_len);

  return rb_out;
}

VALUE
scrypty_encrypt_buffer(rb_obj, rb_data, rb_password, rb_maxmem, rb_maxmemfrac, rb_maxtime)
  VALUE rb_obj;
  VALUE rb_data;
  VALUE rb_password;
  VALUE rb_maxmem;
  VALUE rb_maxmemfrac;
  VALUE rb_maxtime;
{
  return scrypty_buffer(rb_obj, rb_data, rb_password, rb_maxmem, rb_maxmemfrac,
      rb_maxtime, 1);
}

VALUE
scrypty_decrypt_buffer(rb_obj, rb_data, rb_password, rb_maxmem, rb_maxmemfrac, rb_maxtime)
  VALUE rb_obj;
  VALUE rb_data;
  VALUE rb_password;
  VALUE rb_maxmem;
  VALUE rb_maxmemfrac;
  VALUE rb_maxtime;
{
  return scrypty_buffer(rb_obj, rb_data, rb_password, rb_maxmem, rb_maxmemfrac,
      rb_maxtime, 0);
}

VALUE
scrypty_file(rb_obj, rb_infn, rb_outfn, rb_password, rb_maxmem, rb_maxmemfrac, rb_maxtime, encrypt)
  VALUE rb_obj;
  VALUE rb_infn;
  VALUE rb_outfn;
  VALUE rb_password;
  VALUE rb_maxmem;
  VALUE rb_maxmemfrac;
  VALUE rb_maxtime;
  int encrypt;
{
  VALUE rb_infile, rb_outfile;
  FILE *in, *out;
  rb_io_t *in_p, *out_p;
  char *password;
  size_t password_len;
  int errorcode, maxmem;
  double maxmemfrac, maxtime;

  rb_infile = rb_file_open_str(rb_infn, "rb");
  rb_outfile = rb_file_open_str(rb_outfn, "wb");

  if (TYPE(rb_password) == T_STRING) {
    password = RSTRING_PTR(rb_password);
    password_len = (size_t) RSTRING_LEN(rb_password);
  }
  else {
    rb_raise(rb_eTypeError, "third argument (password) must be a String");
  }

  if (TYPE(rb_maxmem) == T_FIXNUM) {
    maxmem = FIX2INT(rb_maxmem);
  }
  else {
    rb_raise(rb_eTypeError, "fourth argument (maxmem) must be a Fixnum");
  }

  if (FIXNUM_P(rb_maxmemfrac) || TYPE(rb_maxmemfrac) == T_FLOAT) {
    maxmemfrac = NUM2DBL(rb_maxmemfrac);
  }
  else {
    rb_raise(rb_eTypeError, "fifth argument (maxmemfrac) must be a Fixnum or Float");
  }

  if (FIXNUM_P(rb_maxtime) || TYPE(rb_maxtime) == T_FLOAT) {
    maxtime = NUM2DBL(rb_maxtime);
  }
  else {
    rb_raise(rb_eTypeError, "sixth argument (maxtime) must be a Fixnum or Float");
  }

  GetOpenFile(rb_infile, in_p);
  in = rb_io_stdio_file(in_p);
  GetOpenFile(rb_outfile, out_p);
  out = rb_io_stdio_file(out_p);

  if (encrypt) {
    errorcode = scrypty_scryptenc_file(in, out, (const uint8_t *) password,
        password_len, maxmem, maxmemfrac, maxtime);
  }
  else {
    errorcode = scrypty_scryptdec_file(in, out, (const uint8_t *) password,
        password_len, maxmem, maxmemfrac, maxtime);
  }
  rb_io_close(rb_infile);
  rb_io_close(rb_outfile);

  if (errorcode) {
    raise_scrypty_error(errorcode);
  }

  return Qnil;
}

VALUE
scrypty_encrypt_file(rb_obj, rb_infn, rb_outfn, rb_password, rb_maxmem, rb_maxmemfrac, rb_maxtime)
  VALUE rb_obj;
  VALUE rb_infn;
  VALUE rb_outfn;
  VALUE rb_password;
  VALUE rb_maxmem;
  VALUE rb_maxmemfrac;
  VALUE rb_maxtime;
{
  return scrypty_file(rb_obj, rb_infn, rb_outfn, rb_password, rb_maxmem,
      rb_maxmemfrac, rb_maxtime, 1);
}

VALUE
scrypty_decrypt_file(rb_obj, rb_infn, rb_outfn, rb_password, rb_maxmem, rb_maxmemfrac, rb_maxtime)
  VALUE rb_obj;
  VALUE rb_infn;
  VALUE rb_outfn;
  VALUE rb_password;
  VALUE rb_maxmem;
  VALUE rb_maxmemfrac;
  VALUE rb_maxtime;
{
  return scrypty_file(rb_obj, rb_infn, rb_outfn, rb_password, rb_maxmem,
      rb_maxmemfrac, rb_maxtime, 0);
}

VALUE
scrypty_memlimit(rb_obj, rb_maxmem, rb_maxmemfrac)
  VALUE rb_obj;
  VALUE rb_maxmem;
  VALUE rb_maxmemfrac;
{
  long l_maxmem;
  size_t maxmem, memlimit, max_size;
  double maxmemfrac;

  max_size = (size_t) -1;

  if (TYPE(rb_maxmem) == T_FIXNUM) {
    l_maxmem = FIX2LONG(rb_maxmem);

    if (l_maxmem < 0) {
      rb_raise(rb_eArgError, "maxmem (%ld) must not be less than 0", l_maxmem);
    }
    else if ((unsigned long) l_maxmem > (unsigned long) max_size) {
      rb_raise(rb_eArgError, "maxmem (%ld) cannot exceed %zu", l_maxmem, max_size);
    }
    else {
      maxmem = (size_t) l_maxmem;
    }
  }
  else {
    rb_raise(rb_eTypeError, "first argument (maxmem) must be a Fixnum");
  }

  if (FIXNUM_P(rb_maxmemfrac) || TYPE(rb_maxmemfrac) == T_FLOAT) {
    maxmemfrac = NUM2DBL(rb_maxmemfrac);
  }
  else {
    rb_raise(rb_eTypeError, "second argument (maxmemfrac) must be a Fixnum or Float");
  }

  if (scrypty_memtouse(maxmem, maxmemfrac, &memlimit) != 0) {
    rb_raise(rb_eRuntimeError, "could not determine memory limit");
  }

  return SIZET2NUM(memlimit);
}

VALUE
scrypty_opslimit(rb_obj, rb_maxtime)
  VALUE rb_obj;
  VALUE rb_maxtime;
{
  double opps, maxtime, opslimit;

  if (FIXNUM_P(rb_maxtime) || TYPE(rb_maxtime) == T_FLOAT) {
    maxtime = NUM2DBL(rb_maxtime);
  }
  else {
    rb_raise(rb_eTypeError, "first argument (maxtime) must be a Fixnum or Float");
  }

  /* Figure out how fast the CPU is. */
  if (scrypty_scryptenc_cpuperf(&opps) != 0) {
    rb_raise(rb_eRuntimeError, "could not determine CPU performance");
  }
  opslimit = opps * maxtime;

  /* Allow a minimum of 2^15 salsa20/8 cores. */
  if (opslimit < 32768)
    opslimit = 32768;

  return DBL2NUM(opslimit);
}

/* Calculate parameters used for creating a derived key with the
 * scrypt algorithm. */
VALUE
scrypty_params(rb_obj, rb_memlimit, rb_opslimit)
  VALUE rb_obj;
  VALUE rb_memlimit;
  VALUE rb_opslimit;
{
  VALUE rb_result;
  long l_memlimit;
  size_t memlimit, max_size;
  double opslimit;
  double maxN, maxrp;
  int logN;
  uint64_t N = 0;
  uint32_t r = 0, p = 0;

  max_size = (size_t) -1;

  if (TYPE(rb_memlimit) == T_FIXNUM) {
    l_memlimit = FIX2LONG(rb_memlimit);

    if (l_memlimit < 0) {
      rb_raise(rb_eArgError, "memlimit (%ld) must not be less than 0", l_memlimit);
    }
    else if ((unsigned long) l_memlimit > (unsigned long) max_size) {
      rb_raise(rb_eArgError, "memlimit (%ld) cannot exceed %zu", l_memlimit, max_size);
    }
    else {
      memlimit = (size_t) l_memlimit;
    }
  }
  else {
    rb_raise(rb_eTypeError, "first argument (memlimit) must be a Fixnum");
  }

  if (FIXNUM_P(rb_opslimit) || TYPE(rb_opslimit) == T_FLOAT) {
    opslimit = NUM2DBL(rb_opslimit);
  }
  else {
    rb_raise(rb_eTypeError, "second argument (opslimit) must be a Fixnum or Float");
  }

  /* Fix r = 8 for now. */
  r = 8;

  if (opslimit < memlimit/32) {
    /* Set p = 1 and choose N based on the CPU limit. */
    p = 1;
    maxN = opslimit / (r * 4);
    for (logN = 1; logN < 63; logN += 1) {
      if ((uint64_t)(1) << logN > maxN / 2)
        break;
    }
  } else {
    /* Set N based on the memory limit. */
    maxN = memlimit / (r * 128);
    for (logN = 1; logN < 63; logN += 1) {
      N = (uint64_t)(1) << logN;
      if (N > maxN / 2)
        break;
    }

    /* Choose p based on the CPU limit. */
    maxrp = (opslimit / 4) / ((uint64_t)(1) << logN);
    if (maxrp > 0x3fffffff)
      maxrp = 0x3fffffff;
    p = (uint32_t)(maxrp) / r;
  }

  rb_result = rb_ary_new3(3, UINT2NUM(N), UINT2NUM(r), UINT2NUM(p));
  return rb_result;
};

VALUE
scrypty_dk(rb_obj, rb_password, rb_salt, rb_n, rb_r, rb_p, rb_keylen)
  VALUE rb_obj;
  VALUE rb_password;
  VALUE rb_salt;
  VALUE rb_n;
  VALUE rb_r;
  VALUE rb_p;
  VALUE rb_keylen;
{
  VALUE rb_dk;
  const uint8_t *password, *salt;
  uint8_t *dk;
  uint64_t N;
  uint32_t r, p;
  size_t password_len, salt_len, keylen;

  if (TYPE(rb_password) == T_STRING) {
    password = (const uint8_t *) RSTRING_PTR(rb_password);
    password_len = (size_t) RSTRING_LEN(rb_password);
  }
  else {
    rb_raise(rb_eTypeError, "first argument (password) must be a String");
  }

  if (TYPE(rb_salt) == T_STRING) {
    salt = (const uint8_t *) RSTRING_PTR(rb_salt);
    salt_len = (size_t) RSTRING_LEN(rb_salt);
  }
  else {
    rb_raise(rb_eTypeError, "second argument (salt) must be a String");
  }

  if (FIXNUM_P(rb_n)) {
    N = (uint64_t) NUM2ULL(rb_n);
  }
  else {
    rb_raise(rb_eTypeError, "third argument (n) must be a Fixnum");
  }

  if (FIXNUM_P(rb_r)) {
    r = (uint32_t) NUM2ULONG(rb_r);
  }
  else {
    rb_raise(rb_eTypeError, "fourth argument (r) must be a Fixnum");
  }

  if (FIXNUM_P(rb_p)) {
    p = (uint32_t) NUM2ULONG(rb_p);
  }
  else {
    rb_raise(rb_eTypeError, "fifth argument (p) must be a Fixnum");
  }

  if (FIXNUM_P(rb_keylen)) {
    keylen = NUM2SIZET(rb_keylen);
  }
  else {
    rb_raise(rb_eTypeError, "sixth argument (keylen) must be a Fixnum");
  }

  rb_dk = rb_str_buf_new(keylen);
  dk = (uint8_t *) RSTRING_PTR(rb_dk);

  if (scrypty_crypto_scrypt(password, password_len, salt,
        salt_len, N, r, p, dk, keylen) != 0) {

    switch (errno) {
      case EFBIG:
        rb_raise(rb_eRuntimeError, "parameters were too big");
        break;

      case EINVAL:
        rb_raise(rb_eRuntimeError, "parameters were invalid");
        break;

      case ENOMEM:
        rb_raise(rb_eNoMemError, "not enough memory to create derived key");
        break;

      default:
        rb_raise(rb_eRuntimeError, "%s", strerror(errno));
    }
  }

  rb_str_set_len(rb_dk, keylen);
  return rb_dk;
}

VALUE
scrypty_encrypt_raw(rb_obj, rb_data, rb_dk)
  VALUE rb_obj;
  VALUE rb_data;
  VALUE rb_dk;
{
  VALUE rb_out;
  uint8_t *data, *dk, *out, *key_enc, *key_hmac;
  uint8_t hbuf[32];
  size_t data_len;
  scrypty_HMAC_SHA256_CTX hctx;
  AES_KEY key_enc_exp;
  struct crypto_aesctr *AES;

  if (TYPE(rb_data) == T_STRING) {
    data = (uint8_t *) RSTRING_PTR(rb_data);
    data_len = (size_t) RSTRING_LEN(rb_data);
  }
  else {
    rb_raise(rb_eTypeError, "first argument (data) must be a String");
  }

  if (TYPE(rb_dk) == T_STRING) {
    dk = (uint8_t *) RSTRING_PTR(rb_dk);
  }
  else {
    rb_raise(rb_eTypeError, "second argument (dk) must be a String");
  }
  key_enc = dk;
  key_hmac = &dk[32];

  rb_out = rb_str_buf_new(data_len + 32);
  out = (uint8_t *) RSTRING_PTR(rb_out);

  /* Encrypt data. */
  if (AES_set_encrypt_key(key_enc, 256, &key_enc_exp))
    rb_raise(eOpenSSLError, "OpenSSL error");

  if ((AES = scrypty_crypto_aesctr_init(&key_enc_exp, 0)) == NULL)
    rb_raise(rb_eNoMemError, "couldn't allocate memory");

  scrypty_crypto_aesctr_stream(AES, data, out, data_len);
  scrypty_crypto_aesctr_free(AES);

  /* Add signature. */
  scrypty_HMAC_SHA256_Init(&hctx, key_hmac, 32);
  scrypty_HMAC_SHA256_Update(&hctx, out, data_len);
  scrypty_HMAC_SHA256_Final(hbuf, &hctx);
  memcpy(&out[data_len], hbuf, 32);

  rb_str_set_len(rb_out, data_len + 32);
  return rb_out;
}

VALUE
scrypty_decrypt_raw(rb_obj, rb_data, rb_dk)
  VALUE rb_obj;
  VALUE rb_data;
  VALUE rb_dk;
{
  VALUE rb_out;
  uint8_t *data, *dk, *out, *key_enc, *key_hmac;
  uint8_t hbuf[32];
  size_t data_len;
  scrypty_HMAC_SHA256_CTX hctx;
  AES_KEY key_enc_exp;
  struct crypto_aesctr *AES;

  if (TYPE(rb_data) == T_STRING) {
    data = (uint8_t *) RSTRING_PTR(rb_data);
    data_len = (size_t) RSTRING_LEN(rb_data);
  }
  else {
    rb_raise(rb_eTypeError, "first argument (data) must be a String");
  }

  if (TYPE(rb_dk) == T_STRING) {
    dk = (uint8_t *) RSTRING_PTR(rb_dk);
  }
  else {
    rb_raise(rb_eTypeError, "second argument (dk) must be a String");
  }
  key_enc = dk;
  key_hmac = &dk[32];

  rb_out = rb_str_buf_new(data_len - 32);
  out = (uint8_t *) RSTRING_PTR(rb_out);

  /* Decrypt data. */
  if (AES_set_encrypt_key(key_enc, 256, &key_enc_exp))
    rb_raise(eOpenSSLError, "OpenSSL error");
  if ((AES = scrypty_crypto_aesctr_init(&key_enc_exp, 0)) == NULL)
    rb_raise(rb_eNoMemError, "couldn't allocate memory");

  scrypty_crypto_aesctr_stream(AES, data, out, data_len - 32);
  scrypty_crypto_aesctr_free(AES);

  /* Verify signature. */
  scrypty_HMAC_SHA256_Init(&hctx, key_hmac, 32);
  scrypty_HMAC_SHA256_Update(&hctx, data, data_len - 32);
  scrypty_HMAC_SHA256_Final(hbuf, &hctx);
  if (memcmp(hbuf, &data[data_len - 32], 32))
    rb_raise(eInvalidBlockError, "data is not a valid scrypt-encrypted block");

  rb_str_set_len(rb_out, data_len - 32);
  return rb_out;
}

void
Init_scrypty_ext(void)
{
  mScrypty = rb_define_module("Scrypty");
  rb_define_singleton_method(mScrypty, "encrypt", scrypty_encrypt_buffer, 5);
  rb_define_singleton_method(mScrypty, "decrypt", scrypty_decrypt_buffer, 5);
  rb_define_singleton_method(mScrypty, "encrypt_file", scrypty_encrypt_file, 6);
  rb_define_singleton_method(mScrypty, "decrypt_file", scrypty_decrypt_file, 6);
  rb_define_singleton_method(mScrypty, "memlimit", scrypty_memlimit, 2);
  rb_define_singleton_method(mScrypty, "opslimit", scrypty_opslimit, 1);
  rb_define_singleton_method(mScrypty, "params", scrypty_params, 2);
  rb_define_singleton_method(mScrypty, "dk", scrypty_dk, 6);
  rb_define_singleton_method(mScrypty, "encrypt_raw", scrypty_encrypt_raw, 2);
  rb_define_singleton_method(mScrypty, "decrypt_raw", scrypty_decrypt_raw, 2);

  eScryptyError = rb_define_class_under(mScrypty, "Exception", rb_eException);
  eMemoryLimitError = rb_define_class_under(mScrypty, "MemoryLimitError", eScryptyError);
  eClockTimeError = rb_define_class_under(mScrypty, "ClockTimeError", eScryptyError);
  eDerivedKeyError = rb_define_class_under(mScrypty, "DerivedKeyError", eScryptyError);
  eSaltError = rb_define_class_under(mScrypty, "SaltError", eScryptyError);
  eOpenSSLError = rb_define_class_under(mScrypty, "OpenSSLError", eScryptyError);
  eInvalidBlockError = rb_define_class_under(mScrypty, "InvalidBlockError", eScryptyError);
  eUnrecognizedFormatError = rb_define_class_under(mScrypty, "UnrecognizedFormatError", eScryptyError);
  eNotEnoughMemoryError = rb_define_class_under(mScrypty, "NotEnoughMemoryError", eScryptyError);
  eTooMuchTimeError = rb_define_class_under(mScrypty, "TooMuchTimeError", eScryptyError);
  eIncorrectPasswordError = rb_define_class_under(mScrypty, "IncorrectPasswordError", eScryptyError);
  eWriteError = rb_define_class_under(mScrypty, "WriteError", eScryptyError);
  eReadError = rb_define_class_under(mScrypty, "ReadError", eScryptyError);
}
