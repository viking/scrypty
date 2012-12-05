#include <ruby.h>
#include <stdio.h>
#include "scryptenc.h"

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

VALUE
scrypty_encrypt(rb_obj, rb_data, rb_password, rb_maxmem, rb_maxmemfrac, rb_maxtime)
  VALUE rb_obj;
  VALUE rb_data;
  VALUE rb_password;
  VALUE rb_maxmem;
  VALUE rb_maxmemfrac;
  VALUE rb_maxtime;
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

  out_len = data_len + 128;
  rb_out = rb_str_new(NULL, out_len);
  out = RSTRING_PTR(rb_out);

  errorcode = scryptenc_buf((const uint8_t *) data, data_len,
      (uint8_t *) out, (const uint8_t *) password, password_len,
      maxmem, maxmemfrac, maxtime);
  if (errorcode) {
    raise_scrypt_error(errorcode);
  }
  rb_str_set_len(rb_out, out_len);

  return rb_out;
}

VALUE
scrypty_decrypt(rb_obj, rb_data, rb_password, rb_maxmem, rb_maxmemfrac, rb_maxtime)
  VALUE rb_obj;
  VALUE rb_data;
  VALUE rb_password;
  VALUE rb_maxmem;
  VALUE rb_maxmemfrac;
  VALUE rb_maxtime;
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

  rb_out = rb_str_new(NULL, data_len);
  out = RSTRING_PTR(rb_out);

  errorcode = scryptdec_buf((const uint8_t *) data, data_len,
      (uint8_t *) out, &out_len, (const uint8_t *) password, password_len,
      maxmem, maxmemfrac, maxtime);
  if (errorcode) {
    raise_scrypty_error(errorcode);
  }
  rb_str_set_len(rb_out, out_len);

  return rb_out;
}

void
Init_scrypty_ext(void)
{
  mScrypty = rb_define_module("Scrypty");
  rb_define_singleton_method(mScrypty, "encrypt", scrypty_encrypt, 5);
  rb_define_singleton_method(mScrypty, "decrypt", scrypty_decrypt, 5);

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
