require 'mkmf'

dir_config("openssl")

result = pkg_config("openssl") && have_header("openssl/ssl.h")

unless result
  result = have_header("openssl/ssl.h")
  result &&= %w[crypto libeay32].any? {|lib| have_library(lib, "AES_set_encrypt_key")}
  result &&= %w[ssl ssleay32].any? {|lib| have_library(lib, "AES_set_encrypt_key")}
  unless result
    Logging::message "=== Checking for required stuff failed. ===\n"
    Logging::message "Makefile wasn't created. Fix the errors above.\n"
    exit 1
  end
end

have_library('rt', 'clock_gettime')
%w{err.h fcntl.h inttypes.h memory.h stddef.h stdint.h stdlib.h string.h strings.h sys/endian.h sys/param.h sys/stat.h sys/time.h sys/types.h termios.h unistd.h}.each do |header|
  have_header(header)
end
have_type('size_t')
have_type('ssize_t')
have_type('uint32_t')
have_type('uint64_t')
have_type('uint8_t')
if have_header('sys/sysinfo.h')
  if have_type('struct sysinfo', 'sys/sysinfo.h')
    have_struct_member('struct sysinfo', 'mem_unit', 'sys/sysinfo.h')
    have_struct_member('struct sysinfo', 'totalram', 'sys/sysinfo.h')
  end
end
have_func('malloc')
have_func('mmap')
have_func('strtod')
%w{clock_gettime gettimeofday memmove memset munmap posix_memalign strcspn strdup strerror strtoumax sysinfo}.each do |func|
  have_func(func)
end
have_const('be64enc')

system("sysctl hw.usermem >/dev/null 2>/dev/null")
if $?.exitstatus == 0
  $defs.push("-DHAVE_SYSCTL_HW_USERMEM=1")
end
create_header
create_makefile('scrypty_ext')
