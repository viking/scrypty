# Scrypty

This is a Rubygem that uses the scrypt algorithm to encrypt/decrypt data.
The 'scrypt' gem only provides support for hashing passwords.

## Installation

Add this line to your application's Gemfile:

    gem 'scrypty'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install scrypty

## Usage

The scrypt algorithm uses a few parameters to determine how to encrypt data:
* maxmem - use at most the specified number of bytes of RAM when computing the
  derived encryption key (use 0 for unlimited)
* maxmemfrac - use at most the specified fraction of the available RAM for
  computing the derived encryption key
* maxtime - spend at most maxtime seconds computing the derived encryption key
  from the password

Example:

    require 'scrypty'

    data = "my data"
    password = "secret"
    maxmem = 0
    maxmemfrac = 0.125
    maxtime = 5.0

    encrypted = Scrypty.encrypt(data, password, maxmem, maxmemfrac, maxtime)
    puts "Encrypted data: #{encrypted.inspect}"
    decrypted = Scrypty.decrypt(encrypted, password, maxmem, maxmemfrac, maxtime)
    puts "Decrypted data: #{decrypted.inspect}"

## See also

* [scrypt by Colin Percival](http://www.tarsnap.com/scrypt.html)
* [libscrypt (ChromiumOS source tree)](http://git.chromium.org/gitweb/?p=chromiumos/third_party/libscrypt.git;a=summary)

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
