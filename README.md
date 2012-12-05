# scrypt-full

This is a Rubygem that uses the scrypt algorithm to encrypt/decrypt data.
The 'scrypt' gem only provides support for hashing passwords.

## Installation

Add this line to your application's Gemfile:

    gem 'scrypt-full'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install scrypt-full

## Usage

scrypt uses a few parameters to determine how to encrypt data:
* maxmem - use at most the specified number of bytes of RAM when computing the
  derived encryption key (use 0 for unlimited)
* maxmemfrac - use at most the specified fraction of the available RAM for
  computing the derived encryption key
* maxtime - spend at most maxtime seconds computing the derived encryption key
  from the password

Example:
    maxmem = 0
    maxmemfrac = 0.125
    maxtime = 5.0

    Scrypt.encrypt("your data here", "secret", maxmem, maxmemfrac, maxtime)

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
