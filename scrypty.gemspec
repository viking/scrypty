# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'scrypty/version'

Gem::Specification.new do |gem|
  gem.name          = "scrypty"
  gem.version       = Scrypty::VERSION
  gem.authors       = ["Jeremy Stephens"]
  gem.email         = ["viking@pillageandplunder.net"]
  gem.description   = %q{Uses the scrypt algorithm by Colin Percival to encrypt/decrypt data}
  gem.summary       = %q{Utility to encrypt/decrypt data with the scrypt algorithm}
  gem.homepage      = "https://github.com/viking/scrypt-full"

  gem.files         = `git ls-files`.split($/)
  gem.extensions    = gem.files.grep(%r{extconf.rb})
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]
end
