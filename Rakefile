require "bundler/gem_tasks"
require "rake/testtask"
require "rake/clean"

file "ext/Makefile" => "ext/extconf.rb" do
  Dir.chdir("ext") do
    ruby "extconf.rb"
  end
end

file "ext/scrypty_ext.so" => FileList["ext/*.c", "ext/*.h", "ext/Makefile"] do
  Dir.chdir("ext") do
    sh "make"
  end
end

file "lib/scrypty_ext.so" => "ext/scrypty_ext.so" do
  cp 'ext/scrypty_ext.so', 'lib/scrypty_ext.so'
end

desc "Compile the scrypty extension"
task :compile => "lib/scrypty_ext.so"

desc "Prefix C function names"
task :prefix do
  names = %w{SHA256Context SHA256_CTX HMAC_SHA256Context HMAC_SHA256_CTX SHA256_Init SHA256_Update SHA256_Final HMAC_SHA256_Init HMAC_SHA256_Update HMAC_SHA256_Final PBKDF2_SHA256 crypto_aesctr_init crypto_aesctr_stream crypto_aesctr_free crypto_scrypt memtouse scryptenc_cpuperf scryptenc_buf scryptdec_buf scryptenc_file scryptdec_file}
  `git ls-files ext`.chomp.split(/\s+/).each do |filename|
    data = File.read(filename)
    names.each do |name|
      data.gsub!(/(?<!")\b#{name}\b(?!")/m, "scrypty_#{name}")
    end
    File.open(filename, "w") { |f| f.write(data) }
  end
end

Rake::TestTask.new do |t|
  t.test_files = FileList['test/test_*.rb']
  t.verbose = true
end
task :test => :compile
task :default => :test

CLEAN.clear
CLEAN.include(["ext/*.o", "ext/*.so", "lib/*.so", "ext/extconf.h", "ext/Makefile"])
