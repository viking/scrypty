require "bundler/gem_tasks"

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

desc "Compile the scrypty extension"
task :compile => "ext/scrypty_ext.so"
