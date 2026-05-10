require "rspec/core/rake_task"
require "fileutils"

RSpec::Core::RakeTask.new(:spec)

desc "Validate YARD API documentation"
task :yard do
  sh "yard", "doc", "--no-output", "--fail-on-warning"
end

desc "Build GitHub Pages API documentation with YARD"
task :docs do
  FileUtils.rm_rf("_site")
  sh "yard", "doc", "--fail-on-warning", "--output-dir", "_site"
  FileUtils.mkdir_p("_site/white_paper")
  FileUtils.cp("white_paper/ssh_tresor_white_paper.pdf", "_site/white_paper/ssh_tresor_white_paper.pdf")
end

task default: :spec
