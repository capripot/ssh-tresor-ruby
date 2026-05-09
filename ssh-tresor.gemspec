# frozen_string_literal: true

require_relative "lib/ssh_tresor/version"

Gem::Specification.new do |spec|
  spec.name = "ssh-tresor"
  spec.version = SshTresor::VERSION
  spec.authors = ["Ronan Potage"]
  spec.summary = "SSH-agent-mediated encryption at rest for secrets"
  spec.description = "Independent Ruby implementation of ssh-tresor using live ssh-agent signatures, HKDF-SHA256, and AES-256-GCM."
  spec.homepage = "https://github.com/capripot/ssh-tresor-ruby"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1"

  spec.files = Dir.chdir(__dir__) do
    Dir["lib/**/*.rb", "exe/*", "README.md", "LICENSE.txt"]
  end
  spec.bindir = "exe"
  spec.executables = ["ssh-tresor"]
  spec.require_paths = ["lib"]

  spec.add_dependency "base64", "~> 0.3"

  spec.add_development_dependency "rake", "~> 13.3"
  spec.add_development_dependency "rspec", "~> 3.13"
  spec.add_development_dependency "yard", "~> 0.9"

  spec.metadata["documentation_uri"] = "https://capripot.github.io/ssh-tresor-ruby/"
  spec.metadata["source_code_uri"] = "https://github.com/capripot/ssh-tresor-ruby"
  spec.metadata["rubygems_mfa_required"] = "true"
end
