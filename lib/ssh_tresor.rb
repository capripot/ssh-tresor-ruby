# frozen_string_literal: true

require_relative "ssh_tresor/agent"
require_relative "ssh_tresor/crypto"
require_relative "ssh_tresor/error"
require_relative "ssh_tresor/format"
require_relative "ssh_tresor/tresor"
require_relative "ssh_tresor/vault"
require_relative "ssh_tresor/version"

# SSH-agent-mediated encryption at rest for Ruby applications.
#
# The public entry point is {SshTresor::Vault}. Lower-level modules are exposed
# for callers that need direct control over agent access, binary `SSHTRESR`
# parsing, or key-slot management.
#
# @example Encrypt and decrypt with the current SSH agent
#   vault = SshTresor::Vault.new
#   encrypted = vault.encrypt("secret", armor: true)
#   vault.decrypt(encrypted)
#
# @see SshTresor::Vault
module SshTresor
end
