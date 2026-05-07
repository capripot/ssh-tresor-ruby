# frozen_string_literal: true

require_relative "format"
require_relative "tresor"

module SshTresor
  # Public high-level API for encrypting and decrypting tresors from another Ruby
  # application or gem.
  #
  # `Vault` is intentionally a small facade over the lower-level SSH agent,
  # crypto, and wire-format objects. It connects to `SSH_AUTH_SOCK` by default,
  # but accepts an injected agent object for tests or alternate transports.
  #
  # @example Encrypt and decrypt using the current SSH agent
  #   vault = SshTresor::Vault.new
  #   encrypted = vault.encrypt("secret", armor: true)
  #   plaintext = vault.decrypt(encrypted)
  #
  # @example Inject a custom agent implementation
  #   vault = SshTresor::Vault.new(agent: my_agent)
  #
  # @see SshTresor::Tresor
  # @see SshTresor::TresorBlob
  class Vault
    # Creates a vault bound to an SSH agent.
    #
    # The default agent is opened from `ENV["SSH_AUTH_SOCK"]`. The injected agent
    # must implement the subset of {SshTresor::Agent} used by the high-level
    # operations: `first_key`, `find_key`, `list_keys`, and `sign`.
    #
    # @param agent [#first_key, #find_key, #list_keys, #sign] SSH agent-like object.
    # @raise [SshTresor::AgentError] when the default SSH agent cannot be reached.
    # @return [SshTresor::Vault]
    def initialize(agent: Agent.connect)
      @agent = agent
    end

    # Encrypts plaintext for one or more keys available in the SSH agent.
    #
    # When no fingerprints are given, the first key returned by the agent is
    # used. Fingerprints may be full `SHA256:...` values or unambiguous prefixes.
    #
    # @param plaintext [String] Plaintext bytes to encrypt.
    # @param fingerprints [Array<String>] SSH key fingerprints to encrypt for.
    # @param armor [Boolean] Whether to return base64 armor instead of binary format.
    # @return [String] Encrypted tresor bytes or armored text.
    # @raise [SshTresor::KeyNotFound] when a requested key is unavailable.
    # @raise [SshTresor::AgentError] when agent signing fails.
    def encrypt(plaintext, fingerprints: [], armor: false)
      blob = Tresor.encrypt_with_agent(@agent, plaintext, fingerprints: fingerprints)
      armor ? blob.to_armored : blob.to_bytes
    end

    # Decrypts an encrypted tresor using any matching key in the SSH agent.
    #
    # The input may be binary `SSHTRESR` v3 data or armored text. The agent is
    # asked to sign the stored slot challenge for matching key fingerprints.
    #
    # @param encrypted [String] Binary or armored tresor content.
    # @return [String] Decrypted plaintext bytes.
    # @raise [SshTresor::NoMatchingSlot] when no loaded agent key can decrypt it.
    # @raise [SshTresor::DecryptionError] when authentication/decryption fails.
    # @raise [SshTresor::Error] when the tresor format is invalid.
    def decrypt(encrypted)
      Tresor.decrypt_with_agent(@agent, TresorBlob.from_bytes(encrypted))
    end

    # Adds one SSH key slot to an existing tresor.
    #
    # The current agent must be able to decrypt an existing slot before adding a
    # new one, because the master key must be recovered and re-wrapped for the
    # new key.
    #
    # @param encrypted [String] Binary or armored tresor content.
    # @param fingerprint [String] Fingerprint or unambiguous prefix of the key to add.
    # @param armor [Boolean, nil] Output armor mode. `nil` preserves input format.
    # @return [String] Updated encrypted tresor content.
    # @raise [SshTresor::NoMatchingSlot] when the current agent cannot unlock the tresor.
    # @raise [SshTresor::KeyNotFound] when the new key is unavailable.
    def add_key(encrypted, fingerprint:, armor: nil)
      input_was_armored = armored?(encrypted)
      blob = TresorBlob.from_bytes(encrypted)
      updated = Tresor.add_key_with_agent(@agent, blob, fingerprint)
      serialize(updated, armor.nil? ? input_was_armored : armor)
    end

    # Adds slots for all available SSH agent keys not already present.
    #
    # Keys that are already present or cannot sign are skipped.
    #
    # @param encrypted [String] Binary or armored tresor content.
    # @param armor [Boolean, nil] Output armor mode. `nil` preserves input format.
    # @return [Array(String, Integer)] Updated tresor content and number of slots added.
    # @raise [SshTresor::NoMatchingSlot] when the current agent cannot unlock the tresor.
    def add_all_keys(encrypted, armor: nil)
      input_was_armored = armored?(encrypted)
      blob = TresorBlob.from_bytes(encrypted)
      updated, added = Tresor.add_all_keys_with_agent(@agent, blob)
      [serialize(updated, armor.nil? ? input_was_armored : armor), added]
    end

    # Removes one key slot from an existing tresor.
    #
    # This operation only edits metadata and does not require the SSH agent to
    # hold the removed key. Removing the final slot is rejected.
    #
    # @param encrypted [String] Binary or armored tresor content.
    # @param fingerprint [String] Fingerprint or unambiguous prefix of the slot to remove.
    # @param armor [Boolean, nil] Output armor mode. `nil` preserves input format.
    # @return [String] Updated encrypted tresor content.
    # @raise [SshTresor::KeyNotFound] when no slot matches the fingerprint.
    # @raise [SshTresor::Error] when attempting to remove the last slot.
    def remove_key(encrypted, fingerprint:, armor: nil)
      input_was_armored = armored?(encrypted)
      blob = TresorBlob.from_bytes(encrypted)
      updated = Tresor.remove_key(blob, fingerprint)
      serialize(updated, armor.nil? ? input_was_armored : armor)
    end

    # Lists keys currently available through the configured SSH agent.
    #
    # @return [Array<SshTresor::AgentKey>] Agent keys with fingerprints, type, and comments.
    # @raise [SshTresor::AgentError] when the SSH agent cannot be queried.
    def list_keys
      @agent.list_keys
    end

    # Lists key slot fingerprints present in encrypted tresor content.
    #
    # This does not require access to an SSH agent because slot fingerprints are
    # stored in the tresor header.
    #
    # @param encrypted [String] Binary or armored tresor content.
    # @return [Array<String>] Raw 32-byte SHA-256 fingerprint bytes for each slot.
    # @raise [SshTresor::Error] when the tresor format is invalid.
    def list_slots(encrypted)
      TresorBlob.from_bytes(encrypted).slot_fingerprints
    end

    private

    def armored?(data)
      data.b.strip.start_with?(TresorBlob::ARMOR_BEGIN)
    end

    def serialize(blob, armor)
      armor ? blob.to_armored : blob.to_bytes
    end
  end
end
