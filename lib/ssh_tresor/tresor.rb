# frozen_string_literal: true

require_relative "agent"
require_relative "crypto"
require_relative "format"
require "base64"

module SshTresor
  # Lower-level envelope encryption operations.
  #
  # `Tresor` works directly with {SshTresor::TresorBlob} instances and an SSH
  # agent. Most applications should prefer {SshTresor::Vault}, which handles
  # parsing and serialization.
  #
  # @see SshTresor::Vault
  # @see SshTresor::TresorBlob
  module Tresor
    module_function

    # Encrypts plaintext using the default SSH agent from `SSH_AUTH_SOCK`.
    #
    # @param plaintext [String] plaintext bytes.
    # @param fingerprints [Array<String>] optional key fingerprints to encrypt for.
    # @return [SshTresor::TresorBlob]
    def encrypt(plaintext, fingerprints: [])
      encrypt_with_agent(Agent.connect, plaintext, fingerprints: fingerprints)
    end

    # Encrypts plaintext using a supplied SSH agent.
    #
    # @param agent [SshTresor::Agent] SSH agent or compatible object.
    # @param plaintext [String] plaintext bytes.
    # @param fingerprints [Array<String>] optional key fingerprints to encrypt for.
    # @return [SshTresor::TresorBlob]
    # @raise [SshTresor::KeyNotFound] when a requested key is unavailable.
    def encrypt_with_agent(agent, plaintext, fingerprints: [])
      keys = if fingerprints.empty?
               [agent.first_key]
             else
               fingerprints.map { |fingerprint| agent.find_key(fingerprint) }
             end

      encrypt_with_keys(agent, keys, plaintext)
    end

    # Decrypts a blob using the default SSH agent from `SSH_AUTH_SOCK`.
    #
    # @param blob [SshTresor::TresorBlob]
    # @return [String] plaintext bytes.
    def decrypt(blob)
      decrypt_with_agent(Agent.connect, blob)
    end

    # Decrypts a blob using any matching key available in the supplied agent.
    #
    # @param agent [SshTresor::Agent] SSH agent or compatible object.
    # @param blob [SshTresor::TresorBlob]
    # @return [String] plaintext bytes.
    # @raise [SshTresor::NoMatchingSlot] when no available key can decrypt it.
    def decrypt_with_agent(agent, blob)
      keys = agent.list_keys.sort_by(&:security_key?)

      keys.each do |key|
        slot = blob.find_slot(key.fingerprint_bytes)
        next if slot.nil?

        begin
          return decrypt_with_slot(agent, key, slot, blob)
        rescue DecryptionError
          next
        end
      end

      raise NoMatchingSlot
    end

    # Adds one key slot using the default SSH agent.
    #
    # @param blob [SshTresor::TresorBlob]
    # @param fingerprint [String] fingerprint or unambiguous prefix of the key to add.
    # @return [SshTresor::TresorBlob]
    def add_key(blob, fingerprint)
      add_key_with_agent(Agent.connect, blob, fingerprint)
    end

    # Adds one key slot using a supplied SSH agent.
    #
    # @param agent [SshTresor::Agent] SSH agent or compatible object.
    # @param blob [SshTresor::TresorBlob]
    # @param fingerprint [String] fingerprint or unambiguous prefix of the key to add.
    # @return [SshTresor::TresorBlob]
    # @raise [SshTresor::NoMatchingSlot] when the current agent cannot unlock the blob.
    # @raise [SshTresor::KeyNotFound] when the new key is unavailable.
    def add_key_with_agent(agent, blob, fingerprint)
      master_key = recover_master_key(agent, blob)
      new_key = agent.find_key(fingerprint)

      raise Error, "Invalid tresor format: key already exists in tresor" if blob.find_slot(new_key.fingerprint_bytes)

      TresorBlob.new(
        slots: blob.slots + [create_slot(agent, new_key, master_key)],
        data_nonce: blob.data_nonce,
        ciphertext: blob.ciphertext
      )
    end

    # Adds slots for all currently available SSH agent keys.
    #
    # @param blob [SshTresor::TresorBlob]
    # @return [Array(SshTresor::TresorBlob, Integer)] updated blob and added slot count.
    def add_all_keys(blob)
      add_all_keys_with_agent(Agent.connect, blob)
    end

    # Adds slots for all currently available keys from a supplied SSH agent.
    #
    # @param agent [SshTresor::Agent] SSH agent or compatible object.
    # @param blob [SshTresor::TresorBlob]
    # @return [Array(SshTresor::TresorBlob, Integer)] updated blob and added slot count.
    def add_all_keys_with_agent(agent, blob)
      master_key = recover_master_key(agent, blob)
      new_slots = blob.slots.dup
      added = 0

      agent.list_keys.each do |key|
        next if blob.find_slot(key.fingerprint_bytes)

        begin
          new_slots << create_slot(agent, key, master_key)
          added += 1
        rescue Error
          next
        end
      end

      [TresorBlob.new(slots: new_slots, data_nonce: blob.data_nonce, ciphertext: blob.ciphertext), added]
    end

    # Removes one key slot by fingerprint or unambiguous prefix.
    #
    # @param blob [SshTresor::TresorBlob]
    # @param fingerprint [String] fingerprint or unambiguous prefix of the slot to remove.
    # @return [SshTresor::TresorBlob]
    # @raise [SshTresor::Error] when removing the final slot.
    # @raise [SshTresor::KeyNotFound] when no slot matches.
    def remove_key(blob, fingerprint)
      raise Error, "Invalid tresor format: cannot remove the last key from tresor" if blob.slots.length == 1

      fingerprint_bytes = resolve_slot_fingerprint(blob, fingerprint)
      new_slots = blob.slots.reject { |slot| slot.fingerprint == fingerprint_bytes }

      raise KeyNotFound, "Key not found: #{fingerprint}" if new_slots.length == blob.slots.length

      TresorBlob.new(slots: new_slots, data_nonce: blob.data_nonce, ciphertext: blob.ciphertext)
    end

    # Lists keys currently available through the default SSH agent.
    #
    # @return [Array<SshTresor::AgentKey>]
    def list_keys
      Agent.connect.list_keys
    end

    # Lists raw slot fingerprints stored in a blob.
    #
    # @param blob [SshTresor::TresorBlob]
    # @return [Array<String>] raw 32-byte SHA-256 fingerprint bytes.
    def list_slots(blob)
      blob.slot_fingerprints
    end

    # Encrypts plaintext for concrete agent keys.
    #
    # @api private
    def encrypt_with_keys(agent, keys, plaintext)
      master_key = Crypto.random_master_key
      slots = keys.map { |key| create_slot(agent, key, master_key) }
      data_nonce = Crypto.random_nonce
      ciphertext = Crypto.encrypt(master_key, data_nonce, plaintext)

      TresorBlob.new(slots: slots, data_nonce: data_nonce, ciphertext: ciphertext)
    end

    # Creates one encrypted master-key slot.
    #
    # @api private
    def create_slot(agent, key, master_key)
      challenge = Crypto.random_challenge
      signature = agent.sign(key, challenge)
      slot_key = Crypto.derive_key(signature)
      nonce = Crypto.random_nonce
      encrypted_key = Crypto.encrypt(slot_key, nonce, master_key)

      Slot.new(
        fingerprint: key.fingerprint_bytes,
        challenge: challenge,
        nonce: nonce,
        encrypted_key: encrypted_key
      )
    end

    # Decrypts a blob through one matching slot.
    #
    # @api private
    def decrypt_with_slot(agent, key, slot, blob)
      signature = agent.sign(key, slot.challenge)
      slot_key = Crypto.derive_key(signature)
      master_key = Crypto.decrypt(slot_key, slot.nonce, slot.encrypted_key)
      Crypto.decrypt(master_key, blob.data_nonce, blob.ciphertext)
    end

    # Recovers the data master key from any matching slot.
    #
    # @api private
    def recover_master_key(agent, blob)
      agent.list_keys.each do |key|
        slot = blob.find_slot(key.fingerprint_bytes)
        next if slot.nil?

        begin
          signature = agent.sign(key, slot.challenge)
          slot_key = Crypto.derive_key(signature)
          return Crypto.decrypt(slot_key, slot.nonce, slot.encrypted_key)
        rescue DecryptionError
          next
        end
      end

      raise NoMatchingSlot
    end

    # Resolves a slot fingerprint prefix to raw fingerprint bytes.
    #
    # @api private
    def resolve_slot_fingerprint(blob, fingerprint)
      normalized = fingerprint.delete_prefix("SHA256:")
      matches = blob.slot_fingerprints.select do |slot_fingerprint|
        Base64.strict_encode64(slot_fingerprint).delete("=").start_with?(normalized)
      end

      case matches.length
      when 0
        raise KeyNotFound, "Key not found: #{fingerprint}"
      when 1
        matches.first
      else
        raise KeyNotFound, "Key not found: #{fingerprint} (ambiguous: #{matches.length} slots match this prefix, please be more specific)"
      end
    end
  end
end
