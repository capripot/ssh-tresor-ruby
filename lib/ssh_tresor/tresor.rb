# frozen_string_literal: true

require_relative "agent"
require_relative "crypto"
require_relative "format"
require "base64"

module SshTresor
  module Tresor
    module_function

    def encrypt(plaintext, fingerprints: [])
      encrypt_with_agent(Agent.connect, plaintext, fingerprints: fingerprints)
    end

    def encrypt_with_agent(agent, plaintext, fingerprints: [])
      keys = if fingerprints.empty?
               [agent.first_key]
             else
               fingerprints.map { |fingerprint| agent.find_key(fingerprint) }
             end

      encrypt_with_keys(agent, keys, plaintext)
    end

    def decrypt(blob)
      decrypt_with_agent(Agent.connect, blob)
    end

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

    def add_key(blob, fingerprint)
      add_key_with_agent(Agent.connect, blob, fingerprint)
    end

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

    def add_all_keys(blob)
      add_all_keys_with_agent(Agent.connect, blob)
    end

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

    def remove_key(blob, fingerprint)
      raise Error, "Invalid tresor format: cannot remove the last key from tresor" if blob.slots.length == 1

      fingerprint_bytes = resolve_slot_fingerprint(blob, fingerprint)
      new_slots = blob.slots.reject { |slot| slot.fingerprint == fingerprint_bytes }

      raise KeyNotFound, "Key not found: #{fingerprint}" if new_slots.length == blob.slots.length

      TresorBlob.new(slots: new_slots, data_nonce: blob.data_nonce, ciphertext: blob.ciphertext)
    end

    def list_keys
      Agent.connect.list_keys
    end

    def list_slots(blob)
      blob.slot_fingerprints
    end

    def encrypt_with_keys(agent, keys, plaintext)
      master_key = Crypto.random_master_key
      slots = keys.map { |key| create_slot(agent, key, master_key) }
      data_nonce = Crypto.random_nonce
      ciphertext = Crypto.encrypt(master_key, data_nonce, plaintext)

      TresorBlob.new(slots: slots, data_nonce: data_nonce, ciphertext: ciphertext)
    end

    def create_slot(agent, key, master_key)
      challenge = Crypto.random_challenge
      signature = sign_slot_challenge(agent, key, challenge)
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

    def decrypt_with_slot(agent, key, slot, blob)
      master_key = decrypt_slot_master_key(agent, key, slot)
      Crypto.decrypt(master_key, blob.data_nonce, blob.ciphertext)
    end

    def recover_master_key(agent, blob)
      agent.list_keys.each do |key|
        slot = blob.find_slot(key.fingerprint_bytes)
        next if slot.nil?

        begin
          return decrypt_slot_master_key(agent, key, slot)
        rescue DecryptionError
          next
        end
      end

      raise NoMatchingSlot
    end

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

    def sign_slot_challenge(agent, key, challenge)
      agent.sign(key, Crypto.slot_signing_payload(challenge))
    end

    def decrypt_slot_master_key(agent, key, slot)
      signature = agent.sign(key, Crypto.slot_signing_payload(slot.challenge))
      slot_key = Crypto.derive_key(signature)
      Crypto.decrypt(slot_key, slot.nonce, slot.encrypted_key)
    end
  end
end
