# frozen_string_literal: true

require "openssl"
require "securerandom"

require_relative "error"

module SshTresor
  # Cryptographic primitives used by the envelope encryption construction.
  #
  # This module intentionally exposes small byte-oriented helpers. Higher-level
  # callers should normally use {SshTresor::Vault}.
  #
  # @api private
  module Crypto
    CHALLENGE_SIZE = 32
    MASTER_KEY_SIZE = 32
    NONCE_SIZE = 12
    AUTH_TAG_SIZE = 16

    module_function

    # Generates a random SSH-agent signing challenge.
    #
    # @return [String] 32 random bytes.
    def random_challenge
      SecureRandom.random_bytes(CHALLENGE_SIZE)
    end

    # Generates a fresh data master key.
    #
    # @return [String] 32 random bytes suitable for AES-256.
    def random_master_key
      SecureRandom.random_bytes(MASTER_KEY_SIZE)
    end

    # Generates a fresh AES-GCM nonce.
    #
    # @return [String] 12 random bytes.
    def random_nonce
      SecureRandom.random_bytes(NONCE_SIZE)
    end

    # Derives a slot-wrapping key from SSH-agent signature bytes.
    #
    # @param signature [String] raw signature bytes returned by the SSH agent.
    # @return [String] 32-byte AES key derived with HKDF-SHA256.
    def derive_key(signature)
      OpenSSL::KDF.hkdf(
        signature,
        salt: "ssh-tresor-v3",
        info: "slot-key-derivation",
        length: 32,
        hash: "SHA256"
      )
    end

    # Encrypts plaintext with AES-256-GCM.
    #
    # @param key [String] 32-byte AES key.
    # @param nonce [String] 12-byte AES-GCM nonce.
    # @param plaintext [String] plaintext bytes.
    # @return [String] ciphertext followed by the 16-byte GCM authentication tag.
    # @raise [SshTresor::Error] when OpenSSL encryption fails.
    def encrypt(key, nonce, plaintext)
      cipher = OpenSSL::Cipher.new("aes-256-gcm")
      cipher.encrypt
      cipher.key = key
      cipher.iv = nonce
      cipher.auth_data = "".b

      ciphertext = cipher.update(plaintext.b) + cipher.final
      ciphertext + cipher.auth_tag
    rescue OpenSSL::Cipher::CipherError => e
      raise Error, "Encryption failed: AES-GCM encryption failed: #{e.message}"
    end

    # Decrypts ciphertext produced by {.encrypt}.
    #
    # @param key [String] 32-byte AES key.
    # @param nonce [String] 12-byte AES-GCM nonce.
    # @param ciphertext_with_tag [String] ciphertext followed by the GCM tag.
    # @return [String] plaintext bytes.
    # @raise [SshTresor::DecryptionError] when authentication fails or input is too short.
    def decrypt(key, nonce, ciphertext_with_tag)
      raise DecryptionError, "ciphertext too short" if ciphertext_with_tag.bytesize < AUTH_TAG_SIZE

      ciphertext = ciphertext_with_tag.byteslice(0, ciphertext_with_tag.bytesize - AUTH_TAG_SIZE)
      tag = ciphertext_with_tag.byteslice(-AUTH_TAG_SIZE, AUTH_TAG_SIZE)

      cipher = OpenSSL::Cipher.new("aes-256-gcm")
      cipher.decrypt
      cipher.key = key
      cipher.iv = nonce
      cipher.auth_tag = tag
      cipher.auth_data = "".b

      cipher.update(ciphertext) + cipher.final
    rescue OpenSSL::Cipher::CipherError
      raise DecryptionError, "authentication failed - wrong key or corrupted data"
    end
  end
end
