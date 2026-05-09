# frozen_string_literal: true

require "openssl"
require "securerandom"

require_relative "error"

module SshTresor
  module Crypto
    CHALLENGE_SIZE = 32
    MASTER_KEY_SIZE = 32
    NONCE_SIZE = 12
    AUTH_TAG_SIZE = 16
    KDF_SALT = "ssh-tresor-ruby-v1".b
    SIGNING_DOMAIN = "ssh-tresor-ruby-v1 slot-key-derivation".b

    module_function

    def random_challenge
      SecureRandom.random_bytes(CHALLENGE_SIZE)
    end

    def random_master_key
      SecureRandom.random_bytes(MASTER_KEY_SIZE)
    end

    def random_nonce
      SecureRandom.random_bytes(NONCE_SIZE)
    end

    def slot_signing_payload(challenge)
      SIGNING_DOMAIN + "\0".b + challenge.b
    end

    def derive_key(signature)
      OpenSSL::KDF.hkdf(
        signature,
        salt: KDF_SALT,
        info: "slot-key-derivation",
        length: 32,
        hash: "SHA256"
      )
    end

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
