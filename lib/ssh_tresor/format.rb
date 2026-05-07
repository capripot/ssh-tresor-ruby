# frozen_string_literal: true

require "base64"

require_relative "crypto"
require_relative "error"

module SshTresor
  Slot = Struct.new(:fingerprint, :challenge, :nonce, :encrypted_key, keyword_init: true) do
    def to_bytes
      fingerprint + challenge + nonce + encrypted_key
    end
  end

  class TresorBlob
    MAGIC = "SSHTRESR".b
    VERSION = 0x03
    FINGERPRINT_SIZE = 32
    CHALLENGE_SIZE = 32
    NONCE_SIZE = 12
    AUTH_TAG_SIZE = 16
    MASTER_KEY_SIZE = 32
    ENCRYPTED_KEY_SIZE = MASTER_KEY_SIZE + AUTH_TAG_SIZE
    SLOT_SIZE = FINGERPRINT_SIZE + CHALLENGE_SIZE + NONCE_SIZE + ENCRYPTED_KEY_SIZE
    HEADER_SIZE = 10
    MAX_TRESOR_SIZE = 100 * 1024 * 1024
    ARMOR_BEGIN = "-----BEGIN SSH TRESOR-----"
    ARMOR_END = "-----END SSH TRESOR-----"

    attr_reader :slots, :data_nonce, :ciphertext

    def self.from_bytes(data)
      bytes = data.b
      if bytes.valid_encoding? && bytes.strip.start_with?(ARMOR_BEGIN)
        from_armored(bytes)
      else
        from_binary(bytes)
      end
    end

    def self.from_armored(text)
      start = text.index(ARMOR_BEGIN)
      finish = text.index(ARMOR_END)
      raise Error, "Invalid tresor format: missing BEGIN header" if start.nil?
      raise Error, "Invalid tresor format: missing END footer" if finish.nil?
      raise Error, "Invalid tresor format: invalid armor structure" if start >= finish

      base64 = text[(start + ARMOR_BEGIN.length)...finish].chars.reject { |char| char =~ /\s/ }.join
      from_binary(Base64.strict_decode64(base64))
    rescue ArgumentError => e
      raise Error, "Invalid tresor format: base64 decoding failed: #{e.message}"
    end

    def self.from_binary(data)
      min_size = HEADER_SIZE + SLOT_SIZE + NONCE_SIZE + AUTH_TAG_SIZE
      raise Error, "Invalid tresor format: data too short: #{data.bytesize} bytes, minimum #{min_size} required" if data.bytesize < min_size
      raise Error, "Invalid tresor format: invalid magic header" unless data.byteslice(0, 8) == MAGIC

      version = data.getbyte(8)
      raise Error, "Invalid tresor format: unsupported version: #{version}, expected #{VERSION}" unless version == VERSION

      slot_count = data.getbyte(9)
      raise Error, "Invalid tresor format: tresor has no key slots" if slot_count.zero?

      slots_end = HEADER_SIZE + (slot_count * SLOT_SIZE)
      raise Error, "Invalid tresor format: data too short for #{slot_count} slots" if data.bytesize < slots_end + NONCE_SIZE + AUTH_TAG_SIZE

      slots = Array.new(slot_count) do |index|
        offset = HEADER_SIZE + (index * SLOT_SIZE)
        parse_slot(data.byteslice(offset, SLOT_SIZE))
      end

      data_nonce = data.byteslice(slots_end, NONCE_SIZE)
      ciphertext = data.byteslice(slots_end + NONCE_SIZE, data.bytesize - slots_end - NONCE_SIZE)

      new(slots: slots, data_nonce: data_nonce, ciphertext: ciphertext)
    end

    def self.parse_slot(bytes)
      raise Error, "Invalid tresor format: slot data too short" if bytes.bytesize < SLOT_SIZE

      offset = 0
      fingerprint = bytes.byteslice(offset, FINGERPRINT_SIZE)
      offset += FINGERPRINT_SIZE
      challenge = bytes.byteslice(offset, CHALLENGE_SIZE)
      offset += CHALLENGE_SIZE
      nonce = bytes.byteslice(offset, NONCE_SIZE)
      offset += NONCE_SIZE
      encrypted_key = bytes.byteslice(offset, ENCRYPTED_KEY_SIZE)

      Slot.new(
        fingerprint: fingerprint,
        challenge: challenge,
        nonce: nonce,
        encrypted_key: encrypted_key
      )
    end

    def initialize(slots:, data_nonce:, ciphertext:)
      @slots = slots
      @data_nonce = data_nonce
      @ciphertext = ciphertext
    end

    def to_bytes
      raise Error, "Invalid tresor format: tresor has no key slots" if slots.empty?
      raise Error, "Invalid tresor format: tresor has too many slots (max 255)" if slots.length > 255

      MAGIC + [VERSION, slots.length].pack("CC") + slots.map(&:to_bytes).join.b + data_nonce + ciphertext
    end

    def to_armored
      encoded = Base64.strict_encode64(to_bytes)
      wrapped = encoded.scan(/.{1,64}/).join("\n")
      "#{ARMOR_BEGIN}\n#{wrapped}\n#{ARMOR_END}\n"
    end

    def find_slot(fingerprint)
      slots.find { |slot| slot.fingerprint == fingerprint }
    end

    def slot_fingerprints
      slots.map(&:fingerprint)
    end
  end
end

