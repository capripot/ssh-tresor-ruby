# frozen_string_literal: true

require "base64"

require_relative "crypto"
require_relative "error"

module SshTresor
  # One key-wrapping slot in a `SSHTRESR` blob.
  #
  # A slot stores public metadata plus an encrypted copy of the data master key.
  # The slot key is not stored; it is re-derived from an SSH-agent signature over
  # the stored challenge.
  #
  # @attr [String] fingerprint raw 32-byte SHA-256 public-key fingerprint.
  # @attr [String] challenge random challenge signed by the SSH agent.
  # @attr [String] nonce AES-GCM nonce for the encrypted master key.
  # @attr [String] encrypted_key AES-GCM ciphertext and tag for the master key.
  Slot = Struct.new(:fingerprint, :challenge, :nonce, :encrypted_key, keyword_init: true) do
    # Serializes the fixed-width slot fields.
    #
    # @return [String] binary slot data.
    def to_bytes
      fingerprint + challenge + nonce + encrypted_key
    end
  end

  # Parsed `SSHTRESR` v3 encrypted file.
  #
  # A blob contains one or more key slots and one AES-256-GCM encrypted payload.
  # It can be read from or written to the binary wire format, and it can also be
  # represented as base64 armor for terminal-friendly transport.
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

    # Parses binary or armored tresor content.
    #
    # @param data [String] binary `SSHTRESR` bytes or armored text.
    # @return [SshTresor::TresorBlob]
    # @raise [SshTresor::Error] when the input is malformed or unsupported.
    def self.from_bytes(data)
      bytes = data.b
      if bytes.valid_encoding? && bytes.strip.start_with?(ARMOR_BEGIN)
        from_armored(bytes)
      else
        from_binary(bytes)
      end
    end

    # Parses armored tresor text.
    #
    # @param text [String] armor containing base64 encoded binary data.
    # @return [SshTresor::TresorBlob]
    # @raise [SshTresor::Error] when the armor is malformed.
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

    # Parses binary `SSHTRESR` v3 bytes.
    #
    # @param data [String] binary tresor data.
    # @return [SshTresor::TresorBlob]
    # @raise [SshTresor::Error] when the binary format is invalid.
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

    # Parses a fixed-width key slot from binary data.
    #
    # @param bytes [String] binary slot data.
    # @return [SshTresor::Slot]
    # @raise [SshTresor::Error] when the slot is too short.
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

    # Creates an in-memory tresor blob.
    #
    # @param slots [Array<SshTresor::Slot>] key-wrapping slots.
    # @param data_nonce [String] AES-GCM nonce for the payload ciphertext.
    # @param ciphertext [String] payload ciphertext with authentication tag.
    def initialize(slots:, data_nonce:, ciphertext:)
      @slots = slots
      @data_nonce = data_nonce
      @ciphertext = ciphertext
    end

    # Serializes the blob as binary `SSHTRESR` v3 bytes.
    #
    # @return [String] binary tresor data.
    # @raise [SshTresor::Error] when the blob has no slots or too many slots.
    def to_bytes
      raise Error, "Invalid tresor format: tresor has no key slots" if slots.empty?
      raise Error, "Invalid tresor format: tresor has too many slots (max 255)" if slots.length > 255

      MAGIC + [VERSION, slots.length].pack("CC") + slots.map(&:to_bytes).join.b + data_nonce + ciphertext
    end

    # Serializes the blob as PEM-like base64 armor.
    #
    # @return [String] armored tresor text.
    def to_armored
      encoded = Base64.strict_encode64(to_bytes)
      wrapped = encoded.scan(/.{1,64}/).join("\n")
      "#{ARMOR_BEGIN}\n#{wrapped}\n#{ARMOR_END}\n"
    end

    # Finds a slot by raw SHA-256 fingerprint bytes.
    #
    # @param fingerprint [String] 32-byte SHA-256 fingerprint digest.
    # @return [SshTresor::Slot, nil]
    def find_slot(fingerprint)
      slots.find { |slot| slot.fingerprint == fingerprint }
    end

    # Lists raw slot fingerprints.
    #
    # @return [Array<String>] raw 32-byte SHA-256 fingerprint bytes.
    def slot_fingerprints
      slots.map(&:fingerprint)
    end
  end
end
