# frozen_string_literal: true

require "base64"
require "digest"
require "socket"

require_relative "error"
require_relative "ssh_encoding"

module SshTresor
  AgentKey = Struct.new(:blob, :comment, keyword_init: true) do
    def fingerprint_bytes
      @fingerprint_bytes ||= Digest::SHA256.digest(blob)
    end

    def fingerprint
      "SHA256:#{Base64.strict_encode64(fingerprint_bytes).delete("=")}"
    end

    def md5_fingerprint
      Digest::MD5.digest(blob).bytes.map { |byte| "%02x" % byte }.join(":")
    end

    def ssh_type
      @ssh_type ||= SSHEncoding::Reader.new(blob).string
    end

    def key_type
      @key_type ||= Agent.format_key_type(blob)
    end

    def security_key?
      ssh_type.start_with?("sk-")
    end

    def matches_fingerprint?(prefix)
      normalized_prefix = prefix.delete_prefix("SHA256:")
      normalized_fingerprint = fingerprint.delete_prefix("SHA256:")
      normalized_fingerprint.start_with?(normalized_prefix)
    end

    def to_s
      "#{fingerprint} #{key_type} #{comment}"
    end
  end

  class Agent
    SSH_AGENT_FAILURE = 5
    SSH_AGENTC_REQUEST_IDENTITIES = 11
    SSH_AGENT_IDENTITIES_ANSWER = 12
    SSH_AGENTC_SIGN_REQUEST = 13
    SSH_AGENT_SIGN_RESPONSE = 14
    SSH_AGENT_SIGN_REQUEST_RSA_SHA2_256 = 2

    def self.connect
      socket_path = ENV["SSH_AUTH_SOCK"]
      raise AgentError, "SSH agent not available\nHint: Is SSH_AUTH_SOCK set? Try running: eval $(ssh-agent) && ssh-add" if socket_path.nil? || socket_path.empty?

      new(UNIXSocket.new(socket_path))
    rescue SystemCallError => e
      raise AgentError, "Failed to connect to SSH agent: #{e.message}"
    end

    def self.format_key_type(blob)
      reader = SSHEncoding::Reader.new(blob)
      type = reader.string

      case type
      when "ssh-ed25519"
        "ED25519"
      when "ssh-rsa"
        reader.string
        n = reader.string
        "RSA-#{bit_length(n)}"
      when /\Aecdsa-sha2-/
        curve = reader.string
        "ECDSA-#{curve.delete_prefix("nistp")}"
      when "sk-ssh-ed25519@openssh.com"
        "SK-ED25519"
      when "sk-ecdsa-sha2-nistp256@openssh.com"
        "SK-ECDSA-256"
      else
        type.upcase
      end
    rescue Error
      "UNKNOWN"
    end

    def self.bit_length(bytes)
      trimmed = bytes.b.sub(/\A\x00+/n, "")
      return 0 if trimmed.empty?

      ((trimmed.bytesize - 1) * 8) + trimmed.getbyte(0).bit_length
    end

    def initialize(socket)
      @socket = socket
    end

    def list_keys
      response = request(SSHEncoding.byte(SSH_AGENTC_REQUEST_IDENTITIES))
      reader = SSHEncoding::Reader.new(response)
      type = reader.byte
      raise AgentError, "SSH agent refused identity request" if type == SSH_AGENT_FAILURE
      raise AgentError, "Unexpected SSH agent response type #{type}" unless type == SSH_AGENT_IDENTITIES_ANSWER

      count = reader.uint32
      Array.new(count) do
        blob = reader.string
        comment = reader.string.force_encoding(Encoding::UTF_8)
        comment = comment.valid_encoding? ? comment : comment.b.inspect
        AgentKey.new(blob: blob, comment: comment)
      end
    end

    def first_key
      list_keys.first || raise(KeyNotFound, "No keys available in SSH agent\nHint: Try running: ssh-add")
    end

    def find_key(fingerprint)
      matches = list_keys.select { |key| key.matches_fingerprint?(fingerprint) }

      case matches.length
      when 0
        raise KeyNotFound, "Key not found: #{fingerprint}\nHint: Use 'ssh-tresor list-keys' to see available keys"
      when 1
        matches.first
      else
        raise KeyNotFound, "Key not found: #{fingerprint} (ambiguous: #{matches.length} keys match this prefix, please be more specific)"
      end
    end

    def find_key_by_fingerprint_bytes(fingerprint_bytes)
      list_keys.find { |key| key.fingerprint_bytes == fingerprint_bytes } ||
        raise(KeyNotFound, "Key not found: SHA256:#{Base64.strict_encode64(fingerprint_bytes).delete("=")}")
    end

    def sign(key, data)
      flags = key.ssh_type == "ssh-rsa" ? SSH_AGENT_SIGN_REQUEST_RSA_SHA2_256 : 0
      payload = SSHEncoding.byte(SSH_AGENTC_SIGN_REQUEST) +
                SSHEncoding.string(key.blob) +
                SSHEncoding.string(data) +
                SSHEncoding.uint32(flags)

      response = request(payload)
      reader = SSHEncoding::Reader.new(response)
      type = reader.byte
      raise AgentError, "SSH agent refused signing request" if type == SSH_AGENT_FAILURE
      raise AgentError, "Unexpected SSH agent response type #{type}" unless type == SSH_AGENT_SIGN_RESPONSE

      signature_blob = reader.string
      signature_reader = SSHEncoding::Reader.new(signature_blob)
      signature_reader.string
      signature_reader.string
    end

    private

    def request(payload)
      @socket.write(SSHEncoding.uint32(payload.bytesize))
      @socket.write(payload)

      length = read_exact(4).unpack1("N")
      read_exact(length)
    rescue IOError, SystemCallError => e
      raise AgentError, "SSH agent communication failed: #{e.message}"
    end

    def read_exact(length)
      buffer = +"".b
      while buffer.bytesize < length
        chunk = @socket.read(length - buffer.bytesize)
        raise AgentError, "SSH agent closed connection" if chunk.nil?

        buffer << chunk
      end
      buffer
    end
  end
end

