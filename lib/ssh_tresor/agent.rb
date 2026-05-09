# frozen_string_literal: true

require "base64"
require "digest"
require "socket"

require_relative "error"
require_relative "ssh_encoding"

module SshTresor
  # Public key identity returned by an SSH agent.
  #
  # The key object stores the SSH public-key blob and comment exactly as returned
  # by the agent. Fingerprints are derived from the public blob and are safe to
  # store in tresor metadata.
  #
  # @attr [String] blob SSH wire-format public-key blob.
  # @attr [String] comment Agent-provided key comment.
  AgentKey = Struct.new(:blob, :comment, keyword_init: true) do
    # Raw SHA-256 fingerprint bytes used inside `SSHTRESR` key slots.
    #
    # @return [String] 32-byte SHA-256 digest of the public-key blob.
    def fingerprint_bytes
      @fingerprint_bytes ||= Digest::SHA256.digest(blob)
    end

    # OpenSSH-style SHA-256 fingerprint.
    #
    # @return [String] fingerprint such as `SHA256:abc...`.
    def fingerprint
      "SHA256:#{Base64.strict_encode64(fingerprint_bytes).delete("=")}"
    end

    # Legacy MD5 fingerprint formatted as colon-separated hex.
    #
    # @return [String] MD5 fingerprint text.
    def md5_fingerprint
      Digest::MD5.digest(blob).bytes.map { |byte| "%02x" % byte }.join(":")
    end

    # SSH wire key type from the public-key blob.
    #
    # @return [String] SSH key type, for example `ssh-ed25519` or `ssh-rsa`.
    def ssh_type
      @ssh_type ||= SSHEncoding::Reader.new(blob).string
    end

    # Human-readable key type.
    #
    # @return [String] formatted key type such as `ED25519` or `RSA-3072`.
    def key_type
      @key_type ||= Agent.format_key_type(blob)
    end

    # Whether this is an OpenSSH security-key backed identity.
    #
    # @return [Boolean]
    def security_key?
      ssh_type.start_with?("sk-")
    end

    # Checks whether the key's SHA-256 fingerprint matches a full fingerprint or
    # unambiguous prefix.
    #
    # @param prefix [String] fingerprint with or without the `SHA256:` prefix.
    # @return [Boolean]
    def matches_fingerprint?(prefix)
      normalized_prefix = prefix.delete_prefix("SHA256:")
      normalized_fingerprint = fingerprint.delete_prefix("SHA256:")
      normalized_fingerprint.start_with?(normalized_prefix)
    end

    # @return [String] CLI-friendly key summary.
    def to_s
      "#{fingerprint} #{key_type} #{comment}"
    end
  end

  # Minimal SSH agent protocol client.
  #
  # The agent is used as a private-key signing oracle: `ssh-tresor-ruby` sends a
  # stored random challenge to the agent and derives wrapping keys from the
  # returned signature bytes. The private key itself never leaves the agent.
  class Agent
    SSH_AGENT_FAILURE = 5
    SSH_AGENTC_REQUEST_IDENTITIES = 11
    SSH_AGENT_IDENTITIES_ANSWER = 12
    SSH_AGENTC_SIGN_REQUEST = 13
    SSH_AGENT_SIGN_RESPONSE = 14
    SSH_AGENT_SIGN_REQUEST_RSA_SHA2_256 = 2

    # Opens the SSH agent named by `SSH_AUTH_SOCK`.
    #
    # @return [SshTresor::Agent]
    # @raise [SshTresor::AgentError] when `SSH_AUTH_SOCK` is absent or the socket cannot be opened.
    def self.connect
      socket_path = ENV["SSH_AUTH_SOCK"]
      raise AgentError, "SSH agent not available\nHint: Is SSH_AUTH_SOCK set? Try running: eval $(ssh-agent) && ssh-add" if socket_path.nil? || socket_path.empty?

      new(UNIXSocket.new(socket_path))
    rescue SystemCallError => e
      raise AgentError, "Failed to connect to SSH agent: #{e.message}"
    end

    # Formats a public-key blob into a human-readable key type.
    #
    # @param blob [String] SSH wire-format public-key blob.
    # @return [String] human-readable key type.
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

    # Returns the bit length of a big-endian SSH integer.
    #
    # @param bytes [String] big-endian integer bytes.
    # @return [Integer]
    def self.bit_length(bytes)
      trimmed = bytes.b.sub(/\A\x00+/n, "")
      return 0 if trimmed.empty?

      ((trimmed.bytesize - 1) * 8) + trimmed.getbyte(0).bit_length
    end

    # Creates an agent client over an already-open socket.
    #
    # @param socket [#read, #write] connected SSH agent socket.
    def initialize(socket)
      @socket = socket
    end

    # Lists public keys available through the agent.
    #
    # @return [Array<SshTresor::AgentKey>]
    # @raise [SshTresor::AgentError] when the agent rejects the request or returns invalid data.
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

    # Returns the first available key.
    #
    # @return [SshTresor::AgentKey]
    # @raise [SshTresor::KeyNotFound] when the agent has no loaded keys.
    def first_key
      list_keys.first || raise(KeyNotFound, "No keys available in SSH agent\nHint: Try running: ssh-add")
    end

    # Finds a key by full SHA-256 fingerprint or unambiguous prefix.
    #
    # @param fingerprint [String] fingerprint with or without the `SHA256:` prefix.
    # @return [SshTresor::AgentKey]
    # @raise [SshTresor::KeyNotFound] when no key matches or the prefix is ambiguous.
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

    # Finds a key by the raw SHA-256 fingerprint bytes stored in a tresor slot.
    #
    # @param fingerprint_bytes [String] 32-byte SHA-256 fingerprint digest.
    # @return [SshTresor::AgentKey]
    # @raise [SshTresor::KeyNotFound] when no key matches.
    def find_key_by_fingerprint_bytes(fingerprint_bytes)
      list_keys.find { |key| key.fingerprint_bytes == fingerprint_bytes } ||
        raise(KeyNotFound, "Key not found: SHA256:#{Base64.strict_encode64(fingerprint_bytes).delete("=")}")
    end

    # Signs arbitrary data with an agent key and returns only the raw signature
    # bytes from the SSH agent response.
    #
    # RSA keys are requested with the RSA/SHA-256 signature flag for modern
    # OpenSSH compatibility.
    #
    # @param key [SshTresor::AgentKey] key returned by this agent.
    # @param data [String] challenge bytes to sign.
    # @return [String] raw signature bytes.
    # @raise [SshTresor::AgentError] when the agent refuses or returns invalid data.
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
