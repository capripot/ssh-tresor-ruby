# frozen_string_literal: true

require "base64"
require "optparse"

require_relative "../ssh_tresor"

module SshTresor
  # Command-line interface for the `ssh-tresor` executable.
  #
  # This class is intentionally small and delegates cryptographic operations to
  # {SshTresor::Tresor}. Library callers should use {SshTresor::Vault} instead.
  #
  # @api private
  class CLI
    # @param argv [Array<String>] command-line arguments excluding executable name.
    def initialize(argv)
      @argv = argv.dup
    end

    # Dispatches the requested CLI command.
    #
    # @return [Integer] process exit code.
    def run
      command = @argv.shift
      return help if command.nil? || %w[-h --help help].include?(command)
      return version if %w[-v --version version].include?(command)

      case command
      when "encrypt"
        encrypt_command
      when "decrypt"
        decrypt_command
      when "add-key"
        add_key_command
      when "remove-key"
        remove_key_command
      when "list-slots"
        list_slots_command
      when "list-keys"
        list_keys_command
      else
        warn "Unknown command: #{command}"
        help(1)
      end
    rescue Error => e
      warn "Error: #{e.message}"
      e.exit_code
    rescue OptionParser::ParseError => e
      warn "Error: #{e.message}"
      Error::EXIT_GENERAL_ERROR
    end

    private

    def help(exit_code = 0)
      io = exit_code.zero? ? $stdout : $stderr
      io.puts <<~HELP
        Usage: ssh-tresor <command> [options]

        Provides SSH-agent-mediated encryption at rest. Decryption requires a
        live SSH agent signing capability, not merely the public key.

        Commands:
          encrypt       Encrypt data using SSH agent signing
          decrypt       Decrypt data using SSH agent signing
          add-key       Add a key to an existing tresor
          remove-key    Remove a key from an existing tresor
          list-slots    List key slots in a tresor
          list-keys     List available keys in the SSH agent
      HELP
      exit_code
    end

    def version
      puts SshTresor::VERSION
      0
    end

    def encrypt_command
      options = { fingerprints: [], armor: false }
      parser = OptionParser.new do |opts|
        opts.on("-k", "--key FINGERPRINT") { |value| options[:fingerprints] << value }
        opts.on("-o", "--output FILE") { |value| options[:output] = value }
        opts.on("-a", "--armor") { options[:armor] = true }
      end
      parser.parse!(@argv)

      plaintext = read_input(@argv.shift)
      blob = Tresor.encrypt(plaintext, fingerprints: options[:fingerprints])
      output = options[:armor] ? blob.to_armored : blob.to_bytes
      write_output(options[:output], output)
      0
    end

    def decrypt_command
      options = {}
      parser = OptionParser.new do |opts|
        opts.on("-o", "--output FILE") { |value| options[:output] = value }
      end
      parser.parse!(@argv)

      encrypted = read_input(@argv.shift)
      blob = TresorBlob.from_bytes(encrypted)
      write_output(options[:output], Tresor.decrypt(blob))
      0
    end

    def add_key_command
      options = { all: false, armor: false, in_place: false }
      parser = OptionParser.new do |opts|
        opts.on("-k", "--key FINGERPRINT") { |value| options[:fingerprint] = value }
        opts.on("-a", "--all") { options[:all] = true }
        opts.on("-i", "--in-place") { options[:in_place] = true }
        opts.on("-o", "--output FILE") { |value| options[:output] = value }
        opts.on("--armor") { options[:armor] = true }
      end
      parser.parse!(@argv)

      raise Error, "Invalid arguments: either --key or --all must be specified" if options[:fingerprint].nil? && !options[:all]
      raise Error, "Invalid arguments: --key and --all are mutually exclusive" if options[:fingerprint] && options[:all]

      input = @argv.shift
      encrypted = read_input(input)
      was_armored = armored?(encrypted)
      blob = TresorBlob.from_bytes(encrypted)

      updated = if options[:all]
                  new_blob, added = Tresor.add_all_keys(blob)
                  warn(added.zero? ? "No new keys added (all keys already present or unavailable)" : "Added #{added} key(s)")
                  new_blob
                else
                  Tresor.add_key(blob, options[:fingerprint])
                end

      output = serialize(updated, options[:armor] || was_armored)
      write_output(options[:in_place] ? input : options[:output], output)
      0
    end

    def remove_key_command
      options = { armor: false, in_place: false }
      parser = OptionParser.new do |opts|
        opts.on("-k", "--key FINGERPRINT") { |value| options[:fingerprint] = value }
        opts.on("-i", "--in-place") { options[:in_place] = true }
        opts.on("-o", "--output FILE") { |value| options[:output] = value }
        opts.on("--armor") { options[:armor] = true }
      end
      parser.parse!(@argv)

      raise Error, "Invalid arguments: --key is required" if options[:fingerprint].nil?

      input = @argv.shift
      encrypted = read_input(input)
      was_armored = armored?(encrypted)
      blob = TresorBlob.from_bytes(encrypted)
      updated = Tresor.remove_key(blob, options[:fingerprint])
      output = serialize(updated, options[:armor] || was_armored)
      write_output(options[:in_place] ? input : options[:output], output)
      0
    end

    def list_slots_command
      encrypted = read_input(@argv.shift)
      blob = TresorBlob.from_bytes(encrypted)
      agent_keys = begin
        Tresor.list_keys
      rescue AgentError
        []
      end

      puts "Tresor contains #{blob.slots.length} key slot(s):"
      blob.slot_fingerprints.each_with_index do |fingerprint, index|
        fingerprint_text = "SHA256:#{Base64.strict_encode64(fingerprint).delete("=")}"
        key = agent_keys.find { |agent_key| agent_key.fingerprint_bytes == fingerprint }
        availability = key ? " #{key.key_type} #{key.comment} [AVAILABLE]" : ""
        puts "  Slot #{index + 1}: #{fingerprint_text}#{availability}"
      end
      0
    end

    def list_keys_command
      options = { md5: false }
      parser = OptionParser.new do |opts|
        opts.on("--md5") { options[:md5] = true }
      end
      parser.parse!(@argv)

      keys = Tresor.list_keys
      raise KeyNotFound, "No keys available in SSH agent\nHint: Try running: ssh-add" if keys.empty?

      keys.each do |key|
        puts(options[:md5] ? "#{key.md5_fingerprint} #{key.key_type} #{key.comment}" : key.to_s)
      end
      0
    end

    def read_input(path)
      bytes = if path.nil? || path == "-"
                $stdin.binmode.read
              else
                File.binread(path)
              end

      if bytes.bytesize > TresorBlob::MAX_TRESOR_SIZE
        raise Error, "Invalid tresor format: input too large: #{bytes.bytesize} bytes, maximum #{TresorBlob::MAX_TRESOR_SIZE} bytes"
      end

      bytes
    end

    def write_output(path, data)
      if path.nil?
        $stdout.binmode.write(data)
      else
        File.binwrite(path, data)
      end
    end

    def armored?(data)
      data.b.strip.start_with?(TresorBlob::ARMOR_BEGIN)
    end

    def serialize(blob, armor)
      armor ? blob.to_armored : blob.to_bytes
    end
  end
end
