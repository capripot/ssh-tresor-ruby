# frozen_string_literal: true

module SshTresor
  # Base error class for all ssh-tresor-ruby failures.
  #
  # CLI callers use {#exit_code} to map domain failures to stable process exit
  # statuses.
  class Error < StandardError
    EXIT_GENERAL_ERROR = 1
    EXIT_AGENT_CONNECTION_FAILED = 2
    EXIT_KEY_NOT_FOUND = 3
    EXIT_DECRYPTION_FAILED = 4

    attr_reader :exit_code

    # @param message [String] human-readable error message.
    # @param exit_code [Integer] process exit code used by the CLI.
    def initialize(message, exit_code: EXIT_GENERAL_ERROR)
      super(message)
      @exit_code = exit_code
    end
  end

  # Raised when the configured SSH agent cannot be reached or refuses a request.
  class AgentError < Error
    def initialize(message)
      super(message, exit_code: EXIT_AGENT_CONNECTION_FAILED)
    end
  end

  # Raised when a requested SSH key or key slot cannot be found.
  class KeyNotFound < Error
    def initialize(message)
      super(message, exit_code: EXIT_KEY_NOT_FOUND)
    end
  end

  # Raised when no loaded agent key can decrypt any slot in a tresor.
  class NoMatchingSlot < Error
    def initialize
      super(
        "No matching slot found\n" \
        "Hint: Decryption requires a matching SSH agent signing capability, " \
        "not just the public key",
        exit_code: EXIT_KEY_NOT_FOUND
      )
    end
  end

  # Raised when AES-GCM authentication or decryption fails.
  class DecryptionError < Error
    def initialize(message)
      super("Decryption failed: #{message}", exit_code: EXIT_DECRYPTION_FAILED)
    end
  end
end
