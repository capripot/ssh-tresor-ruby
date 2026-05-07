# frozen_string_literal: true

module SshTresor
  class Error < StandardError
    EXIT_GENERAL_ERROR = 1
    EXIT_AGENT_CONNECTION_FAILED = 2
    EXIT_KEY_NOT_FOUND = 3
    EXIT_DECRYPTION_FAILED = 4

    attr_reader :exit_code

    def initialize(message, exit_code: EXIT_GENERAL_ERROR)
      super(message)
      @exit_code = exit_code
    end
  end

  class AgentError < Error
    def initialize(message)
      super(message, exit_code: EXIT_AGENT_CONNECTION_FAILED)
    end
  end

  class KeyNotFound < Error
    def initialize(message)
      super(message, exit_code: EXIT_KEY_NOT_FOUND)
    end
  end

  class NoMatchingSlot < Error
    def initialize
      super(
        "No matching slot found\nHint: None of the keys in your SSH agent can decrypt this tresor",
        exit_code: EXIT_KEY_NOT_FOUND
      )
    end
  end

  class DecryptionError < Error
    def initialize(message)
      super("Decryption failed: #{message}", exit_code: EXIT_DECRYPTION_FAILED)
    end
  end
end

