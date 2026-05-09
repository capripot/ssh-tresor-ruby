# frozen_string_literal: true

module SshTresor
  # Helpers for the SSH agent wire encoding.
  #
  # SSH strings are length-prefixed binary strings. These helpers are internal
  # to the agent protocol implementation.
  #
  # @api private
  module SSHEncoding
    module_function

    # @param value [Integer] byte value.
    # @return [String] one-byte binary string.
    def byte(value)
      value.chr.b
    end

    # @param value [Integer] unsigned 32-bit integer.
    # @return [String] network-byte-order integer bytes.
    def uint32(value)
      [value].pack("N")
    end

    # @param value [String] binary string.
    # @return [String] SSH length-prefixed string.
    def string(value)
      bytes = value.b
      uint32(bytes.bytesize) + bytes
    end

    # Sequential reader for SSH wire values.
    #
    # @api private
    class Reader
      # @param data [String] binary SSH wire data.
      def initialize(data)
        @data = data.b
        @offset = 0
      end

      # @return [Integer] next byte value.
      def byte
        read(1).getbyte(0)
      end

      # @return [Integer] next unsigned 32-bit integer.
      def uint32
        read(4).unpack1("N")
      end

      # @return [String] next SSH length-prefixed string.
      def string
        length = uint32
        read(length)
      end

      # @return [Boolean] whether the reader consumed all input.
      def eof?
        @offset == @data.bytesize
      end

      private

      def read(length)
        raise Error, "Invalid SSH wire data: short read" if @offset + length > @data.bytesize

        bytes = @data.byteslice(@offset, length)
        @offset += length
        bytes
      end
    end
  end
end
