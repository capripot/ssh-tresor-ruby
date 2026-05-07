# frozen_string_literal: true

module SshTresor
  module SSHEncoding
    module_function

    def byte(value)
      value.chr.b
    end

    def uint32(value)
      [value].pack("N")
    end

    def string(value)
      bytes = value.b
      uint32(bytes.bytesize) + bytes
    end

    class Reader
      def initialize(data)
        @data = data.b
        @offset = 0
      end

      def byte
        read(1).getbyte(0)
      end

      def uint32
        read(4).unpack1("N")
      end

      def string
        length = uint32
        read(length)
      end

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

