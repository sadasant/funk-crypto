module Crypto
  class DES3CBC
    attr_accessor :iv
    @iv = "0000000000000000"

    def self.fill_data data
      bytes = data.length / 2

      return data + '80'                          if bytes % 8 == 14
      return data + "80" + "00" * (7 - bytes % 8) if bytes % 8 != 0

      return data
    end

    def self.encrypt_block(block_hex, key)
      key   = [key].pack("H*")
      key   = DES::Block.new(key)
      block = [block_hex].pack("H*")
      block = DES::Block.new(block)
      des   = DES::Ctx.new(block, key)

      encrypted_data = des.encrypt
      encrypted_data.string.unpack("H*")[0]
    end

    def self.decrypt_block(block_hex, key)
      key   = [key].pack("H*")
      key   = DES::Block.new(key)
      block = [block_hex].pack("H*")
      block = DES::Block.new(block)
      des   = DES::Ctx.new(block, key)

      decrypted = des.decrypt
      decrypted.string.unpack("H*")[0]
    end

    def self.check_key(key)
      if key.size < 16
        rise
      end
    end

    def self.encrypt(data, key)
      check_key(key)

      data      = fill_data(data)
      key_left  = key[0..15]
      key_right = key[16..31]

      result = ""

      data.split("").each_slice(16) do |*args|
        block = args.join()
        block = (Crypto.hextoi(block) ^ Crypto.hextoi(@iv)).to_s(16)
        block = ("0"*(16-block.size)) + block if block.size < 16

        block = encrypt_block(block, key_left)
        block = decrypt_block(block, key_right)
        block = encrypt_block(block, key_left)
        @iv   = block

        result << block
      end

      @iv = "0000000000000000"
      result
    end

    def self.decrypt(cypher, key)
      check_key(key)

      key_left  = key[0..15]
      key_right = key[16..31]
      result    = ""

      cypher.split("").each_slice(16) do |*args|
        block = args.join()
        block = decrypt_block(block, key_left)
        block = encrypt_block(block, key_right)
        block = decrypt_block(block, key_left)
        block = (Crypto.hextoi(block) ^ Crypto.hextoi(@iv)).to_s(16)
        block = ("0"*(16-block.size)) + block if block.size < 16
        @iv   = args.join()

        result << block
      end

      @iv = "0000000000000000"
      result
    end
  end
end
