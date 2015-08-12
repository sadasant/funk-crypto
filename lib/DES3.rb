module Crypto
  class DES3
    def self.fill_data data
      bytes = data.length / 2

      return data + '80'                          if bytes % 8 == 14
      return data + "80" + "00" * (7 - bytes % 8) if bytes % 8 != 0

      return data
    end

    def self.encrypt_blocks(data, key)
      ret = ''
      key = [key].pack("H*")
      key = DES::Block.new(key)
      data.split("").each_slice(16) do |*args|
        block     = args.join()
        block_hex = [block].pack("H*")
        data      = DES::Block.new(block_hex)
        des       = DES::Ctx.new(data, key)

        encrypted_data = des.encrypt
        encrypted_data = encrypted_data.string.unpack("H*")[0]
        ret << encrypted_data
      end
      ret
    end

    def self.decrypt_blocks(data, key)
      ret = ''
      key = [key].pack("H*")
      key = DES::Block.new(key)
      data.split("").each_slice(16) do |*args|
        block = args.join()
        block_hex = [block].pack("H*")
        data  = DES::Block.new(block_hex)
        des   = DES::Ctx.new(data, key)

        decrypted_data = des.decrypt
        decrypted_data = decrypted_data.string.unpack("H*")[0]
        ret << decrypted_data
      end
      ret
    end

    def self.check_key(key)
      if key.size < 15
        rise
      end
    end

    def self.encrypt(data, key)
      check_key(key)

      data      = fill_data(data)
      key_left  = key[0..15]
      key_right = key[16..31]

      result = encrypt_blocks(data, key_left)
      result = decrypt_blocks(result, key_right)
      result = encrypt_blocks(result, key_left)
    end

    def self.decrypt(cypher, key)
      check_key(key)

      key_left  = key[0..15]
      key_right = key[16..31]

      result = decrypt_blocks(cypher, key_left)
      result = encrypt_blocks(result, key_right)
      result = decrypt_blocks(result, key_left)
    end
  end
end
