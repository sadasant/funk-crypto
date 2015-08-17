module Crypto
  class DES3Triple
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
      if key.size < 16 || key.size%3 != 0 || key.size/3 < 16
        rise
      end
    end

    def self.encrypt(data, key)
      check_key(key)

      data = fill_data(data)

      key_block_size = key.size/3
      key_1 = key[0..(key_block_size-1)]
      key_2 = key[key_block_size..((key_block_size*2)-1)]
      key_3 = key[(key_block_size*2)..-1]

      result = encrypt_blocks(data, key_3)
      result = decrypt_blocks(result, key_2)
      result = encrypt_blocks(result, key_1)
    end

    def self.decrypt(cypher, key)
      check_key(key)

      key_block_size = key.size/3
      key_1 = key[0..(key_block_size-1)]
      key_2 = key[key_block_size..((key_block_size*2)-1)]
      key_3 = key[(key_block_size*2)..-1]

      result = decrypt_blocks(cypher, key_1)
      result = encrypt_blocks(result, key_2)
      result = decrypt_blocks(result, key_3)
    end
  end
end
