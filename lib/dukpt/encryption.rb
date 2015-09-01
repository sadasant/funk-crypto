# From https://github.com/Shopify/dukpt/blob/master/lib/dukpt/encryption.rb

module Crypto
  module DUKPT
    module Encryption
      REG3_MASK       = "2097151".to_bn                                 # 0x1FFFFF
      SHIFT_REG_MASK  = "1048576".to_bn                                 # 0x100000
      REG8_MASK       = "18446744073707454464".to_bn                    # 0xFFFFFFFFFFE00000
      LS16_MASK       = "18446744073709551615".to_bn                    # 0x0000000000000000FFFFFFFFFFFFFFFF
      MS16_MASK       = "340282366920938463444927863358058659840".to_bn # 0xFFFFFFFFFFFFFFFF0000000000000000
      KEY_MASK        = "256212605621993638375572339883398660096".to_bn # 0xC0C0C0C000000000C0C0C0C000000000
      PEK_MASK        = "4703919738795935662335".to_bn                  # 0x00000000000000FF00000000000000FF
      KSN_MASK        = "1208925819614629172609024".to_bn               # 0xFFFFFFFFFFFFFFE00000
      DEK_MASK        = "308276084001730439566786560".to_bn             # 0x0000000000FF00000000000000FF0000

      # ================
      # MRUBY MATH FIXES
      def btoi(b)
        sum = 0
        size = b.size - 1
        size.downto(0) do |i|
          n = size-i
          if !(i == 0 && b[n].to_i == 0)
            sum += (b[n].to_i*2).to_bn ** i
          end
        end
        sum
      end
      def hextob(hex)
        bins = ""
        hex.each_char do |b|
          bin = b.to_i(16).to_s(2)
          bin = ("0"*(4-bin.size)) + bin if bin.size < 4
          bins << bin
        end
        bins
      end
      # ================

      def cipher_mode=(cipher_type)
        if cipher_type == "ecb"
          @cipher_type_des = "des-ecb"
          @cipher_type_tdes = "des-ede"
        else
          @cipher_type_des = "des-cbc"
          @cipher_type_tdes = "des-ede-cbc"
        end
      end

      def derive_key(ipek, ksn)
        ksn_current = ksn.to_bn(16)
        ksn_reg     = ksn_current & LS16_MASK # Get 8 least significant bytes
        ksn_reg     = ksn_reg & REG8_MASK     # Clear the 21 counter bits
        reg_3       = ksn_current & REG3_MASK # Grab the 21 counter bits
        shift_reg   = SHIFT_REG_MASK

        #Initialize "curkey" to be the derived "ipek"
        curkey = ipek.to_bn(16)
        while (shift_reg > 0)
          if shift_reg & reg_3 > 0
            ksn_reg = shift_reg | ksn_reg
            curkey = keygen(curkey, ksn_reg)
          end
          shift_reg = shift_reg >> 1
        end
        hex_string_from_val(curkey, 16)
      end

      def keygen(key, ksn)
        cr1  = ksn
        cr2  = encrypt_register(key, cr1)
        key2 = key ^ KEY_MASK
        cr1  = encrypt_register(key2, cr1)
        hex = [hex_string_from_val(cr1, 8), hex_string_from_val(cr2, 8)].join
        btoi(hextob(hex))
      end

      def pek_from_key(key)
        key_i = btoi(hextob(key))
        hex_string_from_val((key_i ^ PEK_MASK), 16)
      end

      def dek_from_key(key)
        key   = key.to_bn(16)
        key   = key ^ DEK_MASK
        left  = (key & MS16_MASK) >> 64
        right = (key & LS16_MASK)

        invariant_key_hex = hex_string_from_val(key, 16)

        left  = DES3.encrypt(hex_string_from_val(left, 8), invariant_key_hex)
        right = DES3.encrypt(hex_string_from_val(right, 8), invariant_key_hex)

        left  = hex_string_from_val(left.to_bn(16), 8)
        right = hex_string_from_val(right.to_bn(16), 8)

        [left, right].join
      end

      def derive_PEK(ipek, ksn)
        pek_from_key(derive_key(ipek, ksn))
      end

      def derive_DEK(ipek, ksn)
        dek_from_key(derive_key(ipek, ksn))
      end

      def derive_IPEK(bdk, ksn)
        ksn_cleared_count = (ksn.to_bn(16) & KSN_MASK) >> 16
        left_half_of_ipek = DES3.encrypt(hex_string_from_val(ksn_cleared_count, 8), bdk)
        xor_base_derivation_key = bdk.to_bn(16) ^ KEY_MASK
        right_half_of_ipek = DES3.encrypt(hex_string_from_val(ksn_cleared_count, 8), hex_string_from_val(xor_base_derivation_key, 8))
        ipek_derived = left_half_of_ipek + right_half_of_ipek
        ipek_derived
      end

      def hex_string_from_val val, bytes
        rjust_value = val.to_s(16)
        size        = bytes * 2
        if rjust_value.size < size
          rjust_value = "0"*(size - rjust_value.size) + rjust_value
        end
        rjust_value
      end

      def encrypt_register(curkey, reg_8)
        left_key_half  = (curkey & MS16_MASK) >> 64
        right_key_half = curkey & LS16_MASK

        message    = right_key_half ^ reg_8
        ciphertext = des_encrypt(hex_string_from_val(left_key_half, 8), hex_string_from_val(message, 8)).to_bn(16)
        result     = right_key_half ^ ciphertext

        result
      end

      def des_encrypt(raw_key, raw_secret)
        data = Crypto::DES::Block.new([raw_secret].pack('H*'))
        key  = Crypto::DES::Block.new([raw_key].pack('H*'))
        des  = Crypto::DES::Ctx.new(data, key)
        des.encrypt.string.unpack("H*")[0]
      end

    end
  end
end
