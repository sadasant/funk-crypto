# From https://github.com/Shopify/dukpt/blob/master/lib/dukpt/decrypter.rb

module Crypto
  module DUKPT

    # Because of the order of files compiled, we need to add this here.
    module Encryption
    end

    class Decrypter
      include DUKPT::Encryption

      attr_reader :bdk

      def initialize(bdk, mode=nil)
        @bdk = bdk
        self.cipher_mode = mode.nil? ? 'cbc' : mode
      end

      def decrypt(cryptogram, ksn)
        ipek = derive_IPEK(bdk, ksn)
        pek  = derive_PEK(ipek, ksn)
        decrypted_cryptogram = Crypto::DES3CBC.decrypt(cryptogram, pek)
        [decrypted_cryptogram].pack('H*')
      end

      def decrypt_pin_block(cryptogram, ksn)
        decrypt(cryptogram, ksn)
      end

      def decrypt_pin(cryptogram, ksn, pan)
        pan &&= pan.downcase.chomp('f')
        decrypted_block = decrypt_pin_block(cryptogram, ksn).unpack("H*").first
        block_format = decrypted_block[0]
        if block_format == "0"
          coded_pan = "0000"+pan[-13..-2]
          rjust_value = (decrypted_block.to_bn(16) ^ coded_pan.to_bn(16)).to_s(16)
          if rjust_value.size < 16
            rjust_value = "0"*(16 - rjust_value.size) + rjust_value
          end
          coded_pin = rjust_value
          pin_count = coded_pin[1].to_bn
          coded_pin[2,pin_count]
        elsif block_format == "1"
          pin_count = decrypted_block[1]
          coded_pin[2,pin_count]
        end
      end

      def decrypt_data_block(cryptogram, ksn)
        ipek = derive_IPEK(bdk, ksn)
        dek  = derive_DEK(ipek, ksn)
        decrypted_cryptogram = Crypto::DES3CBC.decrypt(cryptogram, dek)
        [decrypted_cryptogram].pack('H*')
      end

    end
  end
end
