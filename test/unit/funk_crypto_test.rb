class FunkCryptoTest < DaFunk::Test.case
  def test_encrypt_decrypt
    # Encrypting
    secret = 'mysecret'
    data   = Crypto::DES::Block.new(secret)
    key    = Crypto::DES::Block.new('hushhush')
    des    = Crypto::DES::Ctx.new(data, key)
    encrypted_data = des.encrypt

    # Decrypting
    un_des = Crypto::DES::Ctx.new(encrypted_data, key)
    decrypted_data = un_des.decrypt

    # From http://www.tero.co.uk/des/test.php and other sources
    expected_hex = "89d829b8fd813404"

    assert_equal encrypted_data.string.unpack("H*").first, expected_hex
    assert_equal encrypted_data.bit_array.join("").to_i(2).to_s(16), expected_hex
    assert_equal data.bit_array.eql?(decrypted_data.bit_array), true
    assert_equal secret, decrypted_data.string
  end
end
