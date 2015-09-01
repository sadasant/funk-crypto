class FunkCryptoTest < DaFunk::Test.case
  def test_des_encrypt_decrypt
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

  def test_des3_enc_dec
    secret = '5f3d3d33303d3d33323439343432343041444438363330413333303042363836354637333335370a3d3d33313d3d41464535334342344237434138333341423834414231383843464145464238330a3d3d33323d3d34443145433842413733383138304337423043453745314135454437454336300a3d3d34303d3d30453633463545413337453443454643433932304134334138304335303043360a3d3d35303d3d37363939413539453043364534314339303843324132464541304337433346370a3d3d35313d3d45354138433842384139304333453534424538413031343336354633413444350a3d3d36303d3d34383930334531303039324331373334333037423742353936453642463143350a3d3d36313d3d35334632343742354346413842414439354543453144453037383646463233420a3d3d36323d3d30314541363136303539454438323337353531363945463136374439414637300a'
    key    = 'D314F4AB5A9D237E1D1BCDD099DEB5B2'
    expected_encrypted_data = 'bafddc45aee2dedf592c7c58246d03d4c5475d8d54b35291ba4bea62f0d1877a2c222359e2dec1f7018c0a0bd749c1162241c22a777dd4d3ea0b57268218b3b429716d01e00bef6d54a7f83783631d1dec514f26b9422c6c42a6d5d47245c98d82c2ffd7ab4ceefced139970d0c0d1315cd3cf288293f8a064f18e578d1375016904071100b21a5dae4e5d1f5a13210a173b3d72d026aebf34c8069b6a18eb01f73596c82549aef502c3f9da13a63ff38f49028a10624fff2305cb618adcd37bd7a2b046cc44b80e730bf09739474a0fed254adb3225a5c93371103edff306605563eda4122119f88a3f404e5b8ad0fd6ad95ce932f3fbb597eb24614380f066f3939fb53e4ca1a6048a7aa07e9abb3c19dcf96762cca85c77db4069f9ab3a546224bf26f15b65df5d7a72b67067bb1072ad7ee1524b490fed1930ea2050dc1a9ddb0db3c77aaa367fba94020a8ca20e534030243fd6f2d5d9ba9a6ac881a5b6'

    encrypted_data = Crypto::DES3.encrypt(secret, key)
    decrypted_data = Crypto::DES3.decrypt(encrypted_data, key)

    assert_equal encrypted_data, expected_encrypted_data
    assert_equal decrypted_data, secret
  end

  def test_des3_triple_length_enc_dec
    secret = '5f3d3d33303d3d33323439343432343041444438363330413333303042363836354637333335370a3d3d33313d3d41464535334342344237434138333341423834414231383843464145464238330a3d3d33323d3d34443145433842413733383138304337423043453745314135454437454336300a3d3d34303d3d30453633463545413337453443454643433932304134334138304335303043360a3d3d35303d3d37363939413539453043364534314339303843324132464541304337433346370a3d3d35313d3d45354138433842384139304333453534424538413031343336354633413444350a3d3d36303d3d34383930334531303039324331373334333037423742353936453642463143350a3d3d36313d3d35334632343742354346413842414439354543453144453037383646463233420a3d3d36323d3d30314541363136303539454438323337353531363945463136374439414637300a'
    key    = 'D314F4AB5A9D237E1D1BCDD099DEB5B23456789012345678'

    encrypted_data = Crypto::DES3Triple.encrypt(secret, key)
    decrypted_data = Crypto::DES3Triple.decrypt(encrypted_data, key)

    assert_equal decrypted_data, secret
  end

  def test_newdes_enc_dec
    secret = 'mysecret'
    key    = '0123456701234567'

    encrypted_data = Crypto::NEWDES.encrypt(secret, key)
    decrypted_data = Crypto::NEWDES.decrypt(encrypted_data, key)

    assert_equal decrypted_data, secret
  end

  def test_dukpt_encryption_derive_ipek
     ksn = "FFFF9876543210E00008"
     bdk = "0123456789ABCDEFFEDCBA9876543210"
     DUK = Crypto::DUKPT::Decrypter.new(nil, nil)
     ipek = DUK.derive_IPEK(bdk, ksn)
     assert_equal '6ac292faa1315b4d858ab3a3d7d5933a', ipek
  end

  def test_dukpt_encryption_derive_pek
     ksn = "FFFF9876543210E00008"
     DUK = Crypto::DUKPT::Decrypter.new(nil, nil)
     pek = DUK.derive_PEK('6ac292faa1315b4d858ab3a3d7d5933a', ksn)
     assert_equal '27f66d5244ff621eaa6f6120edeb427f', pek
  end

  def test_dukpt_encryption_derive_key_3
     ksn = "FFFF9876543210E00003"
     DUK = Crypto::DUKPT::Decrypter.new(nil, nil)
     key = DUK.derive_key('6ac292faa1315b4d858ab3a3d7d5933a', ksn)
     assert_equal '0DF3D9422ACA56E547676D07AD6BADFA', key.upcase
  end

  # def test_dukpt_decrypter
  #   bdk = "0123456789ABCDEFFEDCBA9876543210"
  #   ksn = "FFFF9876543210E00008"
  #   ciphertext = "C25C1D1197D31CAA87285D59A892047426D9182EC11353C051ADD6D0F072A6CB3436560B3071FC1FD11D9F7E74886742D9BEE0CFD1EA1064C213BB55278B2F12"
  #   plaintext = "%B5452300551227189^HOGAN/PAUL      ^08043210000000725000000?\x00\x00\x00\x00"

  #   decrypter = Crypto::DUKPT::Decrypter.new(bdk, "cbc")
  #   decrypted_data = decrypter.decrypt(ciphertext, ksn)
  #   p "decrypted_data:#{decrypted_data}"
  #   p "decrypted_data.unpack(\"H*\"):#{decrypted_data.unpack("H*")}"
  #   assert_equal plaintext, decrypted_data
  # end
end
