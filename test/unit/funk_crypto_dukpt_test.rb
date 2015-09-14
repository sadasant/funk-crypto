class FunkCryptoTest < DaFunk::Test.case
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

  def test_dukpt_encryption_derive_pek_counter_3
    ksn = "FFFF9876543210E00003"
    DUK = Crypto::DUKPT::Decrypter.new(nil, nil)
    pek = DUK.derive_PEK('6ac292faa1315b4d858ab3a3d7d5933a', ksn)
    assert_equal '0DF3D9422ACA561A47676D07AD6BAD05', pek.upcase
  end

  def test_dukpt_encryption_derive_pek_counter_7
    ksn = "FFFF9876543210E00007"
    DUK = Crypto::DUKPT::Decrypter.new(nil, nil)
    pek = DUK.derive_PEK('6ac292faa1315b4d858ab3a3d7d5933a', ksn)
    assert_equal '0C8F780B7C8B492FAE84A9EB2A6CE69F', pek.upcase
  end

  def test_dukpt_encryption_derive_pek_counter_F
    ksn = "FFFF9876543210E0000F"
    DUK = Crypto::DUKPT::Decrypter.new(nil, nil)
    pek = DUK.derive_PEK('6ac292faa1315b4d858ab3a3d7d5933a', ksn)
    assert_equal '93DD5B956C4878B82E453AAEFD32A555', pek.upcase
  end

  def test_dukpt_encryption_derive_pek_counter_10
    ksn = "FFFF9876543210E00010"
    DUK = Crypto::DUKPT::Decrypter.new(nil, nil)
    pek = DUK.derive_PEK('6ac292faa1315b4d858ab3a3d7d5933a', ksn)
    assert_equal '59598DCBD9BD943F94165CE453585FA8', pek.upcase
  end

  def test_dukpt_encryption_derive_pek_counter_13
    ksn = "FFFF9876543210E00013"
    DUK = Crypto::DUKPT::Decrypter.new(nil, nil)
    pek = DUK.derive_PEK('6ac292faa1315b4d858ab3a3d7d5933a', ksn)
    assert_equal 'C3DF489FDF11534BF03DE97C27DC4CD0', pek.upcase
  end

  def test_dukpt_encryption_derive_pek_counter_EFF800
    ksn = "FFFF9876543210EFF800"
    DUK = Crypto::DUKPT::Decrypter.new(nil, nil)
    pek = DUK.derive_PEK('6ac292faa1315b4d858ab3a3d7d5933a', ksn)
    assert_equal 'F9CDFEBF4F5B1D61B3EC12454527E189', pek.upcase
  end

  def test_dukpt_encryption_triple_des_decrypt
    cipher = "C25C1D1197D31CAA87285D59A892047426D9182EC11353C051ADD6D0F072A6CB3436560B3071FC1FD11D9F7E74886742D9BEE0CFD1EA1064C213BB55278B2F12"
    key    = "27f66d5244ff621eaa6f6120edeb427f"
    decryp = Crypto::DES3CBC.decrypt(cipher, key)
    assert_equal '2542353435323330303535313232373138395e484f47414e2f5041554c2020202020205e30383034333231303030303030303732353030303030303f00000000', decryp
  end

  def test_dukpt_dek_from_key
    key = "27F66D5244FF62E1AA6F6120EDEB4280"
    DUK = Crypto::DUKPT::Decrypter.new(nil, nil)
    dek = DUK.dek_from_key(key)
    assert_equal "C39B2778B058AC376FB18DC906F75CBA", dek.upcase
  end

  def test_dukpt_derive_dek_counter_13
    ksn = "FFFF9876543210E00013"
    DUK = Crypto::DUKPT::Decrypter.new(nil, nil)
    dek = DUK.derive_DEK('6ac292faa1315b4d858ab3a3d7d5933a', ksn)
    assert_equal '44893E3434ABDD6A817CE2841825E1FD', dek.upcase
  end

  def test_dukpt_decrypter
    bdk = "0123456789ABCDEFFEDCBA9876543210"
    ksn = "FFFF9876543210E00008"
    ciphertext = "C25C1D1197D31CAA87285D59A892047426D9182EC11353C051ADD6D0F072A6CB3436560B3071FC1FD11D9F7E74886742D9BEE0CFD1EA1064C213BB55278B2F12"
    plaintext = "%B5452300551227189^HOGAN/PAUL      ^08043210000000725000000?\x00\x00\x00\x00"

    DUK = Crypto::DUKPT::Decrypter.new(bdk, "cbc")
    decrypted_data = DUK.decrypt(ciphertext, ksn)
    assert_equal plaintext, decrypted_data
  end

  def test_dukpt_decrypt_data_block
    bdk = "0123456789ABCDEFFEDCBA9876543210"
    ksn = "FFFF01040DA058E00001"
    ciphertext = "85A8A7F9390FD19EABC40B5D624190287D729923D9EDAFE9F24773388A9A1BEF"
    plaintext = ["5A08476173900101001057114761739001010010D15122011143878089000000"].pack("H*")
    DUK = Crypto::DUKPT::Decrypter.new(bdk, "cbc")
    assert_equal plaintext, DUK.decrypt_data_block(ciphertext, ksn)
  end

  def test_dukpt_decrypt_pin
    bdk = "0123456789ABCDEFFEDCBA9876543210"
    ksn = "F8765432108D12400014"
    ciphertext = "129C4FC2537BB63E"
    pan = "5413330089601109"
    plaintext_pin = "4315"

    DUK = Crypto::DUKPT::Decrypter.new(bdk)
    assert_equal plaintext_pin, DUK.decrypt_pin(ciphertext, ksn, pan)
  end

  def test_dukpt_decrypt_pin_with_padded_pan
    bdk = "0123456789ABCDEFFEDCBA9876543210"
    ksn = "F8765432108D12400011"
    ciphertext = "8C3169A2ABC1632F"
    pan = "6799998900000060919F"
    plaintext_pin = "4315"

    DUK = Crypto::DUKPT::Decrypter.new(bdk)
    assert_equal plaintext_pin, DUK.decrypt_pin(ciphertext, ksn, pan)
  end

  def test_dukpt_decrypt_cloudwalk_pin
    # based on: https://github.com/cloudwalkio/robot_rock/blob/master/mrblib/init.rb#L18
    bdk = "0123456789ABCDEFFEDCBA9876543210"
    ksn = "FFFF9876543210E00001"
    pan = "00004012345678909"
    pin = "1234"
    epb = "1B9C1845EB993A7A"

    DUK = Crypto::DUKPT::Decrypter.new(bdk)
    plaintext = DUK.decrypt_pin(epb, ksn, pan)
    assert_equal pin, plaintext
  end

  def test_dukpt_decrypt_cloudwalk_epb
    bdk = "0123456789ABCDEFFEDCBA9876543210"
    ksn = "FFFF9876543210E00001"
    pan = "00004012345678909"
    pin = "1234"
    epb = "1B9C1845EB993A7A"

    DUK = Crypto::DUKPT::Decrypter.new(bdk)

    ipek = DUK.derive_IPEK(bdk, ksn)
    pek  = DUK.derive_PEK(ipek, ksn)

    pin       = "04#{pin}ffffffffff"
    coded_pan = "0000"+pan[-13..-2]
    cipherpin = (pin.to_bn(16) ^ coded_pan.to_bn(16)).to_s(16)
    if cipherpin.size < 16
      cipherpin = ("0"*(16-cipherpin.size)) + cipherpin
    end
    ciphertext = Crypto::DES3CBC.encrypt(cipherpin, pek)
    assert_equal epb, ciphertext.upcase
  end
end
