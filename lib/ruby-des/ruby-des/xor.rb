module Crypto::DES::XOR
  def self.run(x, y)
    output = []

    x.size.times do |i|
      output << (x[i].to_i ^ y[i].to_i)
    end

    return output
  end
end
