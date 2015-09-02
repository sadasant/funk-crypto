module Crypto
  def version
    "0.0.0"
  end

  def self.ntob(i, b)
    i = i.to_bn
    b = b.to_bn
    r = ""
    while true
      m = i%b
      i = (i/b).to_bn
      r = "#{m}#{r}"
      return r if i == 0
    end
  end

  def self.btoi(b)
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

  def self.hextob(hex)
    bins = ""
    hex.each_char do |b|
      bin = b.to_i(16).to_s(2)
      bin = ("0"*(4-bin.size)) + bin if bin.size < 4
      bins << bin
    end
    bins
  end

  def self.hextoi(hex)
    self.btoi(self.hextob(hex))
  end

end
