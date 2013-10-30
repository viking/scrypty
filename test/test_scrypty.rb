require 'test/unit'
require 'scrypty'

class TestScrypty < Test::Unit::TestCase
  test 'memlimit' do
    result = Scrypty.memlimit(2 ** 27, 0.5)
    assert result >= (2 ** 27)
  end

  test 'opslimit' do
    result = Scrypty.opslimit(5)
    assert result >= 32768
  end

  test 'params' do
    memlimit = Scrypty.memlimit(2 ** 27, 0.5)
    opslimit = Scrypty.opslimit(5)
    n, r, p = Scrypty.params(memlimit, opslimit)

    assert_includes 1...63, Math.log2(n)
    assert_equal 8, r
    assert p > 0
  end
end
