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
end
