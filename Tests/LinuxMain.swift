import XCTest

import BIP32Tests

var tests = [XCTestCaseEntry]()
tests += BIP32Tests.allTests()
XCTMain(tests)
