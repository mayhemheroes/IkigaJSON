#if canImport(Darwin)
import Darwin.C
#elseif canImport(Glibc)
import Glibc
#elseif canImport(MSVCRT)
import MSVCRT
#endif

import Foundation
import IkigaJSON

let decoder = IkigaJSONDecoder()
let encoder = IkigaJSONEncoder()

struct FuzzType<Value: Codable & Equatable>: Codable, Equatable {
    let value: Value
}

let encodable_types: [Any.Type] = [
    String.self, Int.self, Int8.self, Int16.self, Int32.self, Int64.self,
    UInt.self, UInt8.self, UInt16.self, UInt32.self, UInt64.self, Float.self,
    Double.self, Bool.self, URL.self, Data.self, Decimal.self, UUID.self,
]

func generateRandomValue<T: Codable & Equatable>(fdp: FuzzedDataProvider) -> T {
    if T.self == String.self {
        return fdp.ConsumeRemainingString() as! T
    }
    else if T.self == Int.self {
        return fdp.ConsumeIntegral<Int> as! Int
    }
}

@_cdecl("LLVMFuzzerTestOneInput")
public func test(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    let fdp = FuzzedDataProvider(start, count)
    do {
        let ty = fdp.PickValueInList(from: encodable_types)
        let original = FuzzType(value: fdp.ConsumeRemainingString())
        let data = try encoder.encode(original)
        let decoded = try decoder.decode(FuzzType<String>.self, from: data)
    }
    catch _ as JSONParserError {
        return -1
    }
    catch let error {
        print(error)
        print(type(of: error))
        exit(EXIT_FAILURE)
    }
    return 0;
}