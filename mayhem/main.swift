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

let encodable_types: [Codable.Type] = [
    String.self, UInt.self, UInt8.self, UInt16.self, UInt32.self, UInt64.self, Float.self, Bool.self
]

let decodable_types = encodable_types + [[String.self], [Int.self], [UInt.self], [Float.self], [Bool.self]] as [Any]

func test_fuzz_type<T: Codable & Equatable>(_ ft: FuzzType<T>) throws {
    let encoded = try encoder.encode(ft)
    let decoded = try decoder.decode(FuzzType<T>.self, from: encoded)
    
    if (ft != decoded) {
        fatalError("Encoded != original")
    }
}

@_cdecl("LLVMFuzzerTestOneInput")
public func test(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    let fdp = FuzzedDataProvider(start, count)
    
    do {
        let ty = fdp.PickValueInList(from: encodable_types)

        if fdp.ConsumeBoolean() {
            // Test conformance
            if ty.self == String.self {
                try test_fuzz_type(FuzzType(value: fdp.ConsumeRemainingString()))
            } else if ty.self == UInt.self {
                let val: UInt = fdp.ConsumeIntegral()
                let original = FuzzType(value: val)
                try test_fuzz_type(original)
            } else if ty.self == UInt8.self {
                let val: UInt8 = fdp.ConsumeIntegral()
                let original = FuzzType(value: val)
                try test_fuzz_type(original)
            } else if ty.self == UInt16.self {
                let val: UInt16 = fdp.ConsumeIntegral()
                let original = FuzzType(value: val)
                try test_fuzz_type(original)
            } else if ty.self == UInt32.self {
                let val: UInt32 = fdp.ConsumeIntegral()
                let original = FuzzType(value: val)
                try test_fuzz_type(original)
            } else if ty.self == UInt64.self {
                let val: UInt64 = fdp.ConsumeIntegral()
                let original = FuzzType(value: val)
                try test_fuzz_type(original)
            } else if ty.self == Bool.self {
                try test_fuzz_type(FuzzType(value: fdp.ConsumeBoolean()))
            }
        } else {
            // Test raw decoding
            let ty = fdp.PickValueInList(from: decodable_types)
            if let casted_ty = ty as? Decodable.Type {
                try decoder.decode(casted_ty, from: fdp.ConsumeRemainingString())
            }
        }
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
