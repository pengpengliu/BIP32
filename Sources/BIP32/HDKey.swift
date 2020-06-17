import Base58
import Crypto101
import Foundation
import OpenSSL
import secp256k1

public enum DerivationError : Error {
    case derivateionFailed
}

public struct HDKey {
    let privateKey: [UInt8]?
    let publicKey: [UInt8]
    let chainCode: [UInt8]
    var depth: UInt8 = 0
    var fingerprint: UInt32 = 0x00000000
    var childIndex: UInt32 = 0x00000000
    
    var parentFingerprint: UInt32 = 0x00000000
    
    private let highestBit: UInt32 = 0x80000000
    
    public init(privateKey: [UInt8], chainCode: [UInt8], depth: UInt8 = 0, childIndex: UInt32 = 0, parentFingerprint: UInt32 = 0x00000000) {
        self.privateKey = privateKey
        let pubkey = ECC.computePublicKey(fromPrivateKey: Data(privateKey), compression: true).bytes
        self.publicKey = pubkey
        self.chainCode = chainCode
        self.depth = depth
        self.parentFingerprint = parentFingerprint
        self.fingerprint = Hash.sha256ripemd160(Data(pubkey)).withUnsafeBytes { $0.load(as: UInt32.self) }
        self.childIndex = childIndex
    }
    
    public init(publicKey: [UInt8], chainCode: [UInt8], depth: UInt8 = 0, childIndex: UInt32 = 0, parentFingerprint: UInt32 = 0x00000000) {
        self.privateKey = nil
        self.publicKey = publicKey
        self.chainCode = chainCode
        self.depth = depth
        self.parentFingerprint = parentFingerprint
        self.fingerprint = Hash.sha256ripemd160(Data(publicKey)).withUnsafeBytes { $0.load(as: UInt32.self) }
        self.childIndex = childIndex
    }
    
    public init(seed: [UInt8]) {
        let bytes = Crypto101.Hash.hmacsha512(Data(seed), key: Data([UInt8]("Bitcoin seed".utf8)))
        let priv = Array(bytes[0..<32])
        self.privateKey = priv
        let pubkey = ECC.computePublicKey(fromPrivateKey: Data(priv), compression: true).bytes
        self.publicKey = pubkey
        self.chainCode = Array(bytes[32..<64])
        self.fingerprint = Hash.sha256ripemd160(Data(pubkey)).withUnsafeBytes { $0.load(as: UInt32.self) }
    }
    
    public func neutered() -> Self {
        return HDKey(publicKey: self.publicKey, chainCode: self.chainCode, depth: self.depth, childIndex: self.childIndex)
    }
    
    public func derive(path: String) throws -> Self? {
        var key = self
        var path = path
        if path == "m" || path == "/" || path == "" {
            return self
        }
        if path.contains("m/") {
            path = String(path.dropFirst(2))
        }
        for chunk in path.split(separator: "/") {
            var hardened = false
            var indexText = chunk
            if chunk.contains("'") {
                hardened = true
                indexText = indexText.dropLast()
            }
            guard let index = UInt32(indexText) else {
                fatalError("invalid path")
            }
            if (hardened) {
                key = try key.deriveHardened(index: index)!
            } else {
                key = try key.derive(index: index)!
            }
        }
        return key
    }
    
    public func deriveHardened(index: UInt32) throws -> Self? {
        return try derive(index: index + highestBit)
    }
    
    // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#child-key-derivation-ckd-functions
    public func derive(index: UInt32) throws -> Self? {
        let isHardened = index >= highestBit
        var bytes: [UInt8] = []

        // Hardened child
        if isHardened {
            bytes += [0x00]
            bytes += privateKey!
            bytes += index.byteArrayLittleEndian
        }
        else {
            bytes += publicKey
            bytes += index.byteArrayLittleEndian
        }
        
        let digest = Hash.hmacsha512(Data(bytes), key: Data(self.chainCode))
        let derivedPrivateKey = digest[0..<32]
        let derivedChainCode = digest[32..<(32+32)]
        
        var curveOrder = BN_new()
        defer {
            BN_free(curveOrder)
        }
        BN_hex2bn(&curveOrder, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
        
        let factor = BN_new()
        defer {
            BN_free(factor)
        }

        derivedPrivateKey.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
            BN_bin2bn(
                ptr.bindMemory(to: UInt8.self).baseAddress.unsafelyUnwrapped,
                Int32(derivedPrivateKey.count),
                factor
            )
            return
        }
        
        let ctx = BN_CTX_new()
        defer {
            BN_CTX_free(ctx)
        }
        
        var result: Data
        if let privateKey = self.privateKey {
            let privateKeyNum = BN_new()!
            defer {
                BN_free(privateKeyNum)
            }
            privateKey.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
                BN_bin2bn(
                    ptr.bindMemory(to: UInt8.self).baseAddress.unsafelyUnwrapped,
                    Int32(privateKey.count),
                    privateKeyNum
                )
                return
            }
            BN_mod_add(privateKeyNum, privateKeyNum, factor, curveOrder, ctx)
            
            let numBytes = ((BN_num_bits(privateKeyNum)+7)/8) // BN_num_bytes
            result = Data(count: Int(numBytes))
            result.withUnsafeMutableBytes { (ptr: UnsafeMutableRawBufferPointer) in
                BN_bn2bin(
                    privateKeyNum,
                    ptr.bindMemory(to: UInt8.self).baseAddress.unsafelyUnwrapped
                )
                return
            }
            if result.count < 32 {
                result = Data(repeating: 0, count: 32 - result.count) + result // 0 padding
            }
        } else {
            let publicKeyNum = BN_new()
            defer {
                BN_free(publicKeyNum)
            }
            
            publicKey.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
                BN_bin2bn(
                    ptr.bindMemory(to: UInt8.self).baseAddress.unsafelyUnwrapped,
                    Int32(publicKey.count),
                    publicKeyNum
                )
                return
            }
            let group = EC_GROUP_new_by_curve_name(NID_secp256k1)
            let point = EC_POINT_new(group)
            defer {
                EC_POINT_free(point)
                EC_GROUP_free(group)
            }
            EC_POINT_bn2point(group, publicKeyNum, point, ctx)
            EC_POINT_mul(group, point, factor, point, BN_value_one(), ctx)
            
            // Check for invalid derivation.
            if EC_POINT_is_at_infinity(group, point) == 1 {
                return nil
            }
            let n = BN_new()
            defer {
                BN_free(n)
            }
            EC_POINT_point2bn(group, point, POINT_CONVERSION_COMPRESSED, n, ctx)
            result = Data(count: 33)
            result.withUnsafeMutableBytes { (ptr: UnsafeMutableRawBufferPointer) in
                BN_bn2bin(
                    n,
                    ptr.bindMemory(to: UInt8.self).baseAddress.unsafelyUnwrapped
                )
                return
            }
        }
        return HDKey(privateKey: result.bytes, chainCode: derivedChainCode.bytes, depth: depth + 1, childIndex: index, parentFingerprint: self.fingerprint)
    }
    
    // The 4 byte header that serializes in base58 to "xprv", default bitcoin
    public func toBase58() -> String {
        var data: [UInt8] = []
        // 4 bytes: prefix bytes
        if let _ = self.privateKey {
            data += [0x04, 0x88, 0xad, 0xe4]
        } else {
            data += [0x04, 0x88, 0xb2, 0x1e]
        }
        // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants, ....
        data += [depth]
        // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
        data += parentFingerprint.data.bytes
        // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
        // This is encoded in big endian. (0x00000000 if master key)
        data += childIndex.byteArrayLittleEndian
        // 32 bytes: the chain code
        data += chainCode
        // 33 bytes: the public key or private key data
        if let priv = self.privateKey {
            // 0x00 + k for private keys
            data += [UInt8(0)]
            data += priv
            // 33 bytes: the public key
        } else {
            // X9.62 encoding for public keys
            data += publicKey
        }
        // 0488ade4013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae623614100edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea
        // 0488ade4013442193e0000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae623614100edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea
        // 0488ade4013442193e0000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae623614100edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea
        let checksum = Hash.sha256(Hash.sha256(Data(data))).prefix(4)
        return Base58.encode(data + checksum)
    }
}

extension UInt32 {
    var data: Data {
        var int = self
        return Data(bytes: &int, count: MemoryLayout<UInt32>.size)
    }
    
    var byteArrayLittleEndian: [UInt8] {
        return [
            UInt8((self & 0xFF000000) >> 24),
            UInt8((self & 0x00FF0000) >> 16),
            UInt8((self & 0x0000FF00) >> 8),
            UInt8(self & 0x000000FF)
        ]
    }
}

extension Data {
    init?(hex: String) {
        let len = hex.count / 2
        var data = Data(capacity: len)
        for i in 0..<len {
            let j = hex.index(hex.startIndex, offsetBy: i * 2)
            let k = hex.index(j, offsetBy: 2)
            let bytes = hex[j..<k]
            if var num = UInt8(bytes, radix: 16) {
                data.append(&num, count: 1)
            } else {
                return nil
            }
        }
        self = data
    }
    
    var hex: String {
        return reduce("") { $0 + String(format: "%02x", $1) }
    }
    
    public var bytes: Array<UInt8> {
      Array(self)
    }
}

enum ECC {
    static func computePublicKey(fromPrivateKey privateKey: Data, compression: Bool) -> Data {
        let ctx = BN_CTX_new()
        defer {
            BN_CTX_free(ctx)
        }
        let key = EC_KEY_new_by_curve_name(NID_secp256k1)
        defer {
            EC_KEY_free(key)
        }
        let group = EC_KEY_get0_group(key)
        
        
        let prv = BN_new()
        defer {
            BN_free(prv)
        }
        privateKey.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
            BN_bin2bn(
                ptr.bindMemory(to: UInt8.self).baseAddress.unsafelyUnwrapped,
                Int32(privateKey.count),
                prv
            )
            return
        }
        
        let pub = EC_POINT_new(group)
        defer {
            EC_POINT_free(pub)
        }
        EC_POINT_mul(group, pub, prv, nil, nil, ctx)
        EC_KEY_set_private_key(key, prv)
        EC_KEY_set_public_key(key, pub)
        
        if compression {
            EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED)
            var ptr: UnsafeMutablePointer<UInt8>? = nil
            let length = i2o_ECPublicKey(key, &ptr)
            return Data(bytes: ptr!, count: Int(length))
        } else {
            var result = [UInt8](repeating: 0, count: 65)
            let n = BN_new()
            defer {
                BN_free(n)
            }
            EC_POINT_point2bn(group, pub, POINT_CONVERSION_UNCOMPRESSED, n, ctx)
            BN_bn2bin(n, &result)
            return Data(result)
        }
    }
}
