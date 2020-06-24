import Base58
import Crypto101
import Foundation
import secp256k1
import CryptoSwift

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
    
    public init(serialized: String) {
        let decoded = Base58.decode(serialized)
        let version = Array(decoded[0..<4])
        if (version == [0x04, 0x88, 0xad, 0xe4]) {
            let priv = Array(decoded[46..<78])
            self.privateKey = priv
            let pubkey = ECC.computePublicKey(fromPrivateKey: Data(priv), compression: true).bytes
            self.publicKey = pubkey
        } else {
            self.privateKey = nil
            self.publicKey = Array(decoded[45..<78])
        }
        self.fingerprint = Data(decoded[5..<9]).withUnsafeBytes { $0.load(as: UInt32.self) }
        self.depth = Data(decoded[4..<5]).withUnsafeBytes { $0.load(as: UInt8.self) }
        self.chainCode = Array(decoded[13..<45])
        self.childIndex = Data(decoded[9..<13]).withUnsafeBytes { $0.load(as: UInt32.self) }
    }
    
    public init(seed: [UInt8]) {
        let bytes = try! Crypto101.Hash.hmacsha512(Data(seed), key: Data([UInt8]("Bitcoin seed".utf8)))
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
        
        let digest = try! Hash.hmacsha512(Data(bytes), key: Data(self.chainCode))
        let derivedPrivateKey = digest[0..<32]
        let derivedChainCode = digest[32..<(32+32)]
        
        let factor = BInt(data: derivedPrivateKey)
        
        let curveOrder = BInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141".lowercased(), radix: 16)!
        
        let privateKeyNum = BInt(data: Data(privateKey!))
        let result = ((privateKeyNum + factor) % curveOrder).data
        
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

extension BInt {
    public init(data: Data) {
        let n = data.count
        guard n > 0 else {
            self.init(0)
            return
        }
        let m = (n + 7) / 8
        var limbs = Limbs(repeating: 0, count: m)
        data.withUnsafeBytes { (ptr: UnsafePointer<UInt8>) -> Void in
            var p = ptr
            let r = n % 8
            let k = r == 0 ? 8 : r
            for j in (0..<k).reversed() {
                limbs[m-1] += UInt64(p.pointee) << UInt64(j*8)
                p += 1
            }
            guard m > 1 else { return }
            for i in (0..<(m-1)).reversed() {
                for j in (0..<8).reversed() {
                    limbs[i] += UInt64(p.pointee) << UInt64(j*8)
                    p += 1
                }
            }
        }
        self.init(limbs: limbs)
    }
    
    /// Representation as Data
    public var data: Data {
        let n = limbs.count
        var data = Data(count: n * 8)
        data.withUnsafeMutableBytes { (ptr: UnsafeMutablePointer<UInt8>) -> Void in
            var p = ptr
            for i in (0..<n).reversed() {
                for j in (0..<8).reversed() {
                    p.pointee = UInt8((limbs[i] >> UInt64(j*8)) & 0xff)
                    p += 1
                }
            }
        }
        return data
    }
}

enum ECC {
    static func computePublicKey(fromPrivateKey privateKey: Data, compression: Bool) -> Data {
        let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN) | UInt32(SECP256K1_CONTEXT_VERIFY))!

        // *** Generate public key ***
        let pubKey = malloc(MemoryLayout<secp256k1_pubkey>.size)!.assumingMemoryBound(to: secp256k1_pubkey.self)
        
        // Cleanup
        defer {
            free(pubKey)
        }
         
        var secret = privateKey.bytes
        _ = secp256k1_ec_pubkey_create(ctx, pubKey, &secret)
                    
        var length = compression ? 33 : 65
        var result = [UInt8](repeating: 0, count: length)
        _ = secp256k1_ec_pubkey_serialize(ctx, &result, &length, pubKey, UInt32(compression ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED))
        // First byte is header byte 0x04
        if (!compression) { result.remove(at: 0) }
        return Data(result)
    }
}
