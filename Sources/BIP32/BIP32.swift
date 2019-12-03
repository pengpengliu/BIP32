import CryptoSwift
import Base58

public struct BIP32 {
    let publicKey: [UInt8]
    let privateKey: [UInt8]?
    let chainCode: [UInt8]
    let depth: UInt8 = 0
    let fingerprint: UInt32 = 0x00000000
    let childIndex: UInt32 = 0x00000000
    
    init(seed: [UInt8]) {
        let data = try! HMAC(key: [UInt8]("Bitcoin seed".utf8), variant: .sha512).authenticate(seed)
        self.privateKey = Array(data[0..<32])
        self.publicKey = []
        self.chainCode = Array(data[32..<64])
    }
    
    // The 4 byte header that serializes in base58 to "xprv", default bitcoin
    func toBase58(bip32Header: [UInt8] = Array<UInt8>(hex: "0488ade4")) -> String {
        precondition(bip32Header.count == 4)
        var data: [UInt8] = []
        // 4 bytes: prefix bytes
        data += bip32Header
        // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants, ....
        data += [depth]
        // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
        data += [
            UInt8((fingerprint & 0xFF000000) >> 24),
            UInt8((fingerprint & 0x00FF0000) >> 16),
            UInt8((fingerprint & 0x0000FF00) >> 8),
            UInt8(fingerprint & 0x000000FF)
        ]
        // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
        // This is encoded in big endian. (0x00000000 if master key)
        data += [
            UInt8((childIndex & 0xFF000000) >> 24),
            UInt8((childIndex & 0x00FF0000) >> 16),
            UInt8((childIndex & 0x0000FF00) >> 8),
            UInt8(childIndex & 0x000000FF)
        ]
        // 32 bytes: the chain code
        data += chainCode
        // 33 bytes: the public key or private key data
        if let p = privateKey {
            // 0x00 + k for private keys
            data += [UInt8(0)]
            data += p
        } else {
            data += publicKey
        }
        let checksum = data.sha256().sha256().prefix(4)
        return Base58.encode(data + checksum)
    }
}
