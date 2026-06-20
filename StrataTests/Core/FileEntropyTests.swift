//
//  FileEntropyTests.swift
//  StrataTests
//
//  Shannon-entropy core used to verify ransomware "mass encryption" bursts are
//  actually high-entropy (encrypted) content rather than renamed files.
//

import Testing
import Foundation
@testable import Strata

struct FileEntropyTests {

    @Test func emptyIsZero() {
        #expect(FileEntropy.shannonEntropy(Data()) == 0)
    }

    @Test func singleByteRunIsZero() {
        let data = Data(repeating: 0x41, count: 4096)   // 4 KB of 'A'
        #expect(FileEntropy.shannonEntropy(data) == 0)
    }

    @Test func uniformBytesAreExactlyEightBits() {
        // Every byte value equally represented → maximal 8 bits/byte.
        var data = Data()
        for _ in 0..<16 { for b in 0...255 { data.append(UInt8(b)) } }
        #expect(abs(FileEntropy.shannonEntropy(data) - 8.0) < 0.0001)
    }

    @Test func englishTextIsModerate() {
        let s = String(repeating: "the quick brown fox jumps over the lazy dog. ", count: 50)
        let e = FileEntropy.shannonEntropy(Data(s.utf8))
        #expect(e > 3.0 && e < 5.0)
    }

    @Test func pseudoRandomIsNearEight() {
        // Deterministic LCG so the test is stable (no RNG). Encrypted content
        // looks like this: ~8 bits/byte.
        var data = Data(count: 8192)
        var x: UInt64 = 0x1234_5678
        for i in 0..<data.count {
            x = x &* 6364136223846793005 &+ 1442695040888963407
            data[i] = UInt8((x >> 33) & 0xFF)
        }
        #expect(FileEntropy.shannonEntropy(data) > 7.9)
    }

    @Test func statVerdictAndAggregation() {
        // looksEncrypted is driven by highEntropyFiles (any file with a high
        // window) - a low *mean* with a high window still corroborates.
        #expect(EncryptionEntropyStat(sampledFiles: 3, highEntropyFiles: 1, meanEntropy: 6.0, maxEntropy: 7.99).looksEncrypted)
        #expect(!EncryptionEntropyStat(sampledFiles: 3, highEntropyFiles: 0, meanEntropy: 5.0, maxEntropy: 6.0).looksEncrypted)
        #expect(!EncryptionEntropyStat(sampledFiles: 0, highEntropyFiles: 0, meanEntropy: 0, maxEntropy: 0).looksEncrypted)
        #expect(EncryptionEntropyStat.from(fileMaxEntropies: []) == nil)
        // 8.0 and 7.6 clear the 7.5 threshold; 4.0 does not.
        let stat = EncryptionEntropyStat.from(fileMaxEntropies: [8.0, 7.6, 4.0])
        #expect(stat?.sampledFiles == 3)
        #expect(stat?.highEntropyFiles == 2)
        #expect(stat?.maxEntropy == 8.0)
        #expect(stat?.looksEncrypted == true)
    }
}
