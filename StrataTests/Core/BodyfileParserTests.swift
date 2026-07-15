//
//  BodyfileParserTests.swift
//  StrataTests
//
//  Covers the TSK mactime bodyfile parser used by the macOS APFS ingest path
//  (fsapfsinfo -B). The canonical line is pinned against a REAL fsapfsinfo line
//  captured from a macOS-27 APFS image (the root inode).
//

import Testing
import Foundation
@testable import Strata

struct BodyfileParserTests {

    /// A real `fsapfsinfo -E 2 -B` line (root directory of a macOS-27 Data
    /// volume): md5=0, empty name, inode 2, dir mode, uid 0 / gid 20, ns times.
    private static let realRoot =
        "0||2|drwxr-xr-x|0|20|0|1742575039.723819148|1545418282.000000000|1742574721.422384095|1742574721.422384095"

    @Test func parsesRealRootLine() throws {
        let e = try #require(BodyfileParser.parseLine(Self.realRoot))
        #expect(e.md5 == "0")
        #expect(e.path == "")
        #expect(e.inode == 2)
        #expect(e.mode == "drwxr-xr-x")
        #expect(e.isDirectory)
        #expect(e.uid == 0)
        #expect(e.gid == 20)
        #expect(e.size == 0)
        #expect(abs((e.accessed ?? .distantPast).timeIntervalSince1970 - 1742575039.723819148) < 0.001)
        #expect(abs((e.modified ?? .distantPast).timeIntervalSince1970 - 1545418282) < 0.001)
        // ctime == crtime here
        #expect(e.changed == e.created)
    }

    @Test func parsesFileWithPath() throws {
        let line = "0|/Users/jane/secret.sh|12345|-rwxr-xr-x|501|20|2048|1700000000|1700000100|1700000200|1700000300"
        let e = try #require(BodyfileParser.parseLine(line))
        #expect(e.path == "/Users/jane/secret.sh")
        #expect(e.name == "secret.sh")
        #expect(e.inode == 12345)
        #expect(!e.isDirectory)
        #expect(e.uid == 501)
        #expect(e.size == 2048)
        #expect(e.modified == Date(timeIntervalSince1970: 1700000100))
    }

    @Test func handlesSymlink() throws {
        let line = "0|/var -> private/var|7|lrwxr-xr-x|0|0|11|1700000000|1700000000|1700000000|1700000000"
        let e = try #require(BodyfileParser.parseLine(line))
        #expect(e.path == "/var")
        #expect(e.symlinkTarget == "private/var")
        #expect(e.isSymlink)
    }

    @Test func regularFileNameContainingArrowIsNotSplit() throws {
        // A regular file (mode '-') whose name legitimately contains " -> " must
        // be kept whole; only actual symlinks (mode 'l') split on the arrow (B6).
        // Splitting it would collapse two entries onto one path or drop a file.
        let line = "0|/data/report -> draft.txt|9|-rw-r--r--|501|20|10|1700000000|1700000000|1700000000|1700000000"
        let e = try #require(BodyfileParser.parseLine(line))
        #expect(e.path == "/data/report -> draft.txt")
        #expect(e.symlinkTarget == nil)
        #expect(!e.isSymlink)
    }

    @Test func nameWithPipeStillParses() throws {
        // A path containing '|' must not break field anchoring (we anchor on the
        // 9 fixed trailing fields).
        let line = "0|/Users/jane/weird|name.txt|9|-rw-r--r--|501|20|10|1700000000|1700000000|1700000000|1700000000"
        let e = try #require(BodyfileParser.parseLine(line))
        #expect(e.path == "/Users/jane/weird|name.txt")
        #expect(e.inode == 9)
        #expect(e.size == 10)
    }

    @Test func integerSecondsTimestamp() throws {
        let e = try #require(BodyfileParser.parseLine(
            "0|/x|1|-rw-r--r--|0|0|0|1700000000|1700000000|1700000000|1700000000"))
        #expect(e.accessed == Date(timeIntervalSince1970: 1700000000))
    }

    @Test func zeroTimestampIsNil() throws {
        // 11 fields: atime "0", mtime real, ctime "0.000000000", crtime "" (empty).
        let e = try #require(BodyfileParser.parseLine(
            "0|/x|1|-rw-r--r--|0|0|0|0|1700000000|0.000000000|"))
        #expect(e.accessed == nil)      // "0"
        #expect(e.changed == nil)       // "0.000000000"
        #expect(e.created == nil)       // "" (empty)
        #expect(e.modified != nil)
    }

    @Test func nanosecondFraction() throws {
        let d = try #require(BodyfileParser.time("1742574721.422384095"))
        #expect(abs(d.timeIntervalSince1970 - 1742574721.422384095) < 0.0001)
    }

    @Test func malformedAndCommentsReturnNil() {
        #expect(BodyfileParser.parseLine("") == nil)
        #expect(BodyfileParser.parseLine("# comment") == nil)
        #expect(BodyfileParser.parseLine("too|few|fields") == nil)
        #expect(BodyfileParser.parseLine("0|/x|notanumber|-|0|0|0|0|0|0|0") == nil)  // bad inode
    }

    @Test func parsesMultilineSkippingBlanks() {
        let text = "\n\(Self.realRoot)\n\n# c\n0|/a|3|-rw-r--r--|0|0|0|1700000000|1700000000|1700000000|1700000000\n"
        #expect(BodyfileParser.parse(text).count == 2)
    }
}
