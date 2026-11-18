import Foundation

/// Conversion between Go `time.Time` JSON text (RFC 3339) and `Date`.
///
/// The control server can include fractional seconds (1~9 digits with trailing zeros removed) and a non-UTC offset in a timestamp
/// (`"2026-01-02T03:04:05.123456789+09:00"`). Foundation's default ISO 8601 decoder cannot accept both together,
/// so parse directly. Calendar calculations use a formula for Gregorian dates ↔ days since 1970
/// (requires no time zone database).
///
/// Go's zero time (`0001-01-01T00:00:00Z`) marks absence. A timestamp field that cannot be omitted
/// is sent as this string even if it has no value.
///
/// `docs/protocol-notes/control-map.md` §3.1.
enum GoTime {
    /// Go's zero time, −62,135,596,800 seconds relative to 1970.
    static let zero = Date(timeIntervalSince1970: -62_135_596_800)

    /// Returns `nil` for the zero time. Used to map fields where zero time means absence to Swift `Optional`.
    static func nonZero(_ date: Date) -> Date? {
        date == zero ? nil : date
    }

    /// Parses RFC 3339 text. Returns `nil` for an invalid format or an out-of-range date or time.
    /// Accepts fractional seconds with 10 or more digits but uses only the first 9 (nanoseconds), matching Go.
    static func parse(_ text: String) -> Date? {
        var scanner = Scanner(Array(text.utf8))
        guard let year = scanner.digits(4), scanner.skip("-"),
              let month = scanner.digits(2), scanner.skip("-"),
              let day = scanner.digits(2), scanner.skip("T"),
              let hour = scanner.digits(2), scanner.skip(":"),
              let minute = scanner.digits(2), scanner.skip(":"),
              let second = scanner.digits(2),
              (1...12).contains(month), (1...daysIn(month: month, year: year)).contains(day),
              hour < 24, minute < 60, second < 60
        else { return nil }

        var nanoseconds = 0
        if scanner.skip(".") {
            guard let fraction = scanner.fraction() else { return nil }
            nanoseconds = fraction
        }

        let offsetSeconds: Int
        if scanner.skip("Z") {
            offsetSeconds = 0
        } else {
            guard let sign = scanner.sign(),
                  let offsetHour = scanner.digits(2), scanner.skip(":"),
                  let offsetMinute = scanner.digits(2),
                  offsetHour < 24, offsetMinute < 60
            else { return nil }
            offsetSeconds = sign * (offsetHour * 3600 + offsetMinute * 60)
        }
        guard scanner.isAtEnd else { return nil }

        let days = daysSince1970(year: year, month: month, day: day)
        let seconds = days * 86_400 + hour * 3600 + minute * 60 + second - offsetSeconds
        return Date(timeIntervalSince1970: Double(seconds) + Double(nanoseconds) / 1e9)
    }

    /// Formats as RFC 3339 text in UTC. Strips trailing zeros from fractional seconds and omits the fraction if 0 (Go's `RFC3339Nano`).
    /// Like Go, cannot write years outside 0~9999 and returns `nil` for them.
    static func format(_ date: Date) -> String? {
        let interval = date.timeIntervalSince1970
        guard interval.isFinite, abs(interval) < 1e12 else { return nil }
        var seconds = Int(interval.rounded(.down))
        var nanoseconds = Int(((interval - Double(seconds)) * 1e9).rounded())
        if nanoseconds == 1_000_000_000 {
            seconds += 1
            nanoseconds = 0
        }
        let days = seconds.floorDivided(by: 86_400)
        let secondOfDay = seconds - days * 86_400
        let (year, month, day) = civilDate(daysSince1970: days)
        guard (0...9999).contains(year) else { return nil }

        var text = pad(year, 4) + "-" + pad(month, 2) + "-" + pad(day, 2)
        text += "T" + pad(secondOfDay / 3600, 2) + ":" + pad(secondOfDay / 60 % 60, 2) + ":" + pad(secondOfDay % 60, 2)
        if nanoseconds > 0 {
            var fraction = pad(nanoseconds, 9)
            while fraction.hasSuffix("0") { fraction.removeLast() }
            text += "." + fraction
        }
        return text + "Z"
    }

    // MARK: Calendar

    private static func daysIn(month: Int, year: Int) -> Int {
        switch month {
        case 2: isLeap(year) ? 29 : 28
        case 4, 6, 9, 11: 30
        default: 31
        }
    }

    private static func isLeap(_ year: Int) -> Bool {
        year.isMultiple(of: 4) && (!year.isMultiple(of: 100) || year.isMultiple(of: 400))
    }

    /// Gregorian date → number of days since 1970-01-01.
    /// Uses Howard Hinnant's `days_from_civil` from "chrono-Compatible Low-Level Date Algorithms".
    private static func daysSince1970(year: Int, month: Int, day: Int) -> Int {
        let shiftedYear = month <= 2 ? year - 1 : year
        let era = shiftedYear.floorDivided(by: 400)
        let yearOfEra = shiftedYear - era * 400
        let dayOfYear = (153 * (month > 2 ? month - 3 : month + 9) + 2) / 5 + day - 1
        let dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear
        return era * 146_097 + dayOfEra - 719_468
    }

    /// Days since 1970-01-01 → Gregorian date. Uses `civil_from_days` from the same article.
    private static func civilDate(daysSince1970 days: Int) -> (year: Int, month: Int, day: Int) {
        let shifted = days + 719_468
        let era = shifted.floorDivided(by: 146_097)
        let dayOfEra = shifted - era * 146_097
        let yearOfEra = (dayOfEra - dayOfEra / 1460 + dayOfEra / 36_524 - dayOfEra / 146_096) / 365
        let dayOfYear = dayOfEra - (365 * yearOfEra + yearOfEra / 4 - yearOfEra / 100)
        let shiftedMonth = (5 * dayOfYear + 2) / 153
        let day = dayOfYear - (153 * shiftedMonth + 2) / 5 + 1
        let month = shiftedMonth < 10 ? shiftedMonth + 3 : shiftedMonth - 9
        return (yearOfEra + era * 400 + (month <= 2 ? 1 : 0), month, day)
    }

    private static func pad(_ value: Int, _ width: Int) -> String {
        let digits = String(value)
        return String(repeating: "0", count: max(0, width - digits.count)) + digits
    }

    /// A cursor that reads one character at a time from the start. Handles ASCII only.
    private struct Scanner {
        private let bytes: [UInt8]
        private var index = 0

        init(_ bytes: [UInt8]) { self.bytes = bytes }

        var isAtEnd: Bool { index == bytes.count }

        mutating func skip(_ character: Unicode.Scalar) -> Bool {
            guard index < bytes.count, bytes[index] == UInt8(ascii: character) else { return false }
            index += 1
            return true
        }

        /// A decimal number of exactly count digits.
        mutating func digits(_ count: Int) -> Int? {
            guard bytes.count - index >= count else { return nil }
            var value = 0
            for byte in bytes[index..<index + count] {
                guard let digit = Self.digit(byte) else { return nil }
                value = value * 10 + digit
            }
            index += count
            return value
        }

        /// Converts at least one digit after the decimal point to nanoseconds. Discards digits from the 10th onward.
        mutating func fraction() -> Int? {
            var nanoseconds = 0
            var count = 0
            while index < bytes.count, let digit = Self.digit(bytes[index]) {
                if count < 9 { nanoseconds = nanoseconds * 10 + digit }
                count += 1
                index += 1
            }
            guard count > 0 else { return nil }
            for _ in count..<max(count, 9) { nanoseconds *= 10 }
            return nanoseconds
        }

        /// `+` is 1 and `-` is −1.
        mutating func sign() -> Int? {
            if skip("+") { return 1 }
            if skip("-") { return -1 }
            return nil
        }

        private static func digit(_ byte: UInt8) -> Int? {
            (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte) ? Int(byte - UInt8(ascii: "0")) : nil
        }
    }
}

private extension Int {
    /// The quotient rounded toward negative infinity. For days before 1970, Swift's `/` rounds toward 0 instead.
    func floorDivided(by divisor: Int) -> Int {
        let quotient = self / divisor
        return (self % divisor != 0 && (self < 0) != (divisor < 0)) ? quotient - 1 : quotient
    }
}
