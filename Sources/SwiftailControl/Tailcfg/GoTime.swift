import Foundation

/// Go `time.Time`의 JSON 텍스트(RFC 3339)와 `Date` 사이의 변환.
///
/// 제어 서버는 시각에 소수 초(뒤 0을 지운 1~9자리)와 UTC가 아닌 오프셋을 붙일 수 있다
/// (`"2026-01-02T03:04:05.123456789+09:00"`). Foundation의 기본 ISO 8601 해독은 이 둘을 함께 받지
/// 못하므로 직접 읽는다. 달력 계산은 그레고리력 날짜 ↔ 1970년부터의 일수 공식으로 한다
/// (시간대 데이터베이스가 필요 없다).
///
/// Go의 0 시각(`0001-01-01T00:00:00Z`)은 "없음"의 표지다. 생략할 수 없는 시각 필드는 값이 없어도
/// 이 문자열로 보낸다.
///
/// `docs/protocol-notes/control-map.md` 3.1.
enum GoTime {
    /// Go의 0 시각. 1970년 기준 −62,135,596,800초.
    static let zero = Date(timeIntervalSince1970: -62_135_596_800)

    /// 0 시각이면 `nil`. "0 시각 = 없음"인 필드를 Swift의 `Optional`로 옮길 때 쓴다.
    static func nonZero(_ date: Date) -> Date? {
        date == zero ? nil : date
    }

    /// RFC 3339 텍스트를 읽는다. 형식이 틀리거나 날짜·시각이 범위 밖이면 `nil`.
    /// 소수 초는 10자리 이상이어도 받되 9자리(나노초)까지만 쓴다. Go와 같다.
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

    /// UTC의 RFC 3339 텍스트로 쓴다. 소수 초는 뒤 0을 지우고, 0이면 생략한다(Go의 `RFC3339Nano`).
    /// Go처럼 0~9999년 밖은 쓰지 못한다(`nil`).
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

    // MARK: 달력

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

    /// 그레고리력 날짜 → 1970-01-01부터의 일수.
    /// 공식: Howard Hinnant, "chrono-Compatible Low-Level Date Algorithms" `days_from_civil`.
    private static func daysSince1970(year: Int, month: Int, day: Int) -> Int {
        let shiftedYear = month <= 2 ? year - 1 : year
        let era = shiftedYear.floorDivided(by: 400)
        let yearOfEra = shiftedYear - era * 400
        let dayOfYear = (153 * (month > 2 ? month - 3 : month + 9) + 2) / 5 + day - 1
        let dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear
        return era * 146_097 + dayOfEra - 719_468
    }

    /// 1970-01-01부터의 일수 → 그레고리력 날짜. 같은 글의 `civil_from_days`.
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

    /// 앞에서부터 한 글자씩 읽는 커서. ASCII만 다룬다.
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

        /// 정확히 count자리의 십진수.
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

        /// 소수점 뒤 한 자리 이상의 숫자를 나노초로. 10번째 자리부터는 버린다.
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

        /// `+`는 1, `-`는 −1.
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
    /// 음의 무한대 쪽으로 내림한 몫. 1970년 이전 날짜에서 `/`(0 쪽으로 버림)와 다르다.
    func floorDivided(by divisor: Int) -> Int {
        let quotient = self / divisor
        return (self % divisor != 0 && (self < 0) != (divisor < 0)) ? quotient - 1 : quotient
    }
}
