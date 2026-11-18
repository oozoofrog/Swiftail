import Foundation

/// Converts the `Retry-After` header (RFC 7231 7.1.3) to the wall-clock time before which requests are withheld.
///
/// ```
/// Retry-After = HTTP-date / delay-seconds
/// delay-seconds = 1*DIGIT
/// ```
///
/// Accepts all three HTTP-date formats (RFC 7231 7.1.1.1 "MUST accept all three"): IMF-fixdate
/// (`Sun, 06 Nov 1994 08:49:37 GMT`), RFC 850(`Sunday, 06-Nov-94 08:49:37 GMT`), asctime(`Sun Nov  6 08:49:37 1994`).
/// Treats values that are neither format as absent (contract behavior X5, H21). Go's `retryAfter` also reads integer seconds and uses
/// http.ParseTime (the same three formats), treating everything else as 0 (`tempfork/acme/http.go:92-104`).
///
/// Caps the result at `received + 7 days` (contract behavior X5 caps only the upper end). Returns past dates unchanged so the caller
/// can skip the wait if the date precedes the current time.
enum RetryAfter {
    /// The upper limit on the server's time (7 days).
    static let maximumDelay: TimeInterval = 7 * 24 * 60 * 60

    /// - Parameters:
    ///   - value: The header value. Leading and trailing whitespace is ignored (OWS in RFC 7230 3.2).
    ///   - received: The time the response arrived. The base for values in seconds and for the 7-day cap.
    static func date(from value: String, receivedAt received: Date) -> Date? {
        let text = value.trimmingCharacters(in: .whitespaces)
        let latest = received.addingTimeInterval(maximumDelay)
        if let seconds = delaySeconds(text) {
            return min(received.addingTimeInterval(seconds), latest)
        }
        guard let date = imfFixdate(text) ?? rfc850Date(text, receivedAt: received) ?? asctimeDate(text) else { return nil }
        return min(date, latest)
    }

    /// Parses `1*DIGIT`. Very large values saturate beyond 7 days without crashing on overflow.
    private static func delaySeconds(_ text: String) -> TimeInterval? {
        let digits = Array(text.utf8)
        guard !digits.isEmpty, digits.allSatisfy(isDigit) else { return nil }
        var seconds: TimeInterval = 0
        for digit in digits {
            seconds = min(seconds * 10 + TimeInterval(digit - UInt8(ascii: "0")), maximumDelay + 1)
        }
        return seconds
    }

    // MARK: HTTP-date (RFC 7231 7.1.1.1)

    private static let dayNames = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    private static let longDayNames = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    private static let monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

    /// `day-name "," SP day SP month SP year SP time-of-day SP "GMT"`.
    private static func imfFixdate(_ text: String) -> Date? {
        let parts = text.split(separator: " ", omittingEmptySubsequences: false)
        guard parts.count == 6, parts[0].count == 4, parts[0].hasSuffix(","), dayNames.contains(String(parts[0].dropLast())),
              parts[5] == "GMT", let day = number(parts[1], digits: 2), let month = month(parts[2]),
              let year = number(parts[3], digits: 4)
        else { return nil }
        return date(year: year, month: month, day: day, time: parts[4])
    }

    /// Parses `day-name-l "," SP day "-" month "-" 2DIGIT SP time-of-day SP "GMT"`. RFC 7231 7.1.1.1 interprets a two-digit year that
    /// appears more than 50 years in the future as the most recent past year with the same last two digits.
    private static func rfc850Date(_ text: String, receivedAt received: Date) -> Date? {
        let parts = text.split(separator: " ", omittingEmptySubsequences: false)
        guard parts.count == 4, parts[0].hasSuffix(","), longDayNames.contains(String(parts[0].dropLast())), parts[3] == "GMT"
        else { return nil }
        let date2 = parts[1].split(separator: "-", omittingEmptySubsequences: false)
        guard date2.count == 3, let day = number(date2[0], digits: 2), let month = month(date2[1]),
              let shortYear = number(date2[2], digits: 2)
        else { return nil }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = .gmt
        let currentYear = calendar.component(.year, from: received)
        var year = currentYear - currentYear % 100 + shortYear
        if year > currentYear + 50 {
            year -= 100
        } else if year + 100 <= currentYear + 50 {
            year += 100
        }
        return date(year: year, month: month, day: day, time: parts[2])
    }

    /// `day-name SP month SP ( 2DIGIT / ( SP 1DIGIT ) ) SP time-of-day SP year`.
    private static func asctimeDate(_ text: String) -> Date? {
        let parts = text.split(separator: " ", omittingEmptySubsequences: false)
        // A one-digit day has an extra leading space, yielding an empty part (`Nov  6`).
        let fields: [Substring]
        if parts.count == 6, parts[2].isEmpty, parts[3].count == 1 {
            fields = [parts[0], parts[1], parts[3], parts[4], parts[5]]
        } else if parts.count == 5, parts[2].count == 2 {
            fields = parts
        } else {
            return nil
        }
        guard dayNames.contains(String(fields[0])), let month = month(fields[1]),
              let day = number(fields[2], digits: fields[2].count), let year = number(fields[4], digits: 4)
        else { return nil }
        return date(year: year, month: month, day: day, time: fields[3])
    }

    /// Appends `hour ":" minute ":" second` (2 digits each) to form a UTC time. Returns nil if the day does not exist in that month.
    private static func date(year: Int, month: Int, day: Int, time: Substring) -> Date? {
        let clock = time.split(separator: ":", omittingEmptySubsequences: false)
        guard clock.count == 3, let hour = number(clock[0], digits: 2), let minute = number(clock[1], digits: 2),
              let second = number(clock[2], digits: 2), hour < 24, minute < 60, second <= 60,
              (1...daysInMonth(month, year: year)).contains(day)
        else { return nil }
        let seconds = (daysFromCivil(year: year, month: month, day: day) * 86_400) + hour * 3600 + minute * 60 + second
        return Date(timeIntervalSince1970: TimeInterval(seconds))
    }

    private static func month(_ text: Substring) -> Int? {
        monthNames.firstIndex(of: String(text)).map { $0 + 1 }
    }

    /// A decimal number of exactly `digits` digits.
    private static func number(_ text: Substring, digits: Int) -> Int? {
        let bytes = Array(text.utf8)
        guard bytes.count == digits, (1...4).contains(digits), bytes.allSatisfy(isDigit) else { return nil }
        return bytes.reduce(0) { $0 * 10 + Int($1 - UInt8(ascii: "0")) }
    }

    private static func isDigit(_ byte: UInt8) -> Bool {
        (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
    }

    private static func daysInMonth(_ month: Int, year: Int) -> Int {
        switch month {
        case 2: (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 ? 29 : 28
        case 4, 6, 9, 11: 30
        default: 31
        }
    }

    /// The number of days since 1970-01-01 (Gregorian calendar), using Howard Hinnant's `days_from_civil` formula.
    private static func daysFromCivil(year: Int, month: Int, day: Int) -> Int {
        let y = month <= 2 ? year - 1 : year
        let era = (y >= 0 ? y : y - 399) / 400
        let yearOfEra = y - era * 400
        let dayOfYear = (153 * (month > 2 ? month - 3 : month + 9) + 2) / 5 + day - 1
        let dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear
        return era * 146_097 + dayOfEra - 719_468
    }
}
