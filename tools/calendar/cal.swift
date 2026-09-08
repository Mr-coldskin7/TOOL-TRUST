import EventKit
import Foundation

let store = EKEventStore()
let sem = DispatchSemaphore(value: 0)
var granted = false
if #available(macOS 14.0, *) {
    store.requestFullAccessToEvents { ok, _ in granted = ok; sem.signal() }
} else {
    store.requestAccess(to: .event) { ok, _ in granted = ok; sem.signal() }
}
sem.wait()
guard granted else { print("ERR: no calendar access"); exit(1) }

let args = CommandLine.arguments
if args.count > 1 && args[1] == "list" {
    for c in store.calendars(for: .event) where c.allowsContentModifications {
        print("\(c.calendarIdentifier)\t\(c.title)")
    }
    exit(0)
}

// add mode: add "<title>" "<startISO>" "<endISO>" [calendarTitle] [location] [notes]
guard args.count >= 5, args[1] == "add" else { print("usage: add <title> <start> <end> [cal] [loc] [notes]"); exit(2) }
let title = args[2], startISO = args[3], endISO = args[4]
let calTitle = args.count > 5 ? args[5] : "事业"

// 宽松解析：兼容 2026-09-06T10:00:00+08:00 / Z / 无时区
func parseDate(_ s: String) -> Date? {
    let iso = ISO8601DateFormatter()
    iso.formatOptions = [.withInternetDateTime, .withDashSeparatorInDate, .withColonSeparatorInTime, .withTimeZone]
    if let d = iso.date(from: s) { return d }
    if s.hasSuffix("Z"), let d = iso.date(from: s) { return d }
    // 尝试无时区：假定本地时区
    let f = DateFormatter()
    f.locale = Locale(identifier: "en_US_POSIX")
    f.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
    f.timeZone = TimeZone.current
    return f.date(from: s)
}
guard let start = parseDate(startISO), let end = parseDate(endISO) else {
    print("ERR: bad ISO dates"); exit(3)
}
let target = store.calendars(for: .event).first { $0.title == calTitle } ?? store.defaultCalendarForNewEvents!
let ev = EKEvent(eventStore: store)
ev.title = title
ev.startDate = start
ev.endDate = end
ev.calendar = target
if args.count > 6 { ev.location = args[6] }
if args.count > 7 { ev.notes = args[7] }
do {
    try store.save(ev, span: .thisEvent)
    print("OK: \(ev.title) @ \(String(describing: ev.startDate)) → \(String(describing: ev.endDate)) in \(target.title)")
} catch { print("ERR: \(error)"); exit(4) }
