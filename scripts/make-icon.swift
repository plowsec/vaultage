// Renders the Coffer app icon into an .iconset folder (AppKit only). Usage: swift make-icon.swift <out.iconset>
import AppKit

let out = URL(fileURLWithPath: CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "Coffer.iconset")
try? FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)

func draw(_ px: Int) -> Data {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8, samplesPerPixel: 4,
                               hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let s = CGFloat(px) / 1024
    func r(_ x: CGFloat, _ y: CGFloat, _ w: CGFloat, _ h: CGFloat) -> NSRect { NSRect(x: x * s, y: y * s, width: w * s, height: h * s) }

    // Body: macOS icon grid (824pt tile, 100pt margin).
    let tile = NSBezierPath(roundedRect: r(100, 100, 824, 824), xRadius: 185 * s, yRadius: 185 * s)
    NSGradient(starting: NSColor(srgbRed: 0.20, green: 0.29, blue: 0.46, alpha: 1),
               ending: NSColor(srgbRed: 0.10, green: 0.15, blue: 0.27, alpha: 1))!.draw(in: tile, angle: -90)

    // Door.
    let door = NSBezierPath(roundedRect: r(205, 215, 614, 594), xRadius: 70 * s, yRadius: 70 * s)
    NSColor(srgbRed: 0.93, green: 0.94, blue: 0.96, alpha: 1).setFill()
    door.fill()
    NSColor(srgbRed: 0.78, green: 0.81, blue: 0.86, alpha: 1).setStroke()
    door.lineWidth = 10 * s
    door.stroke()

    // Hinges.
    NSColor(srgbRed: 0.62, green: 0.66, blue: 0.73, alpha: 1).setFill()
    NSBezierPath(roundedRect: r(178, 320, 44, 96), xRadius: 14 * s, yRadius: 14 * s).fill()
    NSBezierPath(roundedRect: r(178, 608, 44, 96), xRadius: 14 * s, yRadius: 14 * s).fill()

    // Dial.
    let c = NSPoint(x: 512 * s, y: 512 * s)
    let accent = NSColor(srgbRed: 0.16, green: 0.45, blue: 0.95, alpha: 1)
    accent.setFill()
    NSBezierPath(ovalIn: NSRect(x: c.x - 150 * s, y: c.y - 150 * s, width: 300 * s, height: 300 * s)).fill()
    NSColor.white.setStroke()
    for i in 0..<6 {
        let a = CGFloat(i) * .pi / 3 + .pi / 2
        let p = NSBezierPath()
        p.move(to: NSPoint(x: c.x + cos(a) * 46 * s, y: c.y + sin(a) * 46 * s))
        p.line(to: NSPoint(x: c.x + cos(a) * 118 * s, y: c.y + sin(a) * 118 * s))
        p.lineWidth = 22 * s
        p.lineCapStyle = .round
        p.stroke()
    }
    NSColor.white.setFill()
    NSBezierPath(ovalIn: NSRect(x: c.x - 52 * s, y: c.y - 52 * s, width: 104 * s, height: 104 * s)).fill()
    accent.setFill()
    NSBezierPath(ovalIn: NSRect(x: c.x - 26 * s, y: c.y - 26 * s, width: 52 * s, height: 52 * s)).fill()

    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

for base in [16, 32, 128, 256, 512] {
    try draw(base).write(to: out.appendingPathComponent("icon_\(base)x\(base).png"))
    try draw(base * 2).write(to: out.appendingPathComponent("icon_\(base)x\(base)@2x.png"))
}
