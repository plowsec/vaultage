import AppKit
import CofferKit
import SwiftUI

// Hardening must run before anything else touches memory we care about.
let initialPosture = CofferCore.harden()
Pref.register()
CofferApp.main()
