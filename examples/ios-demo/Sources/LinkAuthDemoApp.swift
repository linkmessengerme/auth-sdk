import SwiftUI

@main
struct LinkAuthDemoApp: App {
    @StateObject private var auth = AuthCoordinator()

    var body: some Scene {
        WindowGroup {
            ContentView(auth: auth)
                .onOpenURL { auth.receive($0) }
        }
    }
}
