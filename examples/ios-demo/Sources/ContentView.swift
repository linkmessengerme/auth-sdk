import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @ObservedObject var auth: AuthCoordinator
    @State private var importingFile = false
    @State private var pastingJSON = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    HStack(spacing: 14) {
                        Image(systemName: "link.circle.fill")
                            .font(.system(size: 44))
                            .foregroundStyle(.tint)
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Login with Link").font(.title3.bold())
                            Text("iOS · integration example").font(.subheadline).foregroundStyle(.secondary)
                        }
                    }
                    .padding(.vertical, 6)
                    HStack(alignment: .top, spacing: 10) {
                        if auth.isBusy { ProgressView().padding(.top, 2) }
                        else {
                            Image(systemName: auth.isError ? "exclamationmark.circle" : "info.circle")
                                .foregroundStyle(auth.isError ? Color.orange : Color.secondary)
                        }
                        Text(auth.message).font(.subheadline).accessibilityIdentifier("authStatus")
                    }
                }

                if let session = auth.session {
                    Section("Profile") {
                        Label(session.user.name ?? session.user.preferredUsername ?? "Link user",
                              systemImage: "person.crop.circle.fill")
                            .font(.headline)
                        if let username = session.user.preferredUsername {
                            value("Username", username)
                        }
                        value("Identifier (sub)", session.user.subject)
                        value("Issuer", session.user.issuer)
                        value("Granted scopes", session.user.grantedScopes.sorted().joined(separator: " · "))
                        // device_trust of the ID token; absent while attestation is off in Console.
                        value("Device trust", session.user.deviceTrust ?? "not reported")
                        value("Token expires", session.expiresAt.formatted(date: .abbreviated, time: .standard))
                    }
                    Section("Session") {
                        Button("Check session", systemImage: "checkmark.shield") {
                            auth.checkSession(forceRefresh: false)
                        }
                        .disabled(auth.isBusy)
                        Button("Refresh tokens", systemImage: "arrow.clockwise") {
                            auth.checkSession(forceRefresh: true)
                        }
                        .disabled(auth.isBusy || !session.canRefresh)
                        Button("Sign out", systemImage: "rectangle.portrait.and.arrow.right", role: .destructive) {
                            auth.signOut()
                        }
                        .disabled(!auth.canSignOut)
                    }
                } else {
                    Section {
                        if auth.pending {
                            Label("Waiting for confirmation in Link", systemImage: "clock")
                            Button("Cancel sign-in", role: .cancel) { auth.cancelSignIn() }
                                .disabled(auth.isBusy)
                        } else if auth.revocationPending || auth.recoveryRequired {
                            Button(auth.revocationPending ? "Retry access revocation" : "End the previous session") {
                                auth.signOut()
                            }
                            .disabled(!auth.canSignOut)
                        } else {
                            Button { auth.signIn() } label: {
                                Label("Sign in with Link", systemImage: "link")
                                    .font(.headline)
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 5)
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(!auth.canSignIn)
                            .accessibilityIdentifier("signIn")
                        }
                    } footer: {
                        Text("The sign-in confirmation appears in the installed Link app.")
                    }
                }

                Section {
                    if let config = auth.config {
                        value("Client ID", config.clientID)
                        value("Regional API", config.apiBaseURL)
                        value("Issuer", config.issuer)
                        value("Requested scopes", config.scopes.sorted().joined(separator: " · "))
                    }
                    Button("Import JSON file", systemImage: "doc.badge.plus") { importingFile = true }
                        .disabled(!auth.canConfigure)
                    Button("Paste JSON", systemImage: "curlybraces") { pastingJSON = true }
                        .disabled(!auth.canConfigure)
                } header: {
                    Text("Console configuration")
                } footer: {
                    Text("Use the public config of the iOS client. Sign out before changing the config.")
                }

                Section {
                    ForEach(auth.events) { event in
                        VStack(alignment: .leading, spacing: 3) {
                            Text(event.time, style: .time).font(.caption).foregroundStyle(.secondary)
                            Text(event.message).font(.footnote)
                        }
                    }
                } header: {
                    Text("Events")
                } footer: {
                    Text("The SDK keeps tokens in the Keychain. The log never contains tokens, authorization codes or callback links.")
                }
            }
            .navigationTitle("Link Auth Demo")
            .navigationBarTitleDisplayMode(.inline)
            .fileImporter(isPresented: $importingFile, allowedContentTypes: [.json], allowsMultipleSelection: false) { result in
                switch result {
                case .success(let urls): if let url = urls.first { auth.importFile(url) }
                case .failure: auth.fileImportFailed()
                }
            }
            .sheet(isPresented: $pastingJSON) {
                PasteConfigurationView { auth.importJSON($0) }
            }
        }
    }

    private func value(_ title: String, _ text: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(text).font(.footnote.monospaced()).textSelection(.enabled)
        }
    }
}

private struct PasteConfigurationView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var json = ""
    let save: (String) -> Void

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 12) {
                Text("Paste the public link_oauth_client_config from Console.")
                    .font(.subheadline).foregroundStyle(.secondary)
                TextEditor(text: $json)
                    .font(.system(.footnote, design: .monospaced))
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .accessibilityLabel("Public JSON config")
                if json.utf8.count > DemoConfiguration.maximumBytes {
                    Text("The maximum size is 64 KB.").foregroundStyle(.orange)
                }
            }
            .padding()
            .navigationTitle("Import config")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Load") { save(json); dismiss() }
                        .disabled(json.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                                  || json.utf8.count > DemoConfiguration.maximumBytes)
                }
            }
        }
    }
}
