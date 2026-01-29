import 'package:flutter/material.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:google_sign_in/google_sign_in.dart';
import 'package:google_fonts/google_fonts.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  bool _isLoading = false;

  // --- LOGOWANIE ANONIMOWE (Dla Gościa) ---
  Future<void> _loginAnon() async {
    setState(() => _isLoading = true);
    try {
      await FirebaseAuth.instance.signInAnonymously();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text("Error: $e")));
      }
    } finally {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  // --- LOGOWANIE GOOGLE (Dla Admina/Analityka) ---
  Future<void> _loginGoogle() async {
    setState(() => _isLoading = true);

    try {
      // 1. Get the singleton instance (New in v7)
      final GoogleSignIn googleSignIn = GoogleSignIn.instance;

      // 2. Initialize the plugin (Required in v7)
      await googleSignIn.initialize();

      // 3. Authenticate (New in v7: Replaces signIn())
      // This method throws an exception if cancelled, it does NOT return null.
      final GoogleSignInAccount googleUser = await googleSignIn.authenticate(
        scopeHint: ['email'], // Hint to request email scope
      );

      // 4. Get Auth Details
      // Note: 'authentication' is now synchronous (no await needed)
      final GoogleSignInAuthentication googleAuth = googleUser.authentication;

      // 5. Get Access Token (New in v7)
      // 'accessToken' was removed from googleAuth. We must use authorizationClient.
      final authClient = googleSignIn.authorizationClient;
      final authorization = await authClient.authorizationForScopes(['email']);

      // 6. Create Credential
      final credential = GoogleAuthProvider.credential(
        accessToken: authorization?.accessToken,
        idToken: googleAuth.idToken,
      );

      // 7. Sign in to Firebase
      await FirebaseAuth.instance.signInWithCredential(credential);

      // Success! AuthWrapper handles navigation.
    } catch (e) {
      // Handle cancellation or errors
      if (mounted) {
        // v7 throws GoogleSignInException on cancellation?
        // You can check 'e' type if you want to hide the snackbar for cancellations.
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text("Google Sign-In Failed: $e"),
            backgroundColor: Colors.red,
          ),
        );
      }
    } finally {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(Icons.bug_report, size: 100, color: Colors.redAccent),
              const SizedBox(height: 20),
              Text(
                "INFECTED REPOSITORY",
                style: GoogleFonts.vt323(fontSize: 40, color: Colors.red),
              ),
              const Text(
                "Secure Storage for Binary Threats",
                style: TextStyle(color: Colors.grey),
              ),
              const SizedBox(height: 50),

              if (_isLoading)
                const CircularProgressIndicator()
              else
                Column(
                  children: [
                    // PRZYCISK GOOGLE
                    SizedBox(
                      width: double.infinity,
                      height: 50,
                      child: ElevatedButton.icon(
                        icon: const Icon(Icons.g_mobiledata, size: 30),
                        label: const Text("LOGIN WITH GOOGLE (Analyst)"),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: Colors.white,
                          foregroundColor: Colors.black,
                        ),
                        onPressed: _loginGoogle,
                      ),
                    ),
                    const SizedBox(height: 16),

                    // PRZYCISK GOŚCIA
                    SizedBox(
                      width: double.infinity,
                      height: 50,
                      child: ElevatedButton.icon(
                        icon: const Icon(Icons.person_outline),
                        label: const Text("GUEST ACCESS (Read-Only)"),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: Colors.grey[800],
                          foregroundColor: Colors.white,
                        ),
                        onPressed: _loginAnon,
                      ),
                    ),
                  ],
                ),
            ],
          ),
        ),
      ),
    );
  }
}
