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

  // Anonim
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

  // Google acc
  Future<void> _loginGoogle() async {
    setState(() => _isLoading = true); // forces recall build to show loading

    try {
      final GoogleSignIn googleSignIn = GoogleSignIn.instance;

      await googleSignIn.initialize();

      //throws an exception if cancelled, it does NOT return null.
      final GoogleSignInAccount googleUser = await googleSignIn.authenticate(
        scopeHint: ['email'], // Hint to request email scope
      );

      final GoogleSignInAuthentication googleAuth = googleUser.authentication;

      final authClient = googleSignIn.authorizationClient;
      final authorization = await authClient.authorizationForScopes(['email']);

      final credential = GoogleAuthProvider.credential(
        accessToken: authorization?.accessToken,
        idToken: googleAuth.idToken,
      );

      await FirebaseAuth.instance.signInWithCredential(credential);
    } catch (e) {
      if (mounted) {
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
                "Storage for Binary Threats",
                style: TextStyle(color: Colors.grey),
              ),
              const Text(
                "AM JR AP KP",
                style: TextStyle(color: Color.fromARGB(255, 182, 136, 136)),
                softWrap: true,
              ),
              const SizedBox(height: 50),

              if (_isLoading)
                const CircularProgressIndicator()
              else
                Column(
                  children: [
                    // Google btn
                    SizedBox(
                      width: double.infinity,
                      height: 50,
                      child: ElevatedButton.icon(
                        icon: const Icon(Icons.g_mobiledata, size: 30),
                        label: const Text("Login with GOOGLE (Admin)"),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: Colors.white,
                          foregroundColor: Colors.black,
                        ),
                        onPressed: _loginGoogle,
                      ),
                    ),
                    const SizedBox(height: 16),

                    // Anonim btn
                    SizedBox(
                      width: double.infinity,
                      height: 50,
                      child: ElevatedButton.icon(
                        icon: const Icon(Icons.person_outline),
                        label: const Text("Anonymous Login"),
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
