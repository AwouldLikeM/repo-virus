import 'package:flutter/material.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:google_fonts/google_fonts.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  bool _isLoading = false;

  final String _adminEmail = "admin@virus.com";
  final String _adminPass = "Haslo123!";

  Future<void> _loginAnon() async {
    setState(() => _isLoading = true);
    try {
      await FirebaseAuth.instance.signInAnonymously();
    } catch (e) {
      if (mounted)
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text("Error: $e")));
    } finally {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  Future<void> _loginAdmin() async {
    setState(() => _isLoading = true);
    try {
      await FirebaseAuth.instance.signInWithEmailAndPassword(
        email: _adminEmail,
        password: _adminPass,
      );
    } catch (e) {
      if (mounted)
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text("Admin Auth Error: $e")));
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
                    const SizedBox(height: 16),
                    SizedBox(
                      width: double.infinity,
                      height: 50,
                      child: ElevatedButton.icon(
                        icon: const Icon(Icons.admin_panel_settings),
                        label: const Text("ANALYST PANEL (Full Access)"),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: Colors.redAccent,
                          foregroundColor: Colors.white,
                        ),
                        onPressed: _loginAdmin,
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
