import 'package:flutter/material.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'file_detail_screen.dart'; // Importujemy ekran detali

class DashboardScreen extends StatelessWidget {
  const DashboardScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final user = FirebaseAuth.instance.currentUser;
    final isAnon = user?.isAnonymous ?? true;

    return Scaffold(
      appBar: AppBar(
        title: const Text("Threat Repository"),
        actions: [
          Center(
            child: Text(
              isAnon ? "GUEST" : "ADMIN",
              style: TextStyle(
                color: isAnon ? Colors.grey : Colors.red,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
          IconButton(
            icon: const Icon(Icons.logout),
            onPressed: () => FirebaseAuth.instance.signOut(),
          ),
        ],
      ),
      body: StreamBuilder<QuerySnapshot>(
        stream: FirebaseFirestore.instance
            .collection('infected_files')
            .orderBy('uploaded_at', descending: true)
            .snapshots(),
        builder: (context, snapshot) {
          if (snapshot.hasError)
            return const Center(child: Text("Database Error"));
          if (snapshot.connectionState == ConnectionState.waiting)
            return const Center(child: CircularProgressIndicator());

          final docs = snapshot.data!.docs;
          if (docs.isEmpty)
            return const Center(child: Text("Repository is clean... for now."));

          return ListView.builder(
            itemCount: docs.length,
            itemBuilder: (context, index) {
              final data = docs[index].data() as Map<String, dynamic>;
              final docId = docs[index].id;

              final status = data['status'] ?? 'unknown';
              Color statusColor = Colors.grey;
              if (status == 'quarantined') statusColor = Colors.red;
              if (status == 'flagged') statusColor = Colors.orange;
              if (status == 'active') statusColor = Colors.green;

              return Card(
                margin: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                child: ListTile(
                  leading: Icon(Icons.bug_report, color: statusColor, size: 40),
                  title: Text(
                    data['filename'] ?? 'Unknown File',
                    style: const TextStyle(fontWeight: FontWeight.bold),
                  ),
                  subtitle: Text(
                    "${data['static_metadata']['detected_company'] ?? 'Unknown'} • ${(data['static_metadata']['size_bytes'] / 1024).toStringAsFixed(1)} KB",
                  ),
                  trailing: const Icon(Icons.arrow_forward_ios, size: 16),
                  onTap: () {
                    Navigator.push(
                      context,
                      MaterialPageRoute(
                        builder: (_) => FileDetailScreen(
                          docId: docId,
                          initialData: data,
                          isAnon: isAnon,
                        ),
                      ),
                    );
                  },
                ),
              );
            },
          );
        },
      ),
    );
  }
}
