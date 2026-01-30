import 'package:flutter/material.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'file_detail_screen.dart';

enum SortOption { dateDesc, dateAsc, riskDesc, riskAsc, nameAsc }

enum GroupOption { none, fileType, riskLevel }

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  SortOption _currentSort = SortOption.dateDesc;
  GroupOption _currentGroup = GroupOption.none;

  // --- HELPERS ---

  String _truncateFilename(String name) {
    if (name.length <= 18) return name;
    return "${name.substring(0, 10)}...${name.substring(name.length - 6)}";
  }

  String _getFileTypeShort(String fullType) {
    if (fullType.contains("EXE")) return "EXE";
    if (fullType.contains("DLL")) return "DLL";
    if (fullType.contains("SYS")) return "SYS";
    if (fullType.contains("CPL")) return "CPL";
    return "BIN";
  }

  Color _getStatusColor(int riskScore) {
    if (riskScore > 80) return Colors.redAccent;
    if (riskScore > 50) return Colors.orangeAccent;
    return Colors.green;
  }

  // --- SORTOWANIE I GRUPOWANIE ---

  List<QueryDocumentSnapshot> _sortDocs(List<QueryDocumentSnapshot> docs) {
    docs.sort((a, b) {
      final dataA = a.data() as Map<String, dynamic>;
      final dataB = b.data() as Map<String, dynamic>;

      switch (_currentSort) {
        case SortOption.dateDesc:
          Timestamp tA = dataA['uploaded_at'] ?? Timestamp.now();
          Timestamp tB = dataB['uploaded_at'] ?? Timestamp.now();
          return tB.compareTo(tA);
        case SortOption.dateAsc:
          Timestamp tA = dataA['uploaded_at'] ?? Timestamp.now();
          Timestamp tB = dataB['uploaded_at'] ?? Timestamp.now();
          return tA.compareTo(tB);
        case SortOption.riskDesc:
          int rA = dataA['dynamic_metadata']['risk_score'] ?? 0;
          int rB = dataB['dynamic_metadata']['risk_score'] ?? 0;
          return rB.compareTo(rA);
        case SortOption.riskAsc:
          int rA = dataA['dynamic_metadata']['risk_score'] ?? 0;
          int rB = dataB['dynamic_metadata']['risk_score'] ?? 0;
          return rA.compareTo(rB);
        case SortOption.nameAsc:
          String nA = dataA['original_filename'] ?? dataA['filename'] ?? "";
          String nB = dataB['original_filename'] ?? dataB['filename'] ?? "";
          return nA.compareTo(nB);
      }
    });
    return docs;
  }

  Map<String, List<QueryDocumentSnapshot>> _groupDocs(
    List<QueryDocumentSnapshot> docs,
  ) {
    Map<String, List<QueryDocumentSnapshot>> groups = {};

    for (var doc in docs) {
      final data = doc.data() as Map<String, dynamic>;
      String groupKey = "Other";

      if (_currentGroup == GroupOption.fileType) {
        final fullType = data['static_metadata']['file_type'] ?? "Unknown";
        groupKey = _getFileTypeShort(fullType);
      } else if (_currentGroup == GroupOption.riskLevel) {
        int score = data['dynamic_metadata']['risk_score'] ?? 0;
        if (score > 80)
          groupKey = "CRITICAL (Risk > 80)";
        else if (score > 50)
          groupKey = "SUSPICIOUS (Risk 50-80)";
        else
          groupKey = "SAFE (Risk < 50)";
      }

      if (!groups.containsKey(groupKey)) {
        groups[groupKey] = [];
      }
      groups[groupKey]!.add(doc);
    }
    return groups;
  }

  // --- UI BUILDERS ---

  Widget _buildFileCard(
    BuildContext context,
    QueryDocumentSnapshot doc,
    bool isAnon,
  ) {
    final data = doc.data() as Map<String, dynamic>;
    final docId = doc.id;

    final rawName = data['original_filename'] ?? data['filename'] ?? 'Unknown';
    final displayName = _truncateFilename(rawName);

    final staticMeta = data['static_metadata'] as Map<String, dynamic>? ?? {};
    final dynamicMeta = data['dynamic_metadata'] as Map<String, dynamic>? ?? {};

    final fileTypeFull = staticMeta['file_type'] ?? "BIN";
    final fileTypeShort = _getFileTypeShort(fileTypeFull);
    final company = staticMeta['detected_company'] ?? 'Unknown';
    final sizeKB = (staticMeta['size_bytes'] ?? 0) / 1024;
    final riskScore = dynamicMeta['risk_score'] ?? 0;

    final statusColor = _getStatusColor(riskScore);

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      child: ListTile(
        leading: Container(
          width: 50,
          height: 50,
          decoration: BoxDecoration(
            color: statusColor.withOpacity(0.1),
            border: Border.all(color: statusColor, width: 2),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Center(
            child: Text(
              fileTypeShort,
              style: TextStyle(
                color: statusColor,
                fontWeight: FontWeight.bold,
                fontSize: 12,
              ),
            ),
          ),
        ),
        title: Text(
          displayName,
          style: const TextStyle(fontWeight: FontWeight.bold),
        ),
        subtitle: Text(
          "$company • ${sizeKB.toStringAsFixed(1)} KB",
          style: const TextStyle(fontSize: 12),
        ),
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              "Risk: $riskScore",
              style: TextStyle(color: statusColor, fontSize: 10),
            ),
            const SizedBox(width: 5),
            const Icon(Icons.arrow_forward_ios, size: 16),
          ],
        ),
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
  }

  @override
  Widget build(BuildContext context) {
    final user = FirebaseAuth.instance.currentUser;
    final isAnon = user?.isAnonymous ?? true;

    return Scaffold(
      appBar: AppBar(
        title: const Text("Threat Repository"),
        actions: [
          // IKONA GRUPOWANIA (Nowość)
          PopupMenuButton<GroupOption>(
            icon: const Icon(Icons.category), // Ikonka kategorii/grupowania
            tooltip: "Group by...",
            onSelected: (GroupOption result) {
              setState(() => _currentGroup = result);
            },
            itemBuilder: (context) => [
              const PopupMenuItem(
                value: GroupOption.none,
                child: Text("No Grouping"),
              ),
              const PopupMenuItem(
                value: GroupOption.fileType,
                child: Text("Group by Type (EXE, DLL...)"),
              ),
              const PopupMenuItem(
                value: GroupOption.riskLevel,
                child: Text("Group by Risk Level"),
              ),
            ],
          ),
          // IKONA SORTOWANIA
          PopupMenuButton<SortOption>(
            icon: const Icon(Icons.sort),
            tooltip: "Sort by...",
            onSelected: (SortOption result) {
              setState(() => _currentSort = result);
            },
            itemBuilder: (context) => [
              const PopupMenuItem(
                value: SortOption.dateDesc,
                child: Text("Date: Newest First"),
              ),
              const PopupMenuItem(
                value: SortOption.dateAsc,
                child: Text("Date: Oldest First"),
              ),
              const PopupMenuItem(
                value: SortOption.riskDesc,
                child: Text("Risk: Highest First"),
              ),
              const PopupMenuItem(
                value: SortOption.riskAsc,
                child: Text("Risk: Lowest First"),
              ),
              const PopupMenuItem(
                value: SortOption.nameAsc,
                child: Text("Name: A-Z"),
              ),
            ],
          ),
          Center(
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 8.0),
              child: Text(
                isAnon ? "GUEST" : "ADMIN",
                style: TextStyle(
                  color: isAnon ? Colors.grey : Colors.red,
                  fontWeight: FontWeight.bold,
                ),
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
            .snapshots(),
        builder: (context, snapshot) {
          if (snapshot.hasError)
            return const Center(child: Text("Database Error"));
          if (snapshot.connectionState == ConnectionState.waiting)
            return const Center(child: CircularProgressIndicator());

          var docs = snapshot.data!.docs;
          if (docs.isEmpty)
            return const Center(child: Text("Repository is clean."));

          // 1. Sortowanie (zawsze aktywne)
          docs = _sortDocs(docs);

          // 2. Wybór widoku: Grupowany vs Płaski
          if (_currentGroup == GroupOption.none) {
            // Widok płaski (stary)
            return ListView.builder(
              itemCount: docs.length,
              itemBuilder: (context, index) =>
                  _buildFileCard(context, docs[index], isAnon),
            );
          } else {
            // Widok grupowany (nowy)
            final groups = _groupDocs(docs);

            // Sortujemy klucze grup (np. żeby CRITICAL było przed SAFE)
            var sortedKeys = groups.keys.toList();
            if (_currentGroup == GroupOption.riskLevel) {
              // Specyficzne sortowanie dla ryzyka
              sortedKeys.sort((a, b) {
                if (a.contains("CRITICAL")) return -1; // Critical first
                if (b.contains("CRITICAL")) return 1;
                if (a.contains("SUSPICIOUS")) return -1;
                return 1;
              });
            } else {
              sortedKeys.sort(); // Alfabetycznie dla typów plików
            }

            return ListView(
              children: sortedKeys.map((key) {
                final groupDocs = groups[key]!;
                return Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // Nagłówek Grupy
                    Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 16,
                        vertical: 8,
                      ),
                      width: double.infinity,
                      color: Theme.of(context).cardColor.withOpacity(0.5),
                      child: Text(
                        "$key (${groupDocs.length})",
                        style: const TextStyle(
                          color: Colors.tealAccent,
                          fontWeight: FontWeight.bold,
                          letterSpacing: 1.2,
                        ),
                      ),
                    ),
                    // Lista kafelków w grupie
                    ...groupDocs.map(
                      (doc) => _buildFileCard(context, doc, isAnon),
                    ),
                  ],
                );
              }).toList(),
            );
          }
        },
      ),
    );
  }
}
