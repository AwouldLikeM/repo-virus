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
  // --- KONFIGURACJA STRUMIENIA ---
  int _currentLimit = 20; // Startujemy od 20 elementów
  final int _limitIncrement = 20; // O ile zwiększać przy scrollowaniu
  final ScrollController _scrollController = ScrollController();

  SortOption _currentSort = SortOption.dateDesc;
  GroupOption _currentGroup = GroupOption.none;

  @override
  void initState() {
    super.initState();
    // Nasłuchujemy scrolla, żeby zwiększyć limit ("Infinite Scroll")
    _scrollController.addListener(() {
      if (_scrollController.position.pixels >=
          _scrollController.position.maxScrollExtent - 200) {
        _loadMore();
      }
    });
  }

  void _loadMore() {
    // Po prostu zwiększamy limit.
    // SetState przebuduje UI -> StreamBuilder dostanie nowy limit -> Firebase dociągnie dane.
    setState(() {
      _currentLimit += _limitIncrement;
    });
  }

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  // --- HELPERS UI ---
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

  // --- LOGIKA SORTOWANIA I GRUPOWANIA (Client Side) ---
  // Przy StreamBuilderze sortowanie robimy w zapytaniu (Server Side),
  // ale grupowanie robimy na pobranych danych (Client Side).

  Stream<QuerySnapshot> _getStream() {
    Query query = FirebaseFirestore.instance.collection('infected_files');

    // 1. Server-Side Sorting (Wymagane dla limitu)
    switch (_currentSort) {
      case SortOption.dateDesc:
        query = query.orderBy('uploaded_at', descending: true);
        break;
      case SortOption.dateAsc:
        query = query.orderBy('uploaded_at', descending: false);
        break;
      case SortOption.riskDesc:
        query = query.orderBy('dynamic_metadata.risk_score', descending: true);
        break;
      case SortOption.riskAsc:
        query = query.orderBy('dynamic_metadata.risk_score', descending: false);
        break;
      case SortOption.nameAsc:
        query = query.orderBy('original_filename', descending: false);
        break;
    }

    // 2. Limit (To jest nasz mechanizm "paginacji")
    return query.limit(_currentLimit).snapshots();
  }

  Map<String, List<DocumentSnapshot>> _groupDocs(List<DocumentSnapshot> docs) {
    Map<String, List<DocumentSnapshot>> groups = {};

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

      if (!groups.containsKey(groupKey)) groups[groupKey] = [];
      groups[groupKey]!.add(doc);
    }
    return groups;
  }

  // --- WIDGET BUDOWANIA KARTY ---
  Widget _buildFileCard(
    BuildContext context,
    DocumentSnapshot doc,
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
              "$riskScore",
              style: TextStyle(color: statusColor, fontSize: 15),
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
          PopupMenuButton<GroupOption>(
            icon: const Icon(Icons.category),
            tooltip: "Group by...",
            onSelected: (GroupOption result) =>
                setState(() => _currentGroup = result),
            itemBuilder: (context) => [
              const PopupMenuItem(
                value: GroupOption.none,
                child: Text("No Grouping"),
              ),
              const PopupMenuItem(
                value: GroupOption.fileType,
                child: Text("Group by Type"),
              ),
              const PopupMenuItem(
                value: GroupOption.riskLevel,
                child: Text("Group by Risk"),
              ),
            ],
          ),
          PopupMenuButton<SortOption>(
            icon: const Icon(Icons.sort),
            tooltip: "Sort by...",
            onSelected: (SortOption result) =>
                setState(() => _currentSort = result),
            itemBuilder: (context) => [
              const PopupMenuItem(
                value: SortOption.dateDesc,
                child: Text("Date: Newest"),
              ),
              const PopupMenuItem(
                value: SortOption.dateAsc,
                child: Text("Date: Oldest"),
              ),
              const PopupMenuItem(
                value: SortOption.riskDesc,
                child: Text("Risk: Highest"),
              ),
              const PopupMenuItem(
                value: SortOption.riskAsc,
                child: Text("Risk: Lowest"),
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
      // TU JEST POWRÓT KRÓLA (StreamBuilder)
      // ... (początek StreamBuilder bez zmian)
      body: StreamBuilder<QuerySnapshot>(
        stream: _getStream(),
        builder: (context, snapshot) {
          if (snapshot.hasError)
            return const Center(child: Text("Database Error"));

          if (snapshot.connectionState == ConnectionState.waiting &&
              !snapshot.hasData) {
            return const Center(child: CircularProgressIndicator());
          }

          final docs = snapshot.data?.docs ?? [];
          if (docs.isEmpty)
            return const Center(child: Text("Repository is clean."));

          // Jeśli otrzymaliśmy mniej dokumentów niż wynosi nasz limit,
          // to znaczy, że dotarliśmy do końca kolekcji.
          final bool hasMore = docs.length >= _currentLimit;

          // WIDOK 1: PŁASKA LISTA (BEZ GRUPOWANIA)
          if (_currentGroup == GroupOption.none) {
            return ListView.builder(
              controller: _scrollController,
              // Dodajemy loader (+1) TYLKO jeśli hasMore jest true
              itemCount: docs.length + (hasMore ? 1 : 0),
              itemBuilder: (context, index) {
                // Jeśli jesteśmy na ostatnim indeksie I mamy więcej danych -> pokaż Loader
                if (hasMore && index == docs.length) {
                  return const Padding(
                    padding: EdgeInsets.all(16.0),
                    child: Center(
                      child: SizedBox(
                        width: 20,
                        height: 20,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      ),
                    ),
                  );
                }
                // W przeciwnym razie pokaż kartę pliku
                return _buildFileCard(context, docs[index], isAnon);
              },
            );
          }
          // WIDOK 2: GRUPOWANIE
          else {
            final groups = _groupDocs(docs);
            var sortedKeys = groups.keys.toList();

            sortedKeys.sort((a, b) {
              if (_currentGroup == GroupOption.riskLevel) {
                if (a.contains("CRITICAL")) return -1;
                if (b.contains("CRITICAL")) return 1;
              }
              return a.compareTo(b);
            });

            return ListView(
              controller: _scrollController,
              children: [
                ...sortedKeys.map((key) {
                  final groupDocs = groups[key]!;
                  return Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
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
                          ),
                        ),
                      ),
                      ...groupDocs.map(
                        (doc) => _buildFileCard(context, doc, isAnon),
                      ),
                    ],
                  );
                }),

                if (hasMore)
                  const Padding(
                    padding: EdgeInsets.all(16.0),
                    child: Center(
                      child: SizedBox(
                        width: 20,
                        height: 20,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      ),
                    ),
                  ),
              ],
            );
          }
        },
      ),
    );
  }
}
