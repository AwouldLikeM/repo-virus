import 'package:flutter/material.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:intl/intl.dart';

/// Screen that displays detailed information about a specific infected file.
/// It allows authorized users (Admins) to edit tags, update status, and manage analyst notes.
class FileDetailScreen extends StatelessWidget {
  final String docId;
  final Map<String, dynamic> initialData;
  final bool isAnon;

  const FileDetailScreen({
    super.key,
    required this.docId,
    required this.initialData,
    required this.isAnon,
  });

  /// Opens the provided URL in an external application (browser).
  Future<void> _launchURL(String url) async {
    final uri = Uri.parse(url);
    if (!await launchUrl(uri, mode: LaunchMode.externalApplication)) {
      throw 'Could not launch $url';
    }
  }

  /// Handles advanced tag editing and deletion.
  /// It opens a dialog that allows renaming a tag via a transaction (to ensure atomicity)
  /// or deleting it directly.
  void _editOrDeleteTag(BuildContext context, String currentTag) {
    final TextEditingController tagController = TextEditingController(
      text: currentTag,
    );

    showDialog(
      context: context,
      builder: (ctx) {
        return AlertDialog(
          title: Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Text("Edit Tag"),
              IconButton(
                icon: const Icon(Icons.delete, color: Colors.redAccent),
                tooltip: "Delete tag",
                onPressed: () {
                  // DELETE via arrayRemove (This is an atomic operation, so it is safe without a transaction)
                  showDialog(
                    context: context,
                    builder: (confirmCtx) {
                      return AlertDialog(
                        title: const Text("Confirm Delete"),
                        content: Text("Remove '$currentTag'?"),
                        actions: [
                          TextButton(
                            onPressed: () => Navigator.pop(confirmCtx),
                            child: const Text("Cancel"),
                          ),
                          TextButton(
                            style: TextButton.styleFrom(
                              foregroundColor: Colors.red,
                            ),
                            onPressed: () async {
                              await FirebaseFirestore.instance
                                  .collection('infected_files')
                                  .doc(docId)
                                  .update({
                                    'dynamic_metadata.tags':
                                        FieldValue.arrayRemove([currentTag]),
                                  });
                              if (context.mounted) Navigator.pop(confirmCtx);
                              if (context.mounted) Navigator.pop(ctx);
                            },
                            child: const Text("Delete"),
                          ),
                        ],
                      );
                    },
                  );
                },
              ),
            ],
          ),
          content: TextField(
            controller: tagController,
            decoration: const InputDecoration(
              labelText: "Tag Name",
              border: OutlineInputBorder(),
            ),
            autofocus: true,
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text("Cancel"),
            ),

            // --- PROFESSIONAL EDITING (TRANSACTION) ---
            ElevatedButton(
              onPressed: () async {
                String newText = tagController.text.trim();
                if (newText.isNotEmpty && newText != currentTag) {
                  final docRef = FirebaseFirestore.instance
                      .collection('infected_files')
                      .doc(docId);

                  try {
                    // Run transaction to safely update the array
                    await FirebaseFirestore.instance.runTransaction((
                      transaction,
                    ) async {
                      // 1. READ (Inside transaction!)
                      DocumentSnapshot snapshot = await transaction.get(docRef);

                      if (!snapshot.exists) {
                        throw Exception("Document does not exist!");
                      }

                      // Extract current tag list
                      List<dynamic> currentTags =
                          snapshot.get('dynamic_metadata.tags') ?? [];
                      List<String> tagsList = List<String>.from(currentTags);

                      // 2. BUSINESS LOGIC (In-memory replacement)
                      int index = tagsList.indexOf(currentTag);
                      if (index != -1) {
                        tagsList[index] = newText; // Replace in place

                        // 3. WRITE (Inside transaction!)
                        // The transaction ensures no one else modified the list in the meantime
                        transaction.update(docRef, {
                          'dynamic_metadata.tags': tagsList,
                        });
                      }
                    });

                    if (context.mounted) Navigator.pop(ctx);
                  } catch (e) {
                    // Error handling (e.g., document deleted during edit)
                    print("Transaction failed: $e");
                    if (context.mounted) {
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(content: Text("Error updating tag: $e")),
                      );
                    }
                  }
                } else {
                  Navigator.pop(ctx);
                }
              },
              child: const Text("Save"),
            ),
          ],
        );
      },
    );
  }

  /// Updates the security status of the file in Firestore.
  void _updateStatus(BuildContext context, String newStatus) {
    FirebaseFirestore.instance.collection('infected_files').doc(docId).update({
      'status': newStatus,
    });
    Navigator.pop(context);
  }

  /// Opens a dialog to add a new custom tag to the file's metadata.
  void _addCustomTag(BuildContext context) {
    final TextEditingController tagController = TextEditingController();
    showDialog(
      context: context,
      builder: (ctx) {
        return AlertDialog(
          title: const Text("Add New Tag"),
          content: TextField(
            controller: tagController,
            decoration: const InputDecoration(
              hintText: "e.g., ransomware, urgent",
            ),
            autofocus: true,
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text("Cancel"),
            ),
            TextButton(
              onPressed: () {
                if (tagController.text.isNotEmpty) {
                  FirebaseFirestore.instance
                      .collection('infected_files')
                      .doc(docId)
                      .update({
                        'dynamic_metadata.tags': FieldValue.arrayUnion([
                          tagController.text.trim(),
                        ]),
                      });
                  Navigator.pop(ctx);
                }
              },
              child: const Text("Add"),
            ),
          ],
        );
      },
    );
  }

  /// Opens a confirmation dialog to delete a specific tag (Simplified version).
  void _deleteTag(BuildContext context, String tagToDelete) {
    showDialog(
      context: context,
      builder: (ctx) {
        return AlertDialog(
          title: const Text("Delete Tag?"),
          content: Text("Are you sure you want to remove '$tagToDelete'?"),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text("No"),
            ),
            TextButton(
              style: TextButton.styleFrom(foregroundColor: Colors.red),
              onPressed: () {
                FirebaseFirestore.instance
                    .collection('infected_files')
                    .doc(docId)
                    .update({
                      'dynamic_metadata.tags': FieldValue.arrayRemove([
                        tagToDelete,
                      ]),
                    });
                Navigator.pop(ctx);
              },
              child: const Text("Yes, delete"),
            ),
          ],
        );
      },
    );
  }

  /// Opens a dialog to edit or add analyst notes to the file.
  void _editAnalystNotes(BuildContext context, String currentNotes) {
    final TextEditingController notesController = TextEditingController(
      text: currentNotes,
    );
    showDialog(
      context: context,
      builder: (ctx) {
        return AlertDialog(
          title: const Text("Edit Analyst Notes"),
          content: TextField(
            controller: notesController,
            decoration: const InputDecoration(
              hintText: "Enter your observations...",
              border: OutlineInputBorder(),
            ),
            maxLines: 5,
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text("Cancel"),
            ),
            TextButton(
              onPressed: () {
                FirebaseFirestore.instance
                    .collection('infected_files')
                    .doc(docId)
                    .update({
                      'dynamic_metadata.analyst_notes': notesController.text,
                    });
                Navigator.pop(ctx);
              },
              child: const Text("Save"),
            ),
          ],
        );
      },
    );
  }

  /// Shows a dialog allowing the admin to choose a new status for the file.
  void _showEditStatusDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (ctx) {
        return AlertDialog(
          title: const Text("Analyst Decision (Status)"),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              ListTile(
                leading: const Icon(Icons.local_hospital, color: Colors.red),
                title: const Text("Quarantine"),
                onTap: () => _updateStatus(context, "quarantined"),
              ),
              ListTile(
                leading: const Icon(Icons.warning, color: Colors.orange),
                title: const Text("Flag as Suspicious"),
                onTap: () => _updateStatus(context, "flagged"),
              ),
              ListTile(
                leading: const Icon(Icons.check_circle, color: Colors.green),
                title: const Text("Mark as Safe"),
                onTap: () => _updateStatus(context, "active"),
              ),
            ],
          ),
        );
      },
    );
  }

  /// Builds the UI of the screen, including the StreamBuilder for real-time updates.
  @override
  Widget build(BuildContext context) {
    return StreamBuilder<DocumentSnapshot>(
      stream: FirebaseFirestore.instance
          .collection('infected_files')
          .doc(docId)
          .snapshots(),
      builder: (context, snapshot) {
        Map<String, dynamic> currentData = initialData;

        if (snapshot.hasData &&
            snapshot.data != null &&
            snapshot.data!.data() != null) {
          currentData = snapshot.data!.data() as Map<String, dynamic>;
        }

        final staticMeta =
            currentData['static_metadata'] as Map<String, dynamic>? ?? {};
        final dynamicMeta =
            currentData['dynamic_metadata'] as Map<String, dynamic>? ?? {};
        final tags = List<String>.from(dynamicMeta['tags'] ?? []);
        final notes = dynamicMeta['analyst_notes'] as String? ?? "";
        final timestamp =
            (currentData['uploaded_at'] as Timestamp?)?.toDate() ??
            DateTime.now();

        int riskScore = dynamicMeta['risk_score'] ?? 0;
        Color riskColor = Colors.green;
        if (riskScore > 80) {
          riskColor = Colors.redAccent;
        } else if (riskScore > 50) {
          riskColor = Colors.orangeAccent;
        }
        final rawName =
            currentData['original_filename'] ??
            currentData['filename'] ??
            "Details";
        return Scaffold(
          appBar: AppBar(title: Text(rawName)),
          body: SingleChildScrollView(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Center(
                  child: Column(
                    children: [
                      Icon(
                        Icons.file_present,
                        size: 80,
                        color: Theme.of(context).colorScheme.primary,
                      ),
                      const SizedBox(height: 10),
                      Text(
                        "Risk Score: $riskScore/100",
                        style: TextStyle(
                          fontSize: 24,
                          fontWeight: FontWeight.bold,
                          color: riskColor,
                        ),
                      ),
                      Chip(
                        label: Text(
                          "Status: ${currentData['status']?.toUpperCase()}",
                        ),
                        backgroundColor: Colors.white10,
                      ),
                    ],
                  ),
                ),
                const Divider(height: 40),

                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    const Text(
                      "ANALYST NOTES",
                      style: TextStyle(
                        color: Colors.blueAccent,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    if (!isAnon)
                      IconButton(
                        icon: const Icon(
                          Icons.edit_note,
                          size: 24,
                          color: Colors.blueAccent,
                        ),
                        onPressed: () => _editAnalystNotes(context, notes),
                      ),
                  ],
                ),
                Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: Colors.white.withValues(alpha: 0.05),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: Colors.white10),
                  ),
                  child: Text(
                    notes.isEmpty
                        ? (isAnon
                              ? "No notes available."
                              : "No notes. Click edit icon to add.")
                        : notes,
                    style: const TextStyle(
                      fontStyle: FontStyle.italic,
                      color: Colors.white70,
                    ),
                  ),
                ),
                const SizedBox(height: 20),

                const Text(
                  "STATIC METADATA (Binary Analysis)",
                  style: TextStyle(
                    color: Colors.tealAccent,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 10),
                _buildMetaRow("Company", staticMeta['detected_company']),
                _buildMetaRow(
                  "Product",
                  "${staticMeta['product_name']} ${staticMeta['product_version']}",
                ),
                _buildMetaRow("Internal Desc", staticMeta['file_description']),
                _buildMetaRow("Architecture", staticMeta['architecture']),
                _buildMetaRow(
                  "Size",
                  "${(staticMeta['size_bytes'] ?? 0)} bytes",
                ),
                _buildMetaRow(
                  "Uploaded",
                  DateFormat('yyyy-MM-dd HH:mm').format(timestamp),
                ),

                const Divider(height: 30),

                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    const Text(
                      "DYNAMIC METADATA (Tags)",
                      style: TextStyle(
                        color: Colors.orangeAccent,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    if (!isAnon)
                      IconButton(
                        icon: const Icon(Icons.settings, size: 18),
                        onPressed: () => _showEditStatusDialog(context),
                      ),
                  ],
                ),
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    ...tags.map(
                      (tag) => GestureDetector(
                        onLongPress: isAnon
                            ? null
                            : () => _editOrDeleteTag(context, tag),
                        child: Chip(
                          label: Text(tag),
                          backgroundColor: Colors.red.withValues(alpha: 0.2),
                          avatar: const Icon(Icons.tag, size: 14),
                        ),
                      ),
                    ),
                    if (!isAnon)
                      ActionChip(
                        label: const Text("Add"),
                        avatar: const Icon(Icons.add, size: 16),
                        onPressed: () => _addCustomTag(context),
                        backgroundColor: Colors.blueAccent.withValues(
                          alpha: 0.3,
                        ),
                      ),
                  ],
                ),

                const SizedBox(height: 40),

                SizedBox(
                  width: double.infinity,
                  height: 50,
                  child: ElevatedButton.icon(
                    icon: const Icon(Icons.cloud_download),
                    label: const Text("DOWNLOAD FILE (BLOB)"),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.blueAccent,
                      foregroundColor: Colors.white,
                    ),
                    onPressed: (!isAnon)
                        ? () => _launchURL(currentData['url'])
                        : null,
                  ),
                ),
                if (isAnon)
                  const Padding(
                    padding: EdgeInsets.only(top: 8.0),
                    child: Center(
                      child: Text(
                        "Login as Analyst to download file or manage tags.",
                        style: TextStyle(color: Colors.grey, fontSize: 12),
                      ),
                    ),
                  ),
              ],
            ),
          ),
        );
      },
    );
  }

  /// Helper widget to build a single metadata row (Label + Value).
  Widget _buildMetaRow(String label, String? value) {
    if (value == null || value.isEmpty) return const SizedBox.shrink();
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // FIXED: INCREASED WIDTH FROM 100 TO 120
          SizedBox(
            width: 120,
            child: Text(label, style: const TextStyle(color: Colors.grey)),
          ),
          Expanded(
            child: Text(
              value,
              style: const TextStyle(fontFamily: 'RobotoMono'),
            ),
          ),
        ],
      ),
    );
  }
}
