

# 🦠 Repozytorium Zainfekowanych Plików

To jest dokumentacja dla nas, żebyśmy ogarniali co tu się dzieje, jak to odpalić i co mówić prowadzącemu itp.

---

## 🚀 JAK TO ODPALIĆ (essa)

Mamy jeden skrypt, który robi wszystko:

1. Upewnij się, że masz plik `.env` i `config/serviceAccountKey.json`.
2. Odpal **`start.bat`**.

**Co ten skrypt robi w tle (w razie jakby pytał):**

1. Tworzy środowisko Pythona (`.venv`) i instaluje biblioteki.
2. **Czyści chmurę** (usuwa stare pliki z Firebase, żeby było czysto).
3. **Generuje wirusy** (tworzy lokalnie 10 plików `exe/dll/bin` z randomowymi nagłówkami z metadanymi).
4. **Wrzuca je do chmury** (Uploaduje pliki do Storage + wpisuje dane wraz z URL pliku, wraz z dynamicznymi/statycznymi metadanymi do Firestore).
5. **Odpala apkę Fluttera** na podłączonym telefonie/emulatorze.

---

## 🧠 ARCHITEKTURA

Mamy 3 główne klocki. Jak zapyta "jak to działa?", lecicie tytm schematem:

### 1. Generator (`generator.py`)

To nie są prawdziwe wirusy (bo by nas Defender zablokował). To wydmuszki.

* **Co robimy:** Bierzemy systemowy `calc.exe` (zmieniona nazwa na `virus.exe`) jako szablon.
* **Bajer:** Edytujemy binarnie nagłówki **PE (Portable Executable)**. Wpisujemy tam fejkowe dane: "Microsoft", "NVIDIA", "Trojan".
* **Ważne:** Pliki mają różny rozmiar, bo doklejamy na końcu losowe śmieci (Overlay). Dzięki temu każdy plik ma inny Hash i wagę (wygląda to legitnie), ale nadal ma poprawną strukturę.

### 2. Backend / Ingestia (`uploader.py`)

To nasz "automat", który udaje *Cloud Functions*. Działa w trybie **Batch** (wsadowym).

* **Krok A:** Czyta plik z dysku, sprawdza co to za .exe (dzięki bibliotece `pefile`).
* **Krok B:** Wysyła plik do **Firebase Storage** (jako **BLOB**).
* **Krok C:** Jak upload się udał, to zapisuje metadane do **Firestore Database** (wraz z unikalny URL do pliku ze *Storage*).
* **Fail-safe:** Jak baza danych wywali błąd, to skrypt **usuwa plik ze Storage** (cofa zmiany). To się nazywa "transakcja kompensacyjna" (brzmi mądrze, warto użyć xd).

### 3. Aplikacja Mobilna (Flutter)

Podzielona na moduły (Login, Dashboard, Detale).

* **StreamBuilder:** Używamy tego wszędzie. To znaczy, że jak Admin zmieni coś w bazie, to wszyscy widzą zmianę **NATYCHMIAST** bez odświeżania (WebSocket).  
**Role:**  
-- **Gość (Anonim):** Widzi listę, wchodzi w detale, ale przyciski ma wyszarzone.  
-- **Admin (Analityk):** Może pobierać pliki, edytować notatki do pliku i zmieniać tagi (metadane dynamiczne).



---

## 📚 ŚCIĄGA Z TEORII

**Pytanie:** *Dlaczego trzymacie pliki w Storage, a nie w Bazie Danych?*  
**Odpowiedź:** Bo bazy (Firestore) są do tekstu/JSONów i są drogie. Pliki binarne (BLOBs) trzyma się w **Object Storage** (tanie, szybkie, do dużych danych). W bazie trzymamy tylko link (URL) do pliku. Mieścimy się w Free Tierze.

**Pytanie:** *Czym się różnią metadane statyczne od dynamicznych?*  
**Odpowiedź:**

* **Statyczne:** Są "wypalone" w pliku `.exe` (np. Architektura x64, Nazwa Firmy). Nie da się ich zmienić bez edycji pliku (co nie jest takie proste). Wyciągamy je Pythonem.
* **Dynamiczne:** To tagi w chmurze (np. "Risk Score", "Status: Kwarantanna", "tagi"). Żyją tylko w bazie danych i możemy je zmieniać w aplikacji.

**Pytanie:** *Co jak dwóch adminów edytuje ten sam plik?*  
**Odpowiedź:** Firestore obsługuje "Last Write Wins". Dzięki StreamBuilderowi drugi admin od razu zobaczy, że pierwszy coś zmienił.

**Pytanie:** *Czemu nie Cloud Functions?*  
**Odpowiedź:** Bo mieliśmy zrobić aplikację typu "Batch" (wsadową). Skrypt w Pythonie odpalany lokalnie robi to samo co funkcja, a jest łatwiejszy w kontroli i nie zżera limitów Cloud Functions na darmowym koncie.

---

## ⚠️ KONFIGURACJA (Nie wrzucać na GitHuba!)

Te pliki są ignorowane przez `.gitignore` i każdy musi je mieć u siebie lokalnie:

1. `.env` - tu są nazwy bucketa i ścieżki.
2. `config/serviceAccountKey.json` - klucz do backendu (Python).
3. `android/app/google-services.json` - klucz do apki (Flutter).

Jeżeli tu dotarłeś to daj łapkę w górę, napisz komentarz oraz zasubskrybuj gemini Pro.