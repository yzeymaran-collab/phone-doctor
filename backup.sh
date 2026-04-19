#!/bin/bash

# Phone-Doctor Backup Script
# Erstellt ein Backup der SQLite-Datenbank

BACKUP_DIR="./backups"
TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
BACKUP_FILE="$BACKUP_DIR/phone-doctor_$TIMESTAMP.db"

# Backups-Verzeichnis erstellen, falls nicht vorhanden
mkdir -p "$BACKUP_DIR"

# Datenbank backen (SQLite WAL mode-sicher)
sqlite3 server/data.db ".backup '$BACKUP_FILE'"

# Archivieren
tar -czf "$BACKUP_DIR/phone-doctor_$TIMESTAMP.tar.gz" "$BACKUP_FILE"
rm "$BACKUP_FILE"

echo "✅ Backup erstellt: $BACKUP_DIR/phone-doctor_$TIMESTAMP.tar.gz"
echo "📊 Größe: $(du -h "$BACKUP_DIR/phone-doctor_$TIMESTAMP.tar.gz" | cut -f1)"

# Alte Backups löschen (älter als 30 Tage)
find "$BACKUP_DIR" -name "phone-doctor_*.tar.gz" -mtime +30 -delete

echo "🗑️ Alte Backups gelöscht"
