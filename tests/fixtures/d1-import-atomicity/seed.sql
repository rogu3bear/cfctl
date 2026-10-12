-- Synthetic Sign original-state fixture for isolated native-import qualification.
-- Never a production repair or an inferred migration ledger.
CREATE TABLE audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      doc_id TEXT NOT NULL,
      action TEXT NOT NULL,
      metadata TEXT,
      timestamp TEXT NOT NULL,
      ip_address TEXT NOT NULL
    , prev_hash TEXT, leaf_hash TEXT);
INSERT INTO "audit_log" VALUES(9,'expired','fixture',NULL,'2000-01-01','127.0.0.1',NULL,NULL);
CREATE TABLE audit_segments (
                        segment_id INTEGER PRIMARY KEY,
                        merkle_root TEXT NOT NULL,
                        leaf_count INTEGER NOT NULL,
                        first_leaf_id INTEGER NOT NULL,
                        last_leaf_id INTEGER NOT NULL,
                        sealed_at TEXT NOT NULL
                    );
CREATE TABLE document_download_tokens (
                        id TEXT PRIMARY KEY,
                        doc_id TEXT NOT NULL UNIQUE,
                        token TEXT NOT NULL UNIQUE,
                        expires_at TEXT NOT NULL,
                        download_count INTEGER DEFAULT 0,
                        created_at TEXT NOT NULL
                    );
CREATE TABLE documents (
      id TEXT PRIMARY KEY,
      filename TEXT NOT NULL,
      content_hash TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    , artifact_signature TEXT);
CREATE TABLE download_tokens (
      id TEXT PRIMARY KEY,
      session_id TEXT NOT NULL,
      email TEXT NOT NULL,
      token TEXT NOT NULL UNIQUE,
      expires_at TEXT NOT NULL,
      download_count INTEGER DEFAULT 0,
      created_at TEXT NOT NULL
    );
CREATE TABLE my_documents_tokens (
                        id TEXT PRIMARY KEY,
                        email TEXT NOT NULL,
                        token TEXT NOT NULL UNIQUE,
                        expires_at TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    );
CREATE TABLE sign_schema_certifications (contract_version INTEGER PRIMARY KEY, migration_digest_sha256 TEXT NOT NULL, certified_at_ts INTEGER NOT NULL);
CREATE TABLE sign_schema_migrations (version INTEGER PRIMARY KEY, digest_sha256 TEXT NOT NULL, applied_at_ts INTEGER NOT NULL);
INSERT INTO "sign_schema_migrations" VALUES(1,'9bb789a6313f39dbcc5d19808d60300aa61f70bca8b185c3a9f869a375cd4b81',1);
CREATE TABLE signature_placements (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        signature_id INTEGER NOT NULL,
                        placement_index INTEGER NOT NULL,
                        page INTEGER NOT NULL,
                        position_x REAL NOT NULL,
                        position_y REAL NOT NULL
                    );
CREATE TABLE signatures (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      doc_id TEXT NOT NULL,
      signer_name TEXT NOT NULL,
      signer_email TEXT,
      signature_data TEXT NOT NULL,
      crypto_signature TEXT NOT NULL,
      position_x REAL NOT NULL,
      position_y REAL NOT NULL,
      page INTEGER NOT NULL,
      signed_at TEXT NOT NULL,
      ip_address TEXT NOT NULL
    , signature_kind TEXT, user_agent TEXT, geo_country TEXT, attestation_text TEXT);
INSERT INTO "signatures" VALUES(7,'expired','Synthetic',NULL,'drawn','legacy',1.0,1.0,1,'2000-01-01','127.0.0.1',NULL,NULL,NULL,NULL);
CREATE TABLE signing_sessions (
      id TEXT PRIMARY KEY,
      doc_id TEXT NOT NULL,
      uploader_email TEXT NOT NULL,
      recipient_email TEXT NOT NULL,
      uploader_name TEXT,
      recipient_name TEXT,
      uploader_signed INTEGER DEFAULT 0,
      recipient_signed INTEGER DEFAULT 0,
      uploader_token TEXT NOT NULL UNIQUE,
      recipient_token TEXT NOT NULL UNIQUE,
      status_token TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL,
      first_signed_at TEXT,
      completed_at TEXT
    );
INSERT INTO "signing_sessions" VALUES('session','expired','a@example.invalid','b@example.invalid',NULL,NULL,0,0,'up','rec','status','2000-01-01',NULL,NULL);
CREATE INDEX idx_audit_segments_last_leaf_id ON audit_segments(last_leaf_id);
CREATE INDEX idx_doc_expires ON documents(expires_at);
CREATE INDEX idx_document_download_token ON document_download_tokens(token);
CREATE INDEX idx_download_token ON download_tokens(token);
CREATE INDEX idx_my_documents_token ON my_documents_tokens(token);
CREATE INDEX idx_session_recipient_token ON signing_sessions(recipient_token);
CREATE INDEX idx_session_status_token ON signing_sessions(status_token);
CREATE INDEX idx_session_uploader_token ON signing_sessions(uploader_token);
CREATE INDEX idx_signature_placements_signature_id ON signature_placements(signature_id);
DELETE FROM "sqlite_sequence";
INSERT INTO "sqlite_sequence" VALUES('signatures',1000);
INSERT INTO "sqlite_sequence" VALUES('audit_log',9);
