## ADDED Requirements

### Requirement: Automerge metadata ownership for content-addressed blobs
The system SHALL store attachment and file metadata, including Blake3 content hash, byte length, MIME type, file name, and blob ticket or location within Automerge CRDT documents, while delegating binary storage and network transport to `iroh-blobs`.

#### Scenario: User attaches a file to an item or message
- **WHEN** a user uploads or attaches a binary file
- **THEN** `iroh-blobs` ingests the file and produces a content hash and ticket, and Automerge stores the blob descriptor metadata without embedding raw file bytes in the CRDT document

#### Scenario: Remote peer reads blob reference from Automerge
- **WHEN** a remote peer receives an updated Automerge document containing an attachment reference
- **THEN** the peer extracts the ticket or hash from Automerge and requests the binary content from `iroh-blobs`

### Requirement: Verified streaming and retrieval via iroh-blobs
The system SHALL use `iroh-blobs` to store, stream, and cryptographically verify binary blobs with Blake3 hashes and Bao outboards.

#### Scenario: Verified blob download succeeds
- **WHEN** a peer requests a blob by hash or ticket from the network
- **THEN** `iroh-blobs` streams the blob, validates all Bao chunks against the root Blake3 hash, and returns the complete verified bytes

#### Scenario: Corrupted blob transfer is rejected
- **WHEN** incoming blob data fails cryptographic verification against the expected Blake3 hash
- **THEN** `iroh-blobs` rejects the corrupted data and notifies the caller without persisting bad bytes
