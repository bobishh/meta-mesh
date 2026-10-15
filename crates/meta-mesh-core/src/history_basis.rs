//! Private join of current-state and preserved-history evidence, never activation authority.
use crate::{
    causal_admission::CausalAdmissionInput,
    history_archive_coverage::VerifiedHistoryArchiveCoverage,
    history_capture::VerifiedHistoryArchiveCapture, history_rebase::VerifiedHistoryRebase,
};

pub struct VerifiedHistoryBasisArchive<'a> {
    capture: &'a VerifiedHistoryArchiveCapture,
    rebase: &'a VerifiedHistoryRebase,
    coverage: &'a VerifiedHistoryArchiveCoverage,
}

impl VerifiedHistoryArchiveCapture {
    pub fn bind_rebase<'a>(
        &'a self,
        rebase: &'a VerifiedHistoryRebase,
        coverage: &'a VerifiedHistoryArchiveCoverage,
    ) -> Result<VerifiedHistoryBasisArchive<'a>, String> {
        let preparation = self.preparation();
        let catalogue = coverage.catalogue();
        if catalogue.context.workspace_id != preparation.source().snapshot.workspace_id
            || catalogue.context.history_epoch != self.history_epoch()
            || catalogue.admission_revision != preparation.admission_revision()
            || catalogue.authority_revision != preparation.authority_digest()
            || catalogue.capture_revision != self.capture_revision()
            || rebase.admission_revision() != preparation.admission_revision()
            || rebase.authority_revision() != preparation.authority_digest()
            || rebase.history_epoch() != self.history_epoch()
            || rebase.transition_id() != coverage.data_transition_id()
            || rebase.signer() != preparation.signer()
        {
            return Err(
                "Native basis and archive do not share exact source and preparation".into(),
            );
        }
        // Coverage's private constructor already verified correspondence, exact sets,
        // both service signatures and storage bindings. A host catalogue cannot enter here.
        Ok(VerifiedHistoryBasisArchive {
            capture: self,
            rebase,
            coverage,
        })
    }
}

impl VerifiedHistoryBasisArchive<'_> {
    pub fn capture(&self) -> &VerifiedHistoryArchiveCapture {
        self.capture
    }
    pub fn rebase(&self) -> &VerifiedHistoryRebase {
        self.rebase
    }
    pub fn coverage(&self) -> &VerifiedHistoryArchiveCoverage {
        self.coverage
    }
    pub fn assert_source_current(&self, source: &CausalAdmissionInput) -> Result<(), String> {
        self.capture.preparation().assert_source_current(source)
    }
}
