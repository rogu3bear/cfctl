use std::{
    fs, io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{TaskError, io_error};

const MAX_PROMOTION_ERROR_BYTES: usize = 2_048;

pub(super) trait PromotionFilesystem {
    fn path_exists(&mut self, path: &Path) -> io::Result<bool>;
    fn publish_if_absent(&mut self, staged: &Path, final_dist: &Path) -> io::Result<()>;
    fn exchange(&mut self, staged: &Path, final_dist: &Path) -> io::Result<()>;
    fn retire(&mut self, retired: &Path) -> io::Result<()>;
}

struct NativePromotionFilesystem;

impl PromotionFilesystem for NativePromotionFilesystem {
    fn path_exists(&mut self, path: &Path) -> io::Result<bool> {
        path.try_exists()
    }

    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    fn publish_if_absent(&mut self, staged: &Path, final_dist: &Path) -> io::Result<()> {
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            staged,
            rustix::fs::CWD,
            final_dist,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(Into::into)
    }

    #[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
    fn publish_if_absent(&mut self, _staged: &Path, _final_dist: &Path) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "atomic release publication is supported only on Apple and Linux platforms",
        ))
    }

    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    fn exchange(&mut self, staged: &Path, final_dist: &Path) -> io::Result<()> {
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            staged,
            rustix::fs::CWD,
            final_dist,
            rustix::fs::RenameFlags::EXCHANGE,
        )
        .map_err(Into::into)
    }

    #[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
    fn exchange(&mut self, _staged: &Path, _final_dist: &Path) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "atomic release replacement is supported only on Apple and Linux platforms",
        ))
    }

    fn retire(&mut self, retired: &Path) -> io::Result<()> {
        fs::remove_dir_all(retired)
    }
}

#[derive(Debug)]
pub(super) struct ReleaseStaging {
    dist: PathBuf,
    proof: PathBuf,
}

impl ReleaseStaging {
    pub(super) fn create(base: &Path, commit: &str) -> Result<Self, TaskError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TaskError::Clock)?
            .as_nanos();
        let commit_prefix = commit.get(..12).unwrap_or(commit);
        let transaction_id = format!("{commit_prefix}-{}-{timestamp}", std::process::id());
        Self::at(base.to_owned(), &transaction_id)
    }

    pub(super) fn at(base: PathBuf, transaction_id: &str) -> Result<Self, TaskError> {
        if transaction_id.is_empty()
            || !transaction_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(TaskError::Command(
                "release transaction id contains unsupported characters".to_owned(),
            ));
        }
        let root = base.join(transaction_id);
        let dist = root.join("dist");
        let proof = root.join("proof");
        fs::create_dir_all(&dist).map_err(|source| io_error(&dist, source))?;
        fs::create_dir_all(&proof).map_err(|source| io_error(&proof, source))?;
        Ok(Self { dist, proof })
    }

    pub(super) fn dist(&self) -> &Path {
        &self.dist
    }

    pub(super) fn proof(&self) -> &Path {
        &self.proof
    }

    pub(super) fn promote(&self, final_dist: &Path) -> Result<(), TaskError> {
        self.promote_with(final_dist, &mut NativePromotionFilesystem)
    }

    pub(super) fn promote_with(
        &self,
        final_dist: &Path,
        filesystem: &mut impl PromotionFilesystem,
    ) -> Result<(), TaskError> {
        let parent = final_dist.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
        let final_exists = filesystem.path_exists(final_dist).map_err(|error| {
            promotion_error("inspect final path", &self.dist, final_dist, &error, false)
        })?;
        if !final_exists {
            return filesystem
                .publish_if_absent(&self.dist, final_dist)
                .map_err(|error| {
                    promotion_error(
                        "publish first distribution",
                        &self.dist,
                        final_dist,
                        &error,
                        false,
                    )
                });
        }

        filesystem
            .exchange(&self.dist, final_dist)
            .map_err(|error| {
                promotion_error(
                    "atomically exchange distributions",
                    &self.dist,
                    final_dist,
                    &error,
                    false,
                )
            })?;
        filesystem.retire(&self.dist).map_err(|error| {
            promotion_error(
                "retire previous distribution",
                &self.dist,
                final_dist,
                &error,
                true,
            )
        })
    }
}

fn promotion_error(
    operation: &str,
    staged: &Path,
    final_dist: &Path,
    error: &io::Error,
    new_final_published: bool,
) -> TaskError {
    let disposition = if new_final_published {
        "; new distribution remains published and retirement of the previous staged path is incomplete"
    } else {
        "; accepted final path was not disturbed"
    };
    let context = format!(
        "release promotion could not {operation}{disposition}: kind={:?}, cause={error}, staged={}, final={}",
        error.kind(),
        staged.display(),
        final_dist.display(),
    )
    .replace(['\n', '\r'], " ");
    TaskError::Command(bound_text(&context, MAX_PROMOTION_ERROR_BYTES))
}

fn bound_text(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let suffix = " [TRUNCATED]";
    let mut boundary = max_bytes.saturating_sub(suffix.len());
    while !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    let mut bounded = text[..boundary].to_owned();
    bounded.push_str(suffix);
    bounded
}
