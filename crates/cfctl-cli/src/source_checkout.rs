//! Public exact-source selection for native committed D1 read inventories.
use cfctl_core::d1_read_inventory::D1ReadSourceSelectionV1;
use clap::Args;
use std::path::PathBuf;

#[derive(Debug, Default, Args)]
pub struct SourceCheckoutArgs {
    /// Use a linked checkout of the unique registered D1 read owner.
    #[arg(long, requires_all = ["source_head", "source_tree"])]
    pub source_checkout: Option<PathBuf>,
    /// Exact committed HEAD required in the selected checkout.
    #[arg(long, requires_all = ["source_checkout", "source_tree"])]
    pub source_head: Option<String>,
    /// Exact Git tree required in the selected checkout.
    #[arg(long, requires_all = ["source_checkout", "source_head"])]
    pub source_tree: Option<String>,
}

impl SourceCheckoutArgs {
    pub fn selection(&self) -> Result<Option<D1ReadSourceSelectionV1>, String> {
        match (&self.source_checkout, &self.source_head, &self.source_tree) {
            (None, None, None) => Ok(None),
            (Some(root), Some(head), Some(tree)) => Ok(Some(D1ReadSourceSelectionV1 {
                checkout_root: root
                    .to_str()
                    .ok_or("source checkout must be UTF-8")?
                    .to_owned(),
                head: head.clone(),
                tree: tree.clone(),
            })),
            _ => Err("source checkout, head and tree must be supplied together".to_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;
    #[test]
    fn exact_source_flags_are_public_and_cannot_be_partial() {
        for prefix in [vec!["catalog", "show"], vec!["guide"], vec!["call"]] {
            let mut args = vec!["cfctl"];
            args.extend(prefix);
            args.extend([
                "example.d1-read-inventory",
                "--source-checkout",
                "/selected",
            ]);
            assert!(crate::Cli::try_parse_from(&args).is_err());
            args.extend([
                "--source-head",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "--source-tree",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ]);
            assert!(crate::Cli::try_parse_from(&args).is_ok());
        }
    }
}
