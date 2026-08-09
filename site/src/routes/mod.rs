mod home;
mod legal;
mod not_found;
mod oauth_callback;
mod security;
mod start;

pub use home::HomePage;
pub use legal::{PrivacyPage, TermsPage};
pub use not_found::NotFoundPage;
pub use oauth_callback::OAuthCallbackPage;
pub use security::SecurityPage;
pub use start::StartPage;
