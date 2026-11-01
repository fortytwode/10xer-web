# Runtime configuration

Copy `.env.example` to `.env` and supply the deployment's private configuration through its existing environment configuration. The populated `.env` is ignored. Startup requires a nonempty `MONGO_URI` and a unique, private `SECRET_KEY`; the shared session-secret fallback has been removed. Configure Meta, JWT and email values for the integrations you use.

Before deploying this change, provision those values in the runtime environment. Rotate the MongoDB credential, Meta app secret, JWT signing secret and Gmail app password previously stored in Git, and replace the session secret. Changing signing/session secrets can invalidate existing sessions. Verify affected consumers before retiring old credentials. Removing the file from the current tree does not remove Git history or revoke any credential.
