-- Deliberate failure after the actual initial-open UPDATE, isolated qualification only.
-- Root-authorized native import only after exact current recovery evidence and
-- deployed writer identities have been admitted. Not an HTTP endpoint.
-- This command is bound to the INITIAL post-bootstrap closed state (epoch 1,
-- revision 1). Later reopen operations require a newly reviewed tracked SQL
-- candidate with the observed nonsecret expected epoch/revision; no preflight
-- or export anchor substitutes for these transaction-time predicates.
CREATE TABLE sign_recovery_command_assert (ok INTEGER NOT NULL CHECK(ok=1));
INSERT INTO sign_recovery_command_assert SELECT count(*)=1 FROM sign_bootstrap_marker
WHERE singleton=1 AND protocol=7 AND object_prefix='sign-v7/docs/';
INSERT INTO sign_recovery_command_assert SELECT count(*)=1 FROM sign_schema_certifications WHERE contract_version=7;
UPDATE sign_recovery_control SET mode='open', revision=revision+1, epoch=epoch+1
WHERE singleton=1 AND protocol=7 AND mode='closed' AND epoch=1 AND revision=1;
INSERT INTO sign_recovery_command_assert VALUES(0);
INSERT INTO sign_recovery_command_assert VALUES(changes()=1);
DROP TABLE sign_recovery_command_assert;
