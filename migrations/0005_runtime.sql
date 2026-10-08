CREATE TABLE aiec_connections (
 id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES users(id), name text NOT NULL,
 config jsonb NOT NULL, revision bigint NOT NULL DEFAULT 1, enabled boolean NOT NULL DEFAULT true,
 status text NOT NULL DEFAULT 'UNTESTED', last_test timestamptz, created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(owner_id,id)
);
CREATE TABLE runtime_runs (
 id uuid PRIMARY KEY, owner_id uuid NOT NULL, task_id uuid NOT NULL, connection_id uuid NOT NULL,
 authorization_id uuid NOT NULL UNIQUE, action_snapshot jsonb NOT NULL, task_fence bigint NOT NULL,
 spec jsonb NOT NULL, command jsonb NOT NULL, request_digest text NOT NULL CHECK(length(request_digest)=64),
 state text NOT NULL DEFAULT 'PREPARED' CHECK(state IN ('PREPARED','CREATING','RUNNING','COLLECTING','CLEANUP_PENDING','CLEANUP_CLAIMED','DESTROYED','QUARANTINED','UNRESOLVED')),
 cleanup_required boolean NOT NULL DEFAULT true, cleanup_requested boolean NOT NULL DEFAULT false,
 create_submitted boolean NOT NULL DEFAULT false, exec_submitted boolean NOT NULL DEFAULT false,
 upload_submitted boolean NOT NULL DEFAULT false, remote_running_observed boolean NOT NULL DEFAULT false,
 destroy_acknowledged boolean NOT NULL DEFAULT false, created_at_remote timestamptz,
 creator_id uuid, creator_lease_until timestamptz, runtime_fence bigint NOT NULL DEFAULT 0,
 cleanup_lease_until timestamptz, result jsonb, evidence jsonb NOT NULL DEFAULT '[]',
 active_seconds_used bigint NOT NULL DEFAULT 0, active_seconds_limit bigint NOT NULL DEFAULT 600,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(owner_id,id), FOREIGN KEY(owner_id,task_id) REFERENCES tasks(owner_id,id),
 FOREIGN KEY(owner_id,connection_id) REFERENCES aiec_connections(owner_id,id)
);
CREATE INDEX runtime_cleanup_scan ON runtime_runs(cleanup_required,creator_lease_until,cleanup_lease_until);
CREATE INDEX runtime_owner_task ON runtime_runs(owner_id,task_id,created_at,id);
CREATE TABLE runtime_operator_evidence (
 id uuid PRIMARY KEY, owner_id uuid NOT NULL, runtime_id uuid NOT NULL,
 principal_id uuid NOT NULL, provider_evidence_reference text NOT NULL,
 provisioning_fenced_and_finished boolean NOT NULL CHECK(provisioning_fenced_and_finished),
 no_live_runtime boolean NOT NULL CHECK(no_live_runtime), created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(owner_id,runtime_id) REFERENCES runtime_runs(owner_id,id),
 FOREIGN KEY(owner_id,principal_id) REFERENCES principals(owner_id,id)
);
