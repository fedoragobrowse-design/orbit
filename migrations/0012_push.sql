CREATE TABLE push_subscriptions(id uuid PRIMARY KEY,owner_id uuid NOT NULL REFERENCES users(id),endpoint text NOT NULL,p256dh text NOT NULL,auth text NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(owner_id,id),UNIQUE(owner_id,endpoint));
CREATE INDEX push_subscriptions_owner ON push_subscriptions(owner_id,created_at,id);
CREATE TABLE push_vapid_keys(owner_id uuid PRIMARY KEY REFERENCES users(id),secret_id uuid NOT NULL,public_key text NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
