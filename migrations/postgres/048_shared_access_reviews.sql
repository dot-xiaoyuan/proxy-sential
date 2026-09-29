CREATE TABLE shared_access_reviews (
 review_id text PRIMARY KEY,
 account_id text NOT NULL,
 campus_id text NOT NULL,
 access_domain text NOT NULL,
 session_generation text NOT NULL,
 episode integer NOT NULL DEFAULT 1 CHECK(episode>0),
 state text NOT NULL DEFAULT 'pending',
 latest_version bigint NOT NULL DEFAULT 0,
 latest_result jsonb NOT NULL,
 coverage_state text NOT NULL DEFAULT 'unknown',
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(account_id,campus_id,access_domain,session_generation,episode)
);
CREATE INDEX shared_access_reviews_page ON shared_access_reviews(created_at DESC,review_id DESC);
CREATE TABLE shared_access_review_evidence (
 review_id text NOT NULL REFERENCES shared_access_reviews(review_id),
 version bigint NOT NULL,
 evidence_key text NOT NULL,
 evidence jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(review_id,version),
 UNIQUE(review_id,evidence_key)
);
CREATE TABLE shared_access_review_executions (
 review_id text NOT NULL REFERENCES shared_access_reviews(review_id),
 action_id text NOT NULL REFERENCES enforcement_actions(action_id),
 evidence_version bigint NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(review_id,action_id)
);
CREATE INDEX shared_access_review_executions_page ON shared_access_review_executions(review_id,created_at DESC,action_id DESC);
CREATE TABLE shared_access_review_conclusions (
 conclusion_id bigserial PRIMARY KEY,
 review_id text NOT NULL REFERENCES shared_access_reviews(review_id),
 evidence_version bigint NOT NULL,
 operator_id text NOT NULL,
 conclusion text NOT NULL CHECK(conclusion IN ('shared','normal','insufficient')),
 reason text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
