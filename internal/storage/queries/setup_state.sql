-- The durable one-shot setup lock.

-- name: EnsureSetupState :exec
INSERT INTO setup_state (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

-- name: GetSetupState :one
SELECT * FROM setup_state WHERE id = 1;

-- CompleteSetup is the one-shot itself. The `WHERE setup_state.completed_at IS
-- NULL` guard on the DO UPDATE branch is what makes it single-use: a second caller
-- matches the conflict, fails the guard, updates nothing, and gets NO ROW back —
-- which the service reads as "already complete". Two concurrent callers therefore
-- cannot both win, because the row lock taken by ON CONFLICT serializes them and
-- the loser sees the winner's completed_at.
--
-- This is the fix for the prototype's in-memory lock, which reopened the setup
-- window on every process restart (and, with an empty bootstrap token, reopened it
-- unauthenticated).
-- name: CompleteSetup :one
INSERT INTO setup_state (id, completed_at, controller, controller_kind)
VALUES (1, now(), sqlc.arg(controller), sqlc.arg(controller_kind))
ON CONFLICT (id) DO UPDATE
   SET completed_at    = now(),
       controller      = sqlc.arg(controller),
       controller_kind = sqlc.arg(controller_kind),
       updated_at      = now()
   WHERE setup_state.completed_at IS NULL
RETURNING *;
