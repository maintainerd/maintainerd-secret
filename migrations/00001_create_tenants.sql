-- +goose Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Auth owns identity: users, memberships, and the authoritative tenant record.
-- This service owns encrypted material and nothing else, so its tenant row is a
-- MIRROR keyed to Auth's tenant through auth_tenant_uuid — exactly the split
-- Core makes (see core migrations/00001_create_tenants.sql). Two modes fall out
-- of one table:
--
--   standalone           auth_tenant_uuid IS NULL; this install creates and owns
--                        its own tenant names, because there is no Auth to mirror.
--   ecosystem-attached   auth_tenant_uuid points at Auth's tenant_uuid, and every
--                        secret in the install hangs off that identity.
--
-- Keeping the mirror local (rather than storing Auth's UUID on every secret) means
-- a tenant lookup is one indexed read in this database and never a cross-service
-- call on the hot path of a secret read.
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id        BIGSERIAL PRIMARY KEY,
    tenant_uuid      UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    auth_tenant_uuid UUID,
    name             VARCHAR(63) NOT NULL,
    display_name     VARCHAR(255) NOT NULL DEFAULT '',
    status           VARCHAR(20) NOT NULL DEFAULT 'active',
    is_system        BOOLEAN NOT NULL DEFAULT FALSE,
    metadata         JSONB NOT NULL DEFAULT '{}',
    created_by       BIGINT,
    updated_by       BIGINT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at       TIMESTAMPTZ,
    CONSTRAINT chk_tenants_status CHECK (status IN ('active', 'suspended', 'archived'))
);

-- name is the DNS-safe slug that appears in an MRN's tenant segment
-- (mrn:secret:<tenant>:<project>:secret/<path>); unique among live rows.
CREATE UNIQUE INDEX IF NOT EXISTS uq_tenants_name ON tenants (name) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_tenants_auth_tenant_uuid ON tenants (auth_tenant_uuid) WHERE auth_tenant_uuid IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants (status);
CREATE INDEX IF NOT EXISTS idx_tenants_metadata ON tenants USING GIN (metadata);
CREATE INDEX IF NOT EXISTS idx_tenants_created_at ON tenants (created_at);
CREATE INDEX IF NOT EXISTS idx_tenants_deleted_at ON tenants (deleted_at) WHERE deleted_at IS NULL;
-- Singleton guarantee: at most one live system tenant (the bootstrap root).
CREATE UNIQUE INDEX IF NOT EXISTS uq_tenants_single_system ON tenants (is_system) WHERE is_system = TRUE AND deleted_at IS NULL;

-- +goose Down
DROP TABLE IF EXISTS tenants;
