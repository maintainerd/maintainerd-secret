package grpcserver

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	secretv1 "github.com/maintainerd/secret/gen/maintainerd/secret/v1"
	"github.com/maintainerd/secret/internal/api"
	"github.com/maintainerd/secret/internal/store"
)

// Hierarchy RPCs: projects, environments, folders and scope imports. Each is a thin
// mapping onto one api method — no rules live here.

// ---------------------------------------------------------------------------
// Projects
// ---------------------------------------------------------------------------

func (s *Service) CreateProject(ctx context.Context, req *secretv1.CreateProjectRequest) (*secretv1.CreateProjectResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	project, err := s.api.CreateProject(ctx, c, api.CreateProjectInput{
		Slug:        req.GetSlug(),
		Name:        req.GetName(),
		Description: req.GetDescription(),
	})
	if err != nil {
		return nil, toStatus(err, "create project")
	}
	return &secretv1.CreateProjectResponse{Project: toProtoProject(project)}, nil
}

func (s *Service) ListProjects(ctx context.Context, req *secretv1.ListProjectsRequest) (*secretv1.ListProjectsResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	page, limit := pageOf(req.GetPage())
	projects, total, err := s.api.ListProjects(ctx, c, api.ListProjectsInput{
		Pagination: api.Pagination{Page: page, Limit: limit},
	})
	if err != nil {
		return nil, toStatus(err, "list projects")
	}
	out := make([]*secretv1.Project, 0, len(projects))
	for i := range projects {
		out = append(out, toProtoProject(&projects[i]))
	}
	return &secretv1.ListProjectsResponse{Projects: out, PageInfo: pageInfo(page, limit, total)}, nil
}

func (s *Service) GetProject(ctx context.Context, req *secretv1.GetProjectRequest) (*secretv1.GetProjectResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	project, err := s.api.GetProject(ctx, c, req.GetSlug())
	if err != nil {
		return nil, toStatus(err, "get project")
	}
	return &secretv1.GetProjectResponse{Project: toProtoProject(project)}, nil
}

func (s *Service) UpdateProject(ctx context.Context, req *secretv1.UpdateProjectRequest) (*secretv1.UpdateProjectResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	project, err := s.api.UpdateProject(ctx, c, api.UpdateProjectInput{
		Slug:        req.GetSlug(),
		Name:        req.GetName(),
		Description: req.GetDescription(),
		Status:      req.GetStatus(),
	})
	if err != nil {
		return nil, toStatus(err, "update project")
	}
	return &secretv1.UpdateProjectResponse{Project: toProtoProject(project)}, nil
}

func (s *Service) DeleteProject(ctx context.Context, req *secretv1.DeleteProjectRequest) (*secretv1.DeleteProjectResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.api.DeleteProject(ctx, c, req.GetSlug()); err != nil {
		return nil, toStatus(err, "delete project")
	}
	return &secretv1.DeleteProjectResponse{Deleted: true}, nil
}

// ---------------------------------------------------------------------------
// Environments
// ---------------------------------------------------------------------------

func (s *Service) CreateEnvironment(ctx context.Context, req *secretv1.CreateEnvironmentRequest) (*secretv1.CreateEnvironmentResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	env, err := s.api.CreateEnvironment(ctx, c, api.CreateEnvironmentInput{
		Project:     req.GetProject(),
		Slug:        req.GetSlug(),
		Name:        req.GetName(),
		Description: req.GetDescription(),
		Position:    req.GetPosition(),
	})
	if err != nil {
		return nil, toStatus(err, "create environment")
	}
	return &secretv1.CreateEnvironmentResponse{Environment: toProtoEnvironment(env)}, nil
}

func (s *Service) ListEnvironments(ctx context.Context, req *secretv1.ListEnvironmentsRequest) (*secretv1.ListEnvironmentsResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	envs, err := s.api.ListEnvironments(ctx, c, req.GetProject())
	if err != nil {
		return nil, toStatus(err, "list environments")
	}
	out := make([]*secretv1.Environment, 0, len(envs))
	for i := range envs {
		out = append(out, toProtoEnvironment(&envs[i]))
	}
	return &secretv1.ListEnvironmentsResponse{Environments: out}, nil
}

func (s *Service) GetEnvironment(ctx context.Context, req *secretv1.GetEnvironmentRequest) (*secretv1.GetEnvironmentResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	env, err := s.api.GetEnvironment(ctx, c, req.GetProject(), req.GetSlug())
	if err != nil {
		return nil, toStatus(err, "get environment")
	}
	return &secretv1.GetEnvironmentResponse{Environment: toProtoEnvironment(env)}, nil
}

func (s *Service) UpdateEnvironment(ctx context.Context, req *secretv1.UpdateEnvironmentRequest) (*secretv1.UpdateEnvironmentResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	env, err := s.api.UpdateEnvironment(ctx, c, api.UpdateEnvironmentInput{
		Project:     req.GetProject(),
		Slug:        req.GetSlug(),
		Name:        req.GetName(),
		Description: req.GetDescription(),
		Position:    req.GetPosition(),
		Status:      req.GetStatus(),
	})
	if err != nil {
		return nil, toStatus(err, "update environment")
	}
	return &secretv1.UpdateEnvironmentResponse{Environment: toProtoEnvironment(env)}, nil
}

func (s *Service) DeleteEnvironment(ctx context.Context, req *secretv1.DeleteEnvironmentRequest) (*secretv1.DeleteEnvironmentResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.api.DeleteEnvironment(ctx, c, req.GetProject(), req.GetSlug()); err != nil {
		return nil, toStatus(err, "delete environment")
	}
	return &secretv1.DeleteEnvironmentResponse{Deleted: true}, nil
}

// ---------------------------------------------------------------------------
// Folders
// ---------------------------------------------------------------------------

func (s *Service) CreateFolder(ctx context.Context, req *secretv1.CreateFolderRequest) (*secretv1.CreateFolderResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	folder, err := s.api.CreateFolder(ctx, c, api.CreateFolderInput{
		Project:     req.GetProject(),
		Environment: req.GetEnvironment(),
		Path:        req.GetPath(),
	})
	if err != nil {
		return nil, toStatus(err, "create folder")
	}
	return &secretv1.CreateFolderResponse{Folder: toProtoFolder(folder)}, nil
}

func (s *Service) ListFolders(ctx context.Context, req *secretv1.ListFoldersRequest) (*secretv1.ListFoldersResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	folders, err := s.api.ListFolders(ctx, c, api.ListFoldersInput{
		Project:     req.GetProject(),
		Environment: req.GetEnvironment(),
		Prefix:      req.GetPrefix(),
	})
	if err != nil {
		return nil, toStatus(err, "list folders")
	}
	out := make([]*secretv1.Folder, 0, len(folders))
	for i := range folders {
		out = append(out, toProtoFolder(&folders[i]))
	}
	return &secretv1.ListFoldersResponse{Folders: out}, nil
}

func (s *Service) MoveFolder(ctx context.Context, req *secretv1.MoveFolderRequest) (*secretv1.MoveFolderResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	folder, err := s.api.MoveFolder(ctx, c, api.MoveFolderInput{
		Project:     req.GetProject(),
		Environment: req.GetEnvironment(),
		From:        req.GetFrom(),
		To:          req.GetTo(),
	})
	if err != nil {
		return nil, toStatus(err, "move folder")
	}
	return &secretv1.MoveFolderResponse{Folder: toProtoFolder(folder)}, nil
}

func (s *Service) DeleteFolder(ctx context.Context, req *secretv1.DeleteFolderRequest) (*secretv1.DeleteFolderResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	window, err := optionalDuration(req.GetRecoveryWindow())
	if err != nil {
		return nil, err
	}
	deleted, err := s.api.DeleteFolder(ctx, c, api.DeleteFolderInput{
		Project:        req.GetProject(),
		Environment:    req.GetEnvironment(),
		Path:           req.GetPath(),
		RecoveryWindow: window,
	})
	if err != nil {
		return nil, toStatus(err, "delete folder")
	}
	return &secretv1.DeleteFolderResponse{SecretsDeleted: deleted}, nil
}

// ---------------------------------------------------------------------------
// Scope imports
// ---------------------------------------------------------------------------

func (s *Service) CreateImport(ctx context.Context, req *secretv1.CreateImportRequest) (*secretv1.CreateImportResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	edge, err := s.api.CreateImport(ctx, c, api.CreateImportInput{
		Project:           req.GetProject(),
		Environment:       req.GetEnvironment(),
		FolderPath:        req.GetFolderPath(),
		SourceProject:     req.GetSourceProject(),
		SourceEnvironment: req.GetSourceEnvironment(),
		SourceFolderPath:  req.GetSourceFolderPath(),
		Position:          req.GetPosition(),
	})
	if err != nil {
		return nil, toStatus(err, "create import")
	}
	return &secretv1.CreateImportResponse{ScopeImport: toProtoImport(edge)}, nil
}

func (s *Service) ListImports(ctx context.Context, req *secretv1.ListImportsRequest) (*secretv1.ListImportsResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	edges, err := s.api.ListImports(ctx, c, api.ListImportsInput{
		Project:     req.GetProject(),
		Environment: req.GetEnvironment(),
		FolderPath:  req.GetFolderPath(),
	})
	if err != nil {
		return nil, toStatus(err, "list imports")
	}
	out := make([]*secretv1.ScopeImport, 0, len(edges))
	for i := range edges {
		out = append(out, toProtoImport(&edges[i]))
	}
	return &secretv1.ListImportsResponse{Imports: out}, nil
}

func (s *Service) UpdateImport(ctx context.Context, req *secretv1.UpdateImportRequest) (*secretv1.UpdateImportResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	edge, err := s.api.SetImportEnabled(ctx, c, api.UpdateImportInput{
		ImportUUID: req.GetImportUuid(),
		Enabled:    req.GetEnabled(),
		Position:   req.GetPosition(),
	})
	if err != nil {
		return nil, toStatus(err, "update import")
	}
	return &secretv1.UpdateImportResponse{ScopeImport: toProtoImport(edge)}, nil
}

func (s *Service) DeleteImport(ctx context.Context, req *secretv1.DeleteImportRequest) (*secretv1.DeleteImportResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.api.DeleteImport(ctx, c, api.ImportRef{ImportUUID: req.GetImportUuid()}); err != nil {
		return nil, toStatus(err, "delete import")
	}
	return &secretv1.DeleteImportResponse{Deleted: true}, nil
}

// ---------------------------------------------------------------------------
// Conversions + small helpers
// ---------------------------------------------------------------------------

func toProtoProject(p *store.Project) *secretv1.Project {
	if p == nil {
		return nil
	}
	return &secretv1.Project{
		ProjectUuid: p.UUID.String(),
		Name:        p.Name,
		Slug:        p.Slug,
		Description: p.Description,
		Status:      p.Status,
	}
}

func toProtoEnvironment(e *store.Environment) *secretv1.Environment {
	if e == nil {
		return nil
	}
	return &secretv1.Environment{
		EnvironmentUuid: e.UUID.String(),
		Name:            e.Name,
		Slug:            e.Slug,
		Description:     e.Description,
		Position:        e.Position,
		Status:          e.Status,
	}
}

func toProtoFolder(f *store.Folder) *secretv1.Folder {
	if f == nil {
		return nil
	}
	return &secretv1.Folder{FolderUuid: f.UUID.String(), Name: f.Name, Path: f.Path}
}

func toProtoImport(i *store.ScopeImport) *secretv1.ScopeImport {
	if i == nil {
		return nil
	}
	return &secretv1.ScopeImport{
		ImportUuid:        i.UUID.String(),
		FolderPath:        i.FolderPath,
		SourceProject:     i.SourceProject,
		SourceEnvironment: i.SourceEnvironment,
		SourceFolderPath:  i.SourceFolderPath,
		Position:          i.Position,
		Enabled:           i.Enabled,
	}
}

// pageOf reads a Page message, applying the same defaults the REST surface does so
// the two transports paginate identically.
//
// Like response.PageParams, it does NOT clamp the upper bound: the cap belongs to the
// api layer's Pagination DTO, which REFUSES an over-large limit rather than silently
// narrowing it (a client that asked for 10000 and received 200 believes it read
// everything). Clamping in one transport and refusing in the other would be exactly the
// drift this package's structure exists to prevent.
func pageOf(p *secretv1.Page) (int, int) {
	page, limit := 1, 50
	if p != nil {
		if p.GetPage() > 0 {
			page = int(p.GetPage())
		}
		if p.GetLimit() > 0 {
			limit = int(p.GetLimit())
		}
	}
	return page, limit
}

func pageInfo(page, limit int, total int64) *secretv1.PageInfo {
	return &secretv1.PageInfo{Page: int32(page), Limit: int32(limit), Total: total}
}

// optionalDuration parses an optional duration string field.
func optionalDuration(raw string) (*time.Duration, error) {
	if raw == "" {
		return nil, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "recovery_window must be a duration such as \"168h\"")
	}
	return &d, nil
}

// optionalTime parses an optional RFC3339 timestamp field.
func optionalTime(raw string) (*time.Time, error) {
	if raw == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "timestamp must be RFC3339")
	}
	return &t, nil
}

func formatTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
