package httpapi

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/maintainerd/secret/internal/api"
	"github.com/maintainerd/secret/internal/platform/response"
	"github.com/maintainerd/secret/internal/store"
)

// Hierarchy handlers: projects, environments, folders and scope imports.

// ---------------------------------------------------------------------------
// Projects
// ---------------------------------------------------------------------------

type createProjectRequest struct {
	Slug        string `json:"slug"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req createProjectRequest
	if !decode(w, r, &req) {
		return
	}
	project, err := s.api.CreateProject(r.Context(), c, api.CreateProjectInput{
		Slug:        req.Slug,
		Name:        req.Name,
		Description: req.Description,
	})
	if err != nil {
		response.ServiceError(w, r, "could not create the project", err)
		return
	}
	response.Created(w, project, "project created")
}

func (s *Server) listProjects(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	page, limit := response.PageParams(r)
	projects, total, err := s.api.ListProjects(r.Context(), c, page, limit)
	if err != nil {
		response.ServiceError(w, r, "could not list projects", err)
		return
	}
	response.List(w, projects, page, limit, total)
}

func (s *Server) getProject(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	project, err := s.api.GetProject(r.Context(), c, chi.URLParam(r, "project"))
	if err != nil {
		response.ServiceError(w, r, "could not read the project", err)
		return
	}
	response.OK(w, project, "")
}

type updateProjectRequest struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status,omitempty"`
}

func (s *Server) updateProject(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req updateProjectRequest
	if !decode(w, r, &req) {
		return
	}
	project, err := s.api.UpdateProject(r.Context(), c, store.UpdateProjectInput{
		Slug:        chi.URLParam(r, "project"),
		Name:        req.Name,
		Description: req.Description,
		Status:      req.Status,
	})
	if err != nil {
		response.ServiceError(w, r, "could not update the project", err)
		return
	}
	response.OK(w, project, "project updated")
}

func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	if err := s.api.DeleteProject(r.Context(), c, chi.URLParam(r, "project")); err != nil {
		response.ServiceError(w, r, "could not delete the project", err)
		return
	}
	response.NoContent(w)
}

// ---------------------------------------------------------------------------
// Environments
// ---------------------------------------------------------------------------

type createEnvironmentRequest struct {
	Project     string `json:"project"`
	Slug        string `json:"slug"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Position    int32  `json:"position,omitempty"`
}

func (s *Server) createEnvironment(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req createEnvironmentRequest
	if !decode(w, r, &req) {
		return
	}
	env, err := s.api.CreateEnvironment(r.Context(), c, api.CreateEnvironmentInput{
		Project:     req.Project,
		Slug:        req.Slug,
		Name:        req.Name,
		Description: req.Description,
		Position:    req.Position,
	})
	if err != nil {
		response.ServiceError(w, r, "could not create the environment", err)
		return
	}
	response.Created(w, env, "environment created")
}

func (s *Server) listEnvironments(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	project, ok := requireQuery(w, r, "project")
	if !ok {
		return
	}
	envs, err := s.api.ListEnvironments(r.Context(), c, project)
	if err != nil {
		response.ServiceError(w, r, "could not list environments", err)
		return
	}
	response.OK(w, envs, "")
}

func (s *Server) getEnvironment(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	env, err := s.api.GetEnvironment(r.Context(), c, chi.URLParam(r, "project"), chi.URLParam(r, "environment"))
	if err != nil {
		response.ServiceError(w, r, "could not read the environment", err)
		return
	}
	response.OK(w, env, "")
}

type updateEnvironmentRequest struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Position    int32  `json:"position,omitempty"`
	Status      string `json:"status,omitempty"`
}

func (s *Server) updateEnvironment(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req updateEnvironmentRequest
	if !decode(w, r, &req) {
		return
	}
	env, err := s.api.UpdateEnvironment(r.Context(), c, store.UpdateEnvironmentInput{
		Project:     chi.URLParam(r, "project"),
		Slug:        chi.URLParam(r, "environment"),
		Name:        req.Name,
		Description: req.Description,
		Position:    req.Position,
		Status:      req.Status,
	})
	if err != nil {
		response.ServiceError(w, r, "could not update the environment", err)
		return
	}
	response.OK(w, env, "environment updated")
}

func (s *Server) deleteEnvironment(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	if err := s.api.DeleteEnvironment(r.Context(), c, chi.URLParam(r, "project"), chi.URLParam(r, "environment")); err != nil {
		response.ServiceError(w, r, "could not delete the environment", err)
		return
	}
	response.NoContent(w)
}

// ---------------------------------------------------------------------------
// Folders
// ---------------------------------------------------------------------------

type createFolderRequest struct {
	Project     string `json:"project"`
	Environment string `json:"environment"`
	Path        string `json:"path"`
}

func (s *Server) createFolder(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req createFolderRequest
	if !decode(w, r, &req) {
		return
	}
	folder, err := s.api.CreateFolder(r.Context(), c, req.Project, req.Environment, req.Path)
	if err != nil {
		response.ServiceError(w, r, "could not create the folder", err)
		return
	}
	response.Created(w, folder, "folder created")
}

func (s *Server) listFolders(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	project, ok := requireQuery(w, r, "project")
	if !ok {
		return
	}
	environment, ok := requireQuery(w, r, "environment")
	if !ok {
		return
	}
	folders, err := s.api.ListFolders(r.Context(), c, project, environment, r.URL.Query().Get("prefix"))
	if err != nil {
		response.ServiceError(w, r, "could not list folders", err)
		return
	}
	response.OK(w, folders, "")
}

type moveFolderRequest struct {
	Project     string `json:"project"`
	Environment string `json:"environment"`
	From        string `json:"from"`
	To          string `json:"to"`
}

func (s *Server) moveFolder(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req moveFolderRequest
	if !decode(w, r, &req) {
		return
	}
	folder, err := s.api.MoveFolder(r.Context(), c, req.Project, req.Environment, req.From, req.To)
	if err != nil {
		response.ServiceError(w, r, "could not move the folder", err)
		return
	}
	response.OK(w, folder, "folder moved")
}

func (s *Server) deleteFolder(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	project, ok := requireQuery(w, r, "project")
	if !ok {
		return
	}
	environment, ok := requireQuery(w, r, "environment")
	if !ok {
		return
	}
	path, ok := requireQuery(w, r, "path")
	if !ok {
		return
	}
	var window *time.Duration
	if raw := r.URL.Query().Get("recovery_window"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			response.Error(w, http.StatusBadRequest, "recovery_window must be a duration such as \"168h\"")
			return
		}
		window = &d
	}
	deleted, err := s.api.DeleteFolder(r.Context(), c, project, environment, path, window)
	if err != nil {
		response.ServiceError(w, r, "could not delete the folder", err)
		return
	}
	response.OK(w, map[string]any{"secrets_deleted": deleted}, "folder deleted")
}

// ---------------------------------------------------------------------------
// Scope imports
// ---------------------------------------------------------------------------

type createImportRequest struct {
	Project           string `json:"project"`
	Environment       string `json:"environment"`
	FolderPath        string `json:"folder_path,omitempty"`
	SourceProject     string `json:"source_project"`
	SourceEnvironment string `json:"source_environment"`
	SourceFolderPath  string `json:"source_folder_path,omitempty"`
	Position          int32  `json:"position,omitempty"`
}

func (s *Server) createImport(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req createImportRequest
	if !decode(w, r, &req) {
		return
	}
	edge, err := s.api.CreateImport(r.Context(), c, api.CreateImportInput{
		Project:           req.Project,
		Environment:       req.Environment,
		FolderPath:        req.FolderPath,
		SourceProject:     req.SourceProject,
		SourceEnvironment: req.SourceEnvironment,
		SourceFolderPath:  req.SourceFolderPath,
		Position:          req.Position,
	})
	if err != nil {
		response.ServiceError(w, r, "could not create the import", err)
		return
	}
	response.Created(w, edge, "import created")
}

func (s *Server) listImports(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	project, ok := requireQuery(w, r, "project")
	if !ok {
		return
	}
	environment, ok := requireQuery(w, r, "environment")
	if !ok {
		return
	}
	edges, err := s.api.ListImports(r.Context(), c, project, environment, r.URL.Query().Get("folder_path"))
	if err != nil {
		response.ServiceError(w, r, "could not list imports", err)
		return
	}
	response.OK(w, edges, "")
}

type updateImportRequest struct {
	Enabled  bool  `json:"enabled"`
	Position int32 `json:"position,omitempty"`
}

func (s *Server) updateImport(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "importUUID")
	if !ok {
		return
	}
	var req updateImportRequest
	if !decode(w, r, &req) {
		return
	}
	edge, err := s.api.SetImportEnabled(r.Context(), c, id, req.Enabled, req.Position)
	if err != nil {
		response.ServiceError(w, r, "could not update the import", err)
		return
	}
	response.OK(w, edge, "import updated")
}

func (s *Server) deleteImport(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "importUUID")
	if !ok {
		return
	}
	if err := s.api.DeleteImport(r.Context(), c, id); err != nil {
		response.ServiceError(w, r, "could not delete the import", err)
		return
	}
	response.NoContent(w)
}
