package handlers

import (
	"net/http"
)

type DocsHandler struct{}

func NewDocsHandler() *DocsHandler { return &DocsHandler{} }

func (h *DocsHandler) PageDocs(w http.ResponseWriter, r *http.Request) {
	ServePage(w, r, "docs.html")
}
