package httpapi

import (
	"encoding/json"
	"html/template"
	"net/http"
)

// ErrorRenderer は、Client へリダイレクトできないエラー（client_id 不明、redirect_uri 不一致、
// Resume の拒否など）をブラウザに描く。利用者は自前のテンプレートで差し替えられる。
type ErrorRenderer interface {
	RenderError(w http.ResponseWriter, r *http.Request, status int, code, description string)
}

// PlainErrorRenderer は既定の ErrorRenderer。装飾のない HTML 1 枚を返す。
type PlainErrorRenderer struct{}

var plainErrorTemplate = template.Must(template.New("error").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Authorization error</title></head>
<body><h1>Authorization error</h1><p><code>{{.Code}}</code></p>{{if .Description}}<p>{{.Description}}</p>{{end}}</body></html>
`))

// RenderError は status と共にエラーページを返す。
func (PlainErrorRenderer) RenderError(w http.ResponseWriter, _ *http.Request, status int, code, description string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = plainErrorTemplate.Execute(w, struct{ Code, Description string }{code, description})
}

// errorBody は JSON エラー応答の形（RFC 6749 §5.2 と Interaction API で共用）。
type errorBody struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, errorBody{Error: code, Description: description})
}
