{{- define "mssql-official.name" -}}
mssql-official
{{- end -}}

{{- define "mssql-official.fullname" -}}
{{ printf "%s-%s" (include "mssql-official.name" .) .Release.Name }}
{{- end -}}
