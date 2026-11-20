{{- define "cctl.name" -}}cctl-control-plane{{- end -}}
{{- define "cctl.fullname" -}}
{{- if contains "cctl" .Release.Name }}{{ .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}{{ printf "%s-cctl" .Release.Name | trunc 63 | trimSuffix "-" }}{{ end -}}
{{- end -}}
{{- define "cctl.labels" -}}
app.kubernetes.io/name: {{ include "cctl.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}
{{- define "cctl.selector" -}}
app.kubernetes.io/name: {{ include "cctl.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "cctl.image" -}}
{{- if not .Values.image.repository }}{{ fail "image.repository is required" }}{{ end -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" .Values.image.digest) }}{{ fail "image.digest must be sha256:<64 hex>; deploy by digest" }}{{ end -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- end -}}
