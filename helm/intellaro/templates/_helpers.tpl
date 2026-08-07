{{- define "intellaro.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "intellaro.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "intellaro.name" .) | trunc 63 | trimSuffix "-" | replace (printf "%s-%s" (include "intellaro.name" .) (include "intellaro.name" .)) (include "intellaro.name" .) -}}
{{- end -}}
{{- end -}}

{{- define "intellaro.labels" -}}
app.kubernetes.io/name: {{ include "intellaro.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "intellaro.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (printf "%s-ingress" (include "intellaro.fullname" .)) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "intellaro.mcpUrl" -}}
{{- if .Values.ingressController.mcpUrl -}}
{{- .Values.ingressController.mcpUrl -}}
{{- else -}}
{{- printf "http://%s-dataplane.%s.svc:%d" (include "intellaro.fullname" .) .Release.Namespace (int .Values.dataplane.service.mcpPort) -}}
{{- end -}}
{{- end -}}
