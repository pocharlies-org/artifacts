{{- /* metadata.annotations of every IngressRoute (values ingressRouteAnnotations), or nothing
       when the map is empty. Keys must be Kubernetes annotation keys ([prefix/]name); values
       are rendered as quoted strings. Call with the root context:
         {{- with include "artifacts.ingressRouteAnnotations" $ }}{{ . | nindent 2 }}{{- end }} */ -}}
{{- define "artifacts.ingressRouteAnnotations" -}}
{{- $a := .Values.ingressRouteAnnotations | default dict }}
{{- if not (kindIs "map" $a) }}
{{- fail (printf "ingressRouteAnnotations must be a map of annotation key to value, got %v" $a) }}
{{- end }}
{{- if $a }}
annotations:
{{- range $k := keys $a | sortAlpha }}
{{- if not (regexMatch "^([a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*/)?[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$" $k) }}
{{- fail (printf "ingressRouteAnnotations: %q is not a valid annotation key ([prefix/]name)" $k) }}
{{- end }}
  {{ $k }}: {{ index $a $k | toString | quote }}
{{- end }}
{{- end }}
{{- end }}
