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
{{- /* Traefik host matcher of the artifacts host and its extra hosts:
         (Host(`<artifactsHost>`) || Host(`<artifactsExtraHosts[0]>`) || ...)
       Each name is written verbatim into a Traefik rule, so it must be a plain lowercase DNS
       name (labels of letters, digits and inner '-', joined by '.'). Anything else is refused:
       a backtick or a space (it would rewrite the rule), a port, a wildcard, upper case.
       Call with the root context:  {{- $hostMatch := include "artifacts.hostMatch" . }} */ -}}
{{- define "artifacts.hostMatch" -}}
{{- $extra := .Values.artifactsExtraHosts | default (list) }}
{{- if not (kindIs "slice" $extra) }}
{{- fail (printf "artifactsExtraHosts must be a list of host names, got %v" $extra) }}
{{- end }}
{{- $hm := list }}
{{- range $h := prepend $extra .Values.artifactsHost }}
{{- if not (and (kindIs "string" $h) (le (len (toString $h)) 253) (regexMatch "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$" (toString $h))) }}
{{- fail (printf "artifactsHost / artifactsExtraHosts: %q is not a host name (lowercase DNS name: letters, digits, inner '-', labels joined by '.')" (toString $h)) }}
{{- end }}
{{- $hm = append $hm (printf "Host(`%s`)" $h) }}
{{- end }}
{{- printf "(%s)" (join " || " $hm) }}
{{- end }}
