# Kubernetes deployment

Run commands from the repository root. The examples use the namespace
`image-scan-report`, a default StorageClass, and a Harbor reader account.
Edit `configmap.yaml` for your Harbor URL, project, and organization.

Apply the namespace first, then create credentials locally using the names in
`secret.example.yaml`. Never commit real secret values; the example is a schema
with placeholders, not production credentials.

```sh
kubectl apply -f deploy/k8s/namespace.yaml
kubectl -n image-scan-report create secret generic report-secrets --from-literal=HARBOR_PASSWORD='replace-with-real-password'
kubectl -n image-scan-report create configmap harbor-ca --from-file=ca.pem=/path/to/harbor-ca.pem
kubectl apply -f deploy/k8s/configmap.yaml
kubectl apply -f deploy/k8s/pvc.yaml
kubectl apply -f deploy/k8s/cronjob.yaml
```

`ca-configmap.example.yaml` shows the CA object's shape; replace its placeholder
with a PEM bundle if applying it instead of creating it from a file. The CA
ConfigMap volume is optional, but the supplied application config references
`/etc/report/ca.pem`: create the CA before running. For a publicly trusted Harbor,
remove `source.ca_file` and the CA volume and mount from both workloads.
Avoid applying the whole directory unchanged: it includes placeholder secrets
and certificates and starts the one-off Job.

The CronJob runs Mondays at 02:00 in the controller's timezone and forbids
concurrent scheduled runs. To run the one-off Job and follow its logs:

```sh
kubectl apply -f deploy/k8s/job.yaml
kubectl -n image-scan-report logs -f job/image-scan-report-once
kubectl -n image-scan-report wait --for=condition=complete job/image-scan-report-once --timeout=3600s
```

Delete the completed Job before applying it again. Do not run it alongside the
CronJob: `Forbid` only covers jobs created by that CronJob, and the PVC is RWO.

## Retrieve reports

After the report Job completes, mount its PVC in a temporary helper pod. Avoid
running the helper concurrently with a report Job on a different node (RWO).
The helper image must contain `tar` for `kubectl cp`.

```sh
kubectl -n image-scan-report run report-reader --image=busybox:1.37 --restart=Never --overrides='{"spec":{"securityContext":{"runAsUser":65532,"runAsGroup":65532,"fsGroup":65532},"containers":[{"name":"report-reader","image":"busybox:1.37","command":["sleep","3600"],"volumeMounts":[{"name":"output","mountPath":"/output","readOnly":true}]}],"volumes":[{"name":"output","persistentVolumeClaim":{"claimName":"report-output"}}]}}'
kubectl -n image-scan-report wait --for=condition=Ready pod/report-reader --timeout=120s
kubectl -n image-scan-report cp report-reader:/output ./reports
kubectl -n image-scan-report delete pod report-reader
```

The copied directory contains PDFs and JSON. Alternatively, replace the config's
`output` with an HTTP destination:

```yaml
output:
  - type: http
    url: https://reports.example.com/upload
    method: PUT
    headers:
      Authorization: "Bearer ${UPLOAD_TOKEN}"
```

Add `UPLOAD_TOKEN` to `report-secrets` (the commented key in the Secret example).
For HTTP-only output remove the `output` volume and `/output` mount from both
workloads; no PVC is needed. The destination must accept separate PDF and JSON
uploads. See [HTTP output configuration](../../README.md#output) for TLS and
multipart options.

## Resources and release tags

Each container requests 1 CPU and 1Gi memory, with limits of 2 CPUs and 4Gi memory.
The sizing rule is **0.8 GB + 70 MB per 1,000 findings**, or about 45,000 findings
under 4 GiB. See [development sizing notes](../../docs/development.md). The PVC
requests 1Gi; monitor retained reports and remove old artifacts or increase it.
Job history limits do not prune files on the PVC.

Both workloads pin `ghcr.io/jtr860830/judex:1.0.0-rc.1` to the current crate release.
Update both tags when releasing; the Rust manifest test compares them with
`env!("CARGO_PKG_VERSION")`. The image supplies the default `run --config
/etc/report/config.yaml` command and runs as UID/GID 65532. The pod also sets
fsGroup 65532 so a supporting storage driver grants write access to `/output`.
