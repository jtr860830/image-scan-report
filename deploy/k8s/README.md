# Kubernetes deployment

Run commands from the repository root. The examples use the namespace
`judex`, a default StorageClass, and a Harbor reader account.
Edit `configmap.yaml` for your Harbor URL, project, and organization.

Apply the namespace first, then create credentials locally using the names in
`secret.example.yaml`. Never commit real secret values; the example is a schema
with placeholders, not production credentials.

```sh
kubectl apply -f deploy/k8s/namespace.yaml
kubectl -n judex create secret generic report-secrets --from-literal=HARBOR_PASSWORD='replace-with-real-password'
kubectl -n judex create configmap harbor-ca --from-file=ca.pem=/path/to/harbor-ca.pem
kubectl apply -f deploy/k8s/configmap.yaml
kubectl apply -f deploy/k8s/pvc.yaml
kubectl apply -f deploy/k8s/cronjob.yaml
```

To keep the password out of shell history, use
`--from-file=HARBOR_PASSWORD=./password.txt` instead of `--from-literal`.

`ca-configmap.example.yaml` shows the CA object's shape; replace its placeholder
with a PEM bundle if applying it instead of creating it from a file. The CA
ConfigMap volume is optional, but the supplied application config references
`/etc/judex/ca.pem`: create the CA before running. If the CA ConfigMap is
missing, the Job fails and its log reports the CA file read error. For a
publicly trusted Harbor,
remove `source.ca_file` and the CA volume and mount from both workloads.
Avoid applying the whole directory unchanged: it includes placeholder secrets
and certificates and starts the one-off Job.

The `judex` CronJob runs Mondays at 02:00 in the controller's timezone and forbids
concurrent scheduled runs. To run the one-off Job and follow its logs:

```sh
kubectl apply -f deploy/k8s/job.yaml
kubectl -n judex logs -f job/judex-once
kubectl -n judex wait --for=condition=complete job/judex-once --timeout=3600s
```

Delete the completed Job before applying it again. Do not run it alongside the
CronJob: `Forbid` only covers jobs created by that CronJob, and the PVC is RWO.

## Retrieve reports

After the report Job completes, mount its PVC in a temporary helper pod. Avoid
running the helper concurrently with a report Job on a different node (RWO).
`kubectl cp` needs a running pod, which is why the helper pod is used after
the Job completes. The helper image must contain `tar` for `kubectl cp`.

```sh
kubectl -n judex run report-reader --image=busybox:1.37 --restart=Never --overrides='{"spec":{"securityContext":{"runAsUser":65532,"runAsGroup":65532,"fsGroup":65532},"containers":[{"name":"report-reader","image":"busybox:1.37","command":["sleep","3600"],"volumeMounts":[{"name":"output","mountPath":"/var/lib/judex/reports","readOnly":true}]}],"volumes":[{"name":"output","persistentVolumeClaim":{"claimName":"report-output"}}]}}'
kubectl -n judex wait --for=condition=Ready pod/report-reader --timeout=120s
kubectl -n judex cp report-reader:/var/lib/judex/reports ./reports
kubectl -n judex delete pod report-reader
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
For HTTP-only output remove the `output` volume and `/var/lib/judex/reports` mount from both
workloads; no PVC is needed. The destination must accept separate PDF and JSON
uploads. See [HTTP output configuration](../../README.md#output) for TLS and
multipart options.

## Resources and release tags

Each container requests 1 CPU and 1Gi memory, with limits of 2 CPUs and 4Gi memory.
The sizing rule is **0.8 GB + 70 MB per 1,000 findings**, or about 45,000 findings
under 4 GiB. See [development sizing notes](../../docs/development.md). The PVC
requests 1Gi; monitor retained reports and remove old artifacts or increase it.
Job history limits do not prune files on the PVC.

Both workloads pin `ghcr.io/jtr860830/judex:0.1.0` to the current crate release.
Update both tags when releasing; the Rust manifest test compares them with
`env!("CARGO_PKG_VERSION")`. The image supplies the default `run` command,
discovers configuration at `/etc/judex/config.yaml`, and runs as UID/GID 65532. The pod also sets
fsGroup 65532 so a supporting storage driver grants write access to `/var/lib/judex/reports`.
