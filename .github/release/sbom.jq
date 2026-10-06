# CycloneDX 1.5 SBOM for the `lcoat` binary, from `cargo metadata`.
# Components are the packages `lcoat` links (normal dependencies, followed
# transitively), not the whole workspace: the fuzz crate ships in no binary.
# Inputs: --arg uuid <serial> --arg ts <RFC 3339 time>.
(.resolve.nodes
  | map({key: .id, value: [.deps[] | select(any(.dep_kinds[]; .kind == null)) | .pkg]})
  | from_entries) as $graph
| (.packages | map({key: .id, value: .}) | from_entries) as $pkg
| def component($type):
    {type: $type, name, version, purl: "pkg:cargo/\(.name)@\(.version)",
     licenses: [{license: {id: .license}}]};
  def closure:
    . as $seen
    | ([$seen[] | $graph[.][]] + $seen | unique) as $next
    | if ($next | length) == ($seen | length) then $next else ($next | closure) end;
  (.packages[] | select(.name == "lcoat") | .id) as $root
| {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: ("urn:uuid:" + $uuid),
    version: 1,
    metadata: {timestamp: $ts, component: ($pkg[$root] | component("application"))},
    components: [[$root] | closure | .[] | select(. != $root) | $pkg[.] | component("library")]
  }
