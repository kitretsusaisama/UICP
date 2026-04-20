package uicp.governance

import future.keywords.in

default allow = false

# Every endpoint in the Swagger spec must have tags and an operationId
deny[msg] {
    some path, method
    endpoint := input.paths[path][method]
    not endpoint.tags
    msg := sprintf("Missing tags for route %s %s", [method, path])
}

# Deny any route that allows public access without rate limiting documentation
deny[msg] {
    some path, method
    endpoint := input.paths[path][method]
    "Public" in endpoint.tags
    not endpoint.responses["429"]
    msg := sprintf("Public route %s %s is missing 429 Rate Limit documentation", [method, path])
}

# Deny any admin route that lacks Bearer Auth documentation
deny[msg] {
    some path, method
    endpoint := input.paths[path][method]
    "Admin" in endpoint.tags
    not has_bearer_auth(endpoint)
    msg := sprintf("Admin route %s %s is missing Bearer Auth security requirement", [method, path])
}

has_bearer_auth(endpoint) {
    some i
    security_req := endpoint.security[i]
    security_req["bearer"]
}
